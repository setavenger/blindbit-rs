mod blockheader;
mod config;
mod control;
mod electrum;
mod server;
mod supervisor;
mod types;

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use clap::{Parser, Subcommand};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use axum::{Extension, Router, routing::get};
use blindbit_lib::scanner;

use config::ScanArgs;
use supervisor::ScanSupervisor;

#[derive(Parser)]
#[command(name = "friglet")]
#[command(about = "A daemon for scanning Bitcoin blocks for Silent Payments", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan from start_height to chain tip, then keep watching for new blocks
    Scan(ScanArgs),
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    // No subcommand runs the scan daemon from config file / env alone.
    let args = match cli.command {
        Some(Commands::Scan(args)) => args,
        None => ScanArgs::default(),
    };
    if let Err(e) = run(args).await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run(args: ScanArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (merged, config_file) = config::load(&args)?;
    // Where SetConfig persists changes: the file we loaded, or the default
    // location when the daemon started without one.
    let config_path = config_file.or_else(config::default_config_path);

    if args.print_config {
        print!("{}", toml::to_string_pretty(&merged)?);
        return Ok(());
    }

    // Initialise structured logging.  RUST_LOG takes precedence; the
    // configured log_level sets the default when RUST_LOG is not set.
    // Only colour when stderr is a TTY so a tray-piped daemon never emits
    // ANSI into the capture pipe.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&merged.log_level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();

    let cfg = config::resolve(merged)?;
    let secret_scan = config::resolve_scan_secret(args.scan_secret.as_deref(), &cfg.key_file)?;
    let label_addresses = control::derive_label_addresses(
        secret_scan,
        cfg.spend_pubkey,
        control::wallet_network(cfg.network),
        cfg.max_label_num,
    );
    let outputs_found = Arc::new(AtomicU64::new(control::owned_outputs_count(
        &cfg.state_file,
    )));

    // blindbit-lib persists the scan secret inside the state JSON (see
    // config::tighten_state_file_perms), so keep the file owner-only.
    config::tighten_state_file_perms(&cfg.state_file);

    tracing::info!(
        oracle_url = %cfg.oracle_url,
        p2p_peer = %cfg.p2p_addr,
        network = %cfg.network,
        start_height = cfg.start_height,
        "starting friglet"
    );

    let scanner_config = scanner::ScannerConfig::new(
        cfg.oracle_url.clone(),
        cfg.p2p_addr,
        secret_scan,
        cfg.spend_pubkey,
        cfg.max_label_num,
        cfg.state_file.clone(),
        cfg.network,
    );

    let loaded_scanner = scanner::load_scanner(&scanner_config).await?;

    // Pre-populate the Electrum index from the persisted BDK graph so that
    // Sparrow can immediately fetch wallet history after a restart.
    loaded_scanner
        .rebuild_electrum_index_from_graph(cfg.start_height)
        .await;

    // Snapshot sparse wallet checkpoints before watch_chain takes the scanner
    // lock for its full run. Header misses use this map, then the oracle.
    let block_checkpoints = loaded_scanner
        .staged()
        .map(|stage| {
            stage
                .block_checkpoints
                .iter()
                .map(|(height, hash)| (*height, *hash))
                .collect()
        })
        .unwrap_or_default();
    let header_sidecar = blockheader::sidecar_path(&cfg.state_file);
    let persisted_headers = blockheader::load_headers(&header_sidecar);

    let scanner_instance = Arc::new(Mutex::new(loaded_scanner));

    // Grab Electrum index + push receiver before the scan task locks the scanner.
    let (electrum_index, found_utxos_rx, mut outputs_found_rx) = {
        let s = scanner_instance.lock().await;
        let index = s.electrum_index();
        {
            let mut idx = index.lock().await;
            idx.sp_start_height = cfg.start_height;
            idx.headers.extend(persisted_headers);
        }
        (
            index,
            s.subscribe_to_found_utxos(),
            s.subscribe_to_found_utxos(),
        )
    };
    {
        let outputs_found = outputs_found.clone();
        tokio::spawn(async move {
            while let Ok(count) = outputs_found_rx.recv().await {
                outputs_found.store(count as u64, std::sync::atomic::Ordering::Relaxed);
            }
        });
    }

    // Ensure watch_chain starts from start_height on a fresh wallet
    // (last_scanned_block_height is 0 when there is no saved state).
    {
        let mut s = scanner_instance.lock().await;
        if s.get_last_scanned_block_height() < cfg.start_height {
            s.update_last_scanned_block_height(cfg.start_height.saturating_sub(1));
        }
    }

    // The scan task lives in a supervisor so it can be stopped/started via
    // the control socket.  watch_chain polls the oracle for new blocks and
    // runs indefinitely — no end_height needed.
    let supervisor = Arc::new(ScanSupervisor::new({
        let scanner = scanner_instance.clone();
        move || {
            let scanner = scanner.clone();
            Box::pin(async move {
                let mut s = scanner.lock().await;
                s.watch_chain().await.map_err(|e| e.to_string())
            })
        }
    }));
    supervisor.start();

    let shutdown_token = CancellationToken::new();
    let electrum_clients = Arc::new(AtomicU64::new(0));

    let control_ctx = Arc::new(control::ControlCtx {
        supervisor: supervisor.clone(),
        scanner: scanner_instance.clone(),
        electrum_index: std::sync::Mutex::new(electrum_index.clone()),
        electrum_clients: electrum_clients.clone(),
        outputs_found,
        label_addresses: std::sync::Mutex::new(label_addresses),
        settings: std::sync::Mutex::new(cfg.raw.clone()),
        config_path,
        apply_lock: Mutex::new(()),
        scanner_builder: Box::new(|cfg| {
            Box::pin(async move { scanner::load_scanner(&cfg).await.map_err(|e| e.to_string()) })
        }),
        oracle_tip_cache: std::sync::Mutex::new(control::OracleTipCache::default()),
        shutdown: shutdown_token.clone(),
    });
    let control_server = control::run(cfg.control_socket.clone(), {
        let ctx = control_ctx.clone();
        move |req| {
            let ctx = ctx.clone();
            async move { ctx.handle(req).await }
        }
    });

    let app = Router::new()
        .route("/height", get(server::get_height))
        .route("/subscribe", get(server::subscribe))
        .layer(Extension(server::ScanStartHeight(cfg.start_height)))
        .layer(Extension(scanner_instance.clone()));

    let http_addr = cfg.http_addr.clone();
    let http_server = async move {
        let listener = tokio::net::TcpListener::bind(&http_addr)
            .await
            .expect("Failed to bind HTTP server");
        tracing::info!(addr = %http_addr, "HTTP server listening");
        axum::serve(listener, app)
            .await
            .expect("HTTP server failed");
    };

    let electrum_server = {
        let electrum_addr = cfg.electrum_addr.clone();
        let electrum_clients = electrum_clients.clone();
        let p2p_addr = cfg.p2p_addr;
        let network = cfg.network;
        let oracle_url = cfg.oracle_url.clone();
        async move {
            if let Err(e) = electrum::run(
                electrum_index,
                found_utxos_rx,
                &electrum_addr,
                p2p_addr,
                network,
                oracle_url,
                block_checkpoints,
                header_sidecar,
                electrum_clients,
            )
            .await
            {
                tracing::error!(error = %e, "Electrum server terminated with error");
            }
        }
    };

    // Run everything until a server dies or shutdown is requested; leaving
    // the select! drops the HTTP/Electrum/control listeners.
    tokio::select! {
        _ = http_server => {
            tracing::info!("HTTP server stopped");
        }
        _ = electrum_server => {
            tracing::info!("Electrum server stopped");
        }
        result = control_server => {
            if let Err(e) = result {
                tracing::error!(error = %e, "control socket server failed");
            }
        }
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal received");
        }
        _ = shutdown_token.cancelled() => {
            tracing::info!("shutting down");
        }
    }

    supervisor.stop().await;
    control_ctx.save_state().await;
    cleanup_socket(&cfg.control_socket);
    tracing::info!("friglet stopped");

    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn cleanup_socket(path: &str) {
    #[cfg(unix)]
    let _ = std::fs::remove_file(path);
    #[cfg(not(unix))]
    let _ = path;
}
