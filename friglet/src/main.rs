mod blockheader;
mod config;
mod control;
mod electrum;
mod server;
mod supervisor;
mod types;

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

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

/// How a daemon run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunOutcome {
    /// Shutdown requested (signal or control socket): exit the process.
    Exit,
    /// Settings changed over the control socket: run again from the
    /// (re-read) configuration.
    Restart,
}

/// How long a restart waits for the previous run's tasks to wind down.
const RESTART_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

fn main() {
    let cli = Cli::parse();
    // No subcommand runs the scan daemon from config file / env alone.
    let args = match cli.command {
        Some(Commands::Scan(args)) => args,
        None => ScanArgs::default(),
    };
    // Each run gets its own runtime: a settings change restarts the daemon
    // in-process by dropping the whole runtime, which tears down every task
    // the run spawned — the Electrum client connections (so Sparrow
    // reconnects and sees the new wallet), the reorg / found-output
    // subscriptions taken at startup, listeners and the scan task — and then
    // starts over from the config file. Same PID, so a supervising tray keeps
    // its child handle.
    loop {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build the tokio runtime");
        let outcome = runtime.block_on(run(args.clone()));
        runtime.shutdown_timeout(RESTART_SHUTDOWN_TIMEOUT);
        match outcome {
            Ok(RunOutcome::Exit) => return,
            Ok(RunOutcome::Restart) => {
                tracing::info!("restarting with the new settings");
            }
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        }
    }
}

type LogFilterHandle =
    tracing_subscriber::reload::Handle<tracing_subscriber::EnvFilter, tracing_subscriber::Registry>;

/// Set up logging once per process; later runs (in-process restarts) only
/// swap the filter so a changed `log_level` takes effect. `RUST_LOG` takes
/// precedence over `log_level`. Only colour when stderr is a TTY so a
/// tray-piped daemon never emits ANSI into the capture pipe.
fn init_logging(log_level: &str) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    static HANDLE: OnceLock<LogFilterHandle> = OnceLock::new();

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level));
    if let Some(handle) = HANDLE.get() {
        let _ = handle.reload(filter);
        return;
    }
    let (filter, handle) = tracing_subscriber::reload::Layer::new(filter);
    tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr())),
        )
        .init();
    let _ = HANDLE.set(handle);
}

async fn run(args: ScanArgs) -> Result<RunOutcome, Box<dyn std::error::Error + Send + Sync>> {
    let config::Loaded {
        config: mut merged,
        file: config_file,
        descriptor,
    } = config::load(&args)?;
    // Where SetConfig persists changes: the file we loaded, or the default
    // location when the daemon started without one.
    let config_path = config_file.or_else(config::default_config_path);

    if args.print_config {
        print!("{}", toml::to_string_pretty(&merged)?);
        return Ok(RunOutcome::Exit);
    }

    init_logging(&merged.log_level);

    // New wallet: birthday = the oracle's current tip, recorded in the
    // config file so later restarts keep the same birthday.
    if let Some(height) = config::resolve_start_at_tip(&mut merged).await? {
        tracing::info!(
            start_height = height,
            "new wallet: starting at the current chain tip"
        );
        match &config_path {
            Some(path) => {
                if let Err(e) = config::persist_start_height(path, height) {
                    tracing::warn!(error = %e, "set start_height = {height} in the config to keep this birthday");
                }
            }
            None => tracing::warn!(
                "no config file location: set start_height = {height} to keep this birthday"
            ),
        }
    }

    let mut cfg = config::resolve(merged)?;
    if let Some(d) = &descriptor {
        config::store_descriptor_scan_key(d, &cfg.key_file)?;
        // A descriptor in the config file carries the scan secret.
        if let Some(path) = &config_path {
            config::tighten_state_file_perms(path);
        }
    }
    let secret_scan = config::resolve_scan_secret(args.scan_secret.as_deref(), &cfg.key_file)?;
    if let Some(d) = &descriptor
        && d.scan_secret != secret_scan
    {
        return Err(
            "the scan secret from --scan-secret / FRIGLET_SCAN_SECRET differs from \
                    the configured descriptor's scan key; remove one of them"
                .into(),
        );
    }
    // One state file per wallet: new keys start fresh automatically.
    cfg.state_file = config::wallet_state_file(
        &cfg.state_file,
        &cfg.raw.network,
        &secret_scan,
        &cfg.spend_pubkey,
    )?;
    if let Some(previous) = config::reconcile_birthday(&cfg.state_file, cfg.start_height)? {
        tracing::warn!(
            previous_start_height = previous,
            start_height = cfg.start_height,
            "wallet birthday moved back: rescanning from the new birthday (old state kept as .json.bak)"
        );
    }
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
        state_file = %cfg.state_file.display(),
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
        state_file: cfg.state_file.clone(),
        config_path,
        apply_lock: Mutex::new(()),
        oracle_tip_cache: std::sync::Mutex::new(control::OracleTipCache::default()),
        shutdown: shutdown_token.clone(),
        restart_requested: std::sync::atomic::AtomicBool::new(false),
        spawned_by_tray: control::ControlCtx::spawned_by_tray_from_env(),
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

    // Run everything until a server dies or shutdown/restart is requested;
    // leaving the select! drops the HTTP/Electrum/control listeners. A dead
    // server is an error (non-zero exit), so a supervising tray sees a crash
    // rather than a deliberate stop.
    let mut owns_socket = true;
    let failure: Option<String> = tokio::select! {
        _ = http_server => Some("HTTP server stopped".to_string()),
        _ = electrum_server => Some("Electrum server stopped".to_string()),
        result = control_server => {
            // The control server only returns when binding failed — possibly
            // because another daemon owns the socket, so leave the file alone.
            owns_socket = false;
            Some(match result {
                Err(e) => format!("control socket server failed: {e}"),
                Ok(()) => "control socket server stopped".to_string(),
            })
        }
        _ = shutdown_signal() => {
            tracing::info!("shutdown signal received");
            None
        }
        _ = shutdown_token.cancelled() => {
            tracing::info!("shutting down");
            None
        }
    };

    supervisor.stop().await;
    control_ctx.save_state().await;
    if owns_socket {
        cleanup_socket(&cfg.control_socket);
    }
    if let Some(reason) = failure {
        return Err(reason.into());
    }
    if control_ctx.restart_requested() {
        tracing::info!("friglet stopped for a restart");
        return Ok(RunOutcome::Restart);
    }
    tracing::info!("friglet stopped");
    Ok(RunOutcome::Exit)
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
