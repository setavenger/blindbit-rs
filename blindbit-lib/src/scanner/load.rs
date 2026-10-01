use super::ScannerError;
use super::config::ScannerConfig;
use super::scanner::Scanner;

use crate::oracle_grpc::oracle_service_client::OracleServiceClient;

/// Load a scanner from configuration, optionally restoring from saved state
///
/// This function will attempt to load scanner state from the file specified in the config.
/// If the state file doesn't exist, it will create a new scanner. A state
/// file that exists but cannot be restored is never overwritten; see
/// [`restore_or_create`].
///
/// Requires the `serde` feature to be enabled for state persistence.
#[cfg(feature = "serde")]
pub async fn load_scanner(config: &ScannerConfig) -> Result<Scanner, ScannerError> {
    // Validate configuration
    config.validate()?;

    // Connect to oracle service
    let client = OracleServiceClient::connect(config.oracle_url.clone()).await?;
    restore_or_create(config, client)
}

/// Restore the scanner from `config.state_file`, or create a new one when
/// there is no state file.
///
/// - A state file that cannot be *read* (permissions, I/O) is an error, and
///   nothing is moved or created.
/// - A state file that cannot be *restored* (not valid JSON, missing keys,
///   or written by a newer build in a format this one does not know) is
///   moved aside to `<name>.unreadable-<unix time>`, never overwritten. A new
///   scanner starts from the configured start height, the error is logged,
///   and the scan health reports it ([`StateFileReset`]).
///
/// [`StateFileReset`]: super::health::StateFileReset
#[cfg(feature = "serde")]
pub(crate) fn restore_or_create(
    config: &ScannerConfig,
    client: OracleServiceClient<tonic::transport::Channel>,
) -> Result<Scanner, ScannerError> {
    let path = &config.state_file;
    let changeset = match Scanner::load_from_file(path) {
        Ok(changeset) => changeset,
        Err(e) => match e.downcast_ref::<std::io::Error>() {
            Some(io) if io.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!("no existing state file, creating new scanner");
                return Ok(create_new_scanner(config, client));
            }
            Some(_) => {
                return Err(format!("cannot read state file {}: {e}", path.display()).into());
            }
            None => return start_over(config, client, e.to_string()),
        },
    };

    tracing::info!(path = %path.display(), "loading scanner state");
    if changeset.format_version > super::STATE_FORMAT_VERSION {
        return start_over(
            config,
            client,
            format!(
                "written by a newer build (state format {}; this build reads up to {})",
                changeset.format_version,
                super::STATE_FORMAT_VERSION
            ),
        );
    }
    match Scanner::from_changeset(
        client.clone(),
        config.p2p_socket_addr,
        changeset,
        config.state_file.clone(),
        config.network,
    ) {
        Ok(scanner) => {
            let last_height = scanner.get_last_scanned_block_height();
            tracing::info!(last_scanned_height = last_height, "scanner state loaded");
            Ok(scanner)
        }
        Err(e) => start_over(config, client, e.to_string()),
    }
}

/// The state file cannot be restored: move it aside and start a new scan.
#[cfg(feature = "serde")]
fn start_over(
    config: &ScannerConfig,
    client: OracleServiceClient<tonic::transport::Channel>,
    error: String,
) -> Result<Scanner, ScannerError> {
    let path = &config.state_file;
    let backup = super::state_file::move_aside(path).map_err(|e| {
        format!(
            "state file {} cannot be restored ({error}) and could not be moved aside ({e}); \
             not starting a new scan over it",
            path.display()
        )
    })?;
    tracing::error!(
        path = %path.display(),
        moved_to = %backup.display(),
        error = %error,
        "state file cannot be restored; moved it aside and starting a new scan from the start height"
    );
    let mut scanner = create_new_scanner(config, client);
    scanner.note_state_file_reset(super::health::StateFileReset {
        backup_path: backup,
        error,
    });
    Ok(scanner)
}

/// Create a new scanner from configuration
#[cfg(feature = "serde")]
fn create_new_scanner(
    config: &ScannerConfig,
    client: OracleServiceClient<tonic::transport::Channel>,
) -> Scanner {
    Scanner::new(
        client,
        config.p2p_socket_addr,
        config.secret_scan,
        config.public_spend,
        config.max_label_num,
        config.state_file.clone(),
        config.network,
    )
}
