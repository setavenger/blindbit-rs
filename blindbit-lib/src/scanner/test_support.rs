//! Fixtures shared by the scanner's test modules: the test wallet, an oracle
//! client that never connects, per-test state files and a Tokio runner.

use std::future::Future;
use std::net::SocketAddr;
#[cfg(feature = "serde")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use bdk_sp::bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin_rev::Network;
use tonic::transport::Channel;

use super::Scanner;

pub(super) fn secret(byte: u8) -> SecretKey {
    SecretKey::from_slice(&[byte; 32]).expect("valid secret")
}

/// The test wallet's scan secret and spend public key.
pub(super) fn keys() -> (SecretKey, PublicKey) {
    (secret(0x11), secret(0x22).public_key(&Secp256k1::new()))
}

pub(super) fn run<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

/// An oracle client that never connects (nothing listens on port 1).
///
/// `Channel::connect_lazy` needs a Tokio runtime in scope even though it sends
/// nothing. Inside one (async tests) it uses that; synchronous tests get a
/// process-wide runtime, kept alive so the channel's handle stays valid.
pub(super) fn oracle_client() -> crate::OracleServiceClient<Channel> {
    let lazy = || {
        crate::OracleServiceClient::new(Channel::from_static("http://127.0.0.1:1").connect_lazy())
    };
    if tokio::runtime::Handle::try_current().is_ok() {
        return lazy();
    }
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    let runtime = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime for the lazy tonic channel")
    });
    let _guard = runtime.enter();
    lazy()
}

/// The P2P peer of the tests' scanners; nothing listens there, so a test
/// that needs a node sets `p2p_peer` to its own.
fn p2p_peer() -> SocketAddr {
    "127.0.0.1:1".parse().expect("socket address")
}

/// A state-file path in the temp dir that no other call returns, so tests
/// running in parallel never share one. `tag` only names it.
pub(super) fn state_file(tag: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "blindbit-test-{tag}-{}-{n}.json",
        std::process::id()
    ))
}

/// Removes its state file when dropped.
pub(super) struct TempState(pub(super) PathBuf);

impl Drop for TempState {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A new scanner for the test wallet with labels `0..=max_label_num`,
/// saving to `path`.
pub(super) fn scanner_at(path: PathBuf, max_label_num: u32) -> Scanner {
    let (scan_sk, spend_pk) = keys();
    Scanner::new(
        oracle_client(),
        p2p_peer(),
        scan_sk,
        spend_pk,
        max_label_num,
        path,
        Network::Regtest,
    )
}

/// A new scanner for the test wallet (change label only) and its state
/// file, which is removed when the returned guard is dropped.
pub(super) fn scanner(tag: &str) -> (Scanner, TempState) {
    let path = state_file(tag);
    (scanner_at(path.clone(), 0), TempState(path))
}

/// The wallet as a restarted daemon loads it from its state file at `path`.
#[cfg(feature = "serde")]
pub(super) fn restore_from(path: &Path) -> Scanner {
    let changeset = Scanner::load_from_file(path).expect("load state");
    Scanner::from_changeset(
        oracle_client(),
        p2p_peer(),
        changeset,
        path.to_path_buf(),
        Network::Regtest,
    )
    .expect("restore")
}
