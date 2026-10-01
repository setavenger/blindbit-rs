// todo: make scanner data pulling engine flexible

mod changeset;
mod config;
pub mod electrum_index;
mod health;
mod load;
#[cfg(test)]
mod oracle_floor_tests;
mod p2p;
#[cfg(test)]
mod p2p_tests;
mod reorg;
#[cfg(test)]
mod reorg_tests;
mod scanner;
mod scanning;
#[cfg(feature = "serde")]
mod state_file;
#[cfg(all(test, feature = "serde"))]
mod state_file_tests;
#[cfg(test)]
mod stream_safety_tests;
mod types;
mod utils;

/// Shared error type for scanner operations used across async tasks.
pub type ScannerError = Box<dyn std::error::Error + Send + Sync>;

// Re-export public types and the main Scanner struct
pub use changeset::{ChangeSet, STATE_FORMAT_VERSION};
pub use config::ScannerConfig;
pub use electrum_index::{ScriptHashEntry, SpHistoryEntry, WalletElectrumIndex, electrum_scripthash, electrum_status};
pub use health::{
    OracleFloorStart, ScanHealth, ScanStall, ScanStopped, StateFileReset, StateRescan,
};
pub use p2p::{
    BlockFetchError, BlockFetcher, FetchFailure, PeerInfo, RetryNote, RetryPolicy, broadcast_tx,
};
pub use reorg::{REORG_LOOKBACK, ReorgTooDeep};
pub use scanner::Scanner;
pub use types::{BlockIdentifierDisplay, OwnedOutput, OwnedOutputRecord};

// Re-export load_scanner function when serde feature is enabled
#[cfg(feature = "serde")]
pub use load::load_scanner;
