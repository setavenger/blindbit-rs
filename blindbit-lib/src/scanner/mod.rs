// todo: make scanner data pulling engine flexible

mod changeset;
mod config;
pub mod electrum_index;
mod load;
mod p2p;
mod scanner;
mod scanning;
mod types;
mod utils;

/// Shared error type for scanner operations used across async tasks.
pub type ScannerError = Box<dyn std::error::Error + Send + Sync>;

// Re-export public types and the main Scanner struct
pub use changeset::ChangeSet;
pub use config::ScannerConfig;
pub use electrum_index::{ScriptHashEntry, SpHistoryEntry, WalletElectrumIndex, electrum_scripthash, electrum_status};
pub use p2p::broadcast_tx;
pub use scanner::Scanner;
pub use types::{BlockIdentifierDisplay, OwnedOutput};

// Re-export load_scanner function when serde feature is enabled
#[cfg(feature = "serde")]
pub use load::load_scanner;
