// todo: make scanner data pulling engine flexible

mod changeset;
mod config;
mod load;
mod p2p;
mod scanner;
mod scanning;
mod types;
mod utils;

// Re-export public types and the main Scanner struct
pub use changeset::ChangeSet;
pub use config::ScannerConfig;
pub use scanner::Scanner;
pub use types::{BlockIdentifierDisplay, OwnedOutput};

// Re-export load_scanner function when serde feature is enabled
#[cfg(feature = "serde")]
pub use load::load_scanner;
