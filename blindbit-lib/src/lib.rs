// Generated gRPC client code
pub mod oracle_grpc {
    tonic::include_proto!("blindbit.oracle.v1");
}

// Re-export the client for convenience
pub use oracle_grpc::oracle_service_client::OracleServiceClient;

// Re-export common types
pub use oracle_grpc::*;

// Scanner
pub mod scanner;

/// BIP 352 "low level"related functionality
pub mod bip352;