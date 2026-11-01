// Generated gRPC client code
#[allow(clippy::all)]
pub mod oracle_grpc {
    tonic::include_proto!("blindbit.oracle.v1");
}

// Re-export the client for convenience
pub use oracle_grpc::oracle_service_client::OracleServiceClient;

// Re-export common types
pub use oracle_grpc::*;

// Where P2P connections go: the own node or discovered peers
pub mod net;

// Scanner
pub mod scanner;
