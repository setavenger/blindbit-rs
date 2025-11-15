use blindbit_lib::oracle_grpc::RangedBlockHeightRequestFiltered;
use blindbit_lib::oracle_grpc::oracle_service_client::OracleServiceClient;

static ORACLE_URL: &str = "https://oracle.setor.dev";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to oracle service at {}...", ORACLE_URL);
    let mut client = OracleServiceClient::connect(ORACLE_URL).await?;

    let request = tonic::Request::new(RangedBlockHeightRequestFiltered {
        start: 901000,
        end: 902000,
        dustlimit: 0,
        cut_through: false,
    });

    let mut stream = client
        .stream_block_scan_data_short(request)
        .await
        .unwrap()
        .into_inner();
    while let Some(block_scan_data) = stream.message().await.unwrap() {
        let Some(block_identifier) = block_scan_data.block_identifier.clone() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "block identifier is missing",
            )
            .into());
        };
        println!("height: {}", block_identifier.block_height);
    }

    Ok(())
}
