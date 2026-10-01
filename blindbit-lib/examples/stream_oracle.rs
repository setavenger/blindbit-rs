use blindbit_lib::oracle_grpc::RangedBlockHeightRequestFiltered;
use blindbit_lib::oracle_grpc::oracle_service_client::OracleServiceClient;

static ORACLE_URL: &str = "https://oracle.setor.dev";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to oracle service at {ORACLE_URL}...");
    let mut client = OracleServiceClient::connect(ORACLE_URL).await?;

    let request = tonic::Request::new(RangedBlockHeightRequestFiltered {
        start: 901_000,
        end: 901_010,
        dustlimit: 0,
        cut_through: false,
    });

    let mut stream = client
        .stream_block_scan_data_short(request)
        .await?
        .into_inner();
    // An error status (e.g. NOT_FOUND for a height the oracle has not
    // indexed) ends the stream; `?` surfaces it instead of panicking.
    while let Some(block_scan_data) = stream.message().await? {
        let Some(block_identifier) = block_scan_data.block_identifier.clone() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "block identifier is missing",
            )
            .into());
        };
        // Older oracles answer an unindexed height with an empty block hash
        // and no data; that is not an empty block.
        if block_identifier.block_hash.len() != 32 {
            return Err(format!(
                "height {} has no valid block hash; the oracle has probably not indexed it",
                block_identifier.block_height
            )
            .into());
        }
        println!("height: {}", block_identifier.block_height);
    }

    Ok(())
}
