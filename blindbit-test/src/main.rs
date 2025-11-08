use blindbit_lib::oracle::oracle_service_client::OracleServiceClient;

fn main() {
    println!("Hello, world!");

    let mut client = OracleServiceClient::connect("http://[::1]:50051").await?;
}