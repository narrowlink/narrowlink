use error::ClientError;

mod error;
mod gate;
mod manage;
mod transport;

#[tokio::main]
pub async fn main() -> Result<(), ClientError> {
    println!("Hello, world!");
    Ok(())
}
