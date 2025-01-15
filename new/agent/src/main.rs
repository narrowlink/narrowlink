use error::ClientError;

mod control;
mod error;
mod gate;
mod transport;

#[tokio::main]
pub async fn main() -> Result<(), ClientError> {
    println!("Hello, world!");
    Ok(())
}
