use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(&["proto/negotiation.proto"], &["src/messages/"])?;
    prost_build::compile_protos(&["proto/command.proto"], &["src/messages/"])?;
    prost_build::compile_protos(&["proto/data.proto"], &["src/messages/"])?;
    Ok(())
}
