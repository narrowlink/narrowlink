use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(&["src/messages/negotiation.proto"], &["src/messages/"])?;
    prost_build::compile_protos(&["src/messages/command.proto"], &["src/messages/"])?;
    prost_build::compile_protos(&["src/messages/data.proto"], &["src/messages/"])?;
    Ok(())
}
