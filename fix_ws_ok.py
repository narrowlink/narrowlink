with open("gateway/src/service/ws.rs", "r") as f:
    content = f.read()

import re

content = re.sub(
    r"return Ok\((response_error\([\s\S]*?\))\);",
    r"return \1;",
    content
)

content = re.sub(
    r"Ok\((crate::service::http_templates::response_error\([\s\S]*?\))\)",
    r"\1",
    content
)

content = content.replace("r.headers_mut().append", "r.headers_mut().unwrap().append") # wait, Full doesn't have headers_mut. Response has headers_mut! Let's check!

with open("gateway/src/service/ws.rs", "w") as f:
    f.write(content)
