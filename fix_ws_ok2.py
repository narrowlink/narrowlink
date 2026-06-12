with open("gateway/src/service/ws.rs", "r") as f:
    content = f.read()

import re

# Find and replace Ok(response_error(...))
content = re.sub(
    r"Ok\((crate::service::http_templates::response_error\([\s\S]*?\))\)",
    r"\1",
    content
)

with open("gateway/src/service/ws.rs", "w") as f:
    f.write(content)
