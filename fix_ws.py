with open("gateway/src/service/ws.rs", "r") as f:
    content = f.read()

import re

content = re.sub(
    r"\.body::<dyn Body>\(key_authorization\.into\(\)\);",
    r".body(Full::new(Bytes::from(key_authorization))).unwrap();",
    content
)

content = re.sub(
    r"\.body::<dyn Body>\(\"\"\.into\(\)\)",
    r".body(Full::new(Bytes::new())).unwrap()",
    content
)

content = re.sub(
    r"\.body::<dyn Body>\(INDEX_HTML\.into\(\)\);",
    r".body(Full::new(Bytes::from(INDEX_HTML))).unwrap();",
    content
)

with open("gateway/src/service/ws.rs", "w") as f:
    f.write(content)
