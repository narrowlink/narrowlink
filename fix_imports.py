import glob

# Fix imports in agent
for path in glob.glob("agent/src/**/*.rs", recursive=True):
    with open(path, "r") as f:
        content = f.read()
    orig = content
    if "generic::HmacSha256::new_from_slice" in content and "use hmac::KeyInit;" not in content:
        content = content.replace("use hmac::Mac;", "use hmac::{Mac, KeyInit};")
    if "rand::rng().random" in content and "use rand::RngExt;" not in content:
        content = content.replace("use rand::Rng;", "use rand::{Rng, RngExt};")
    if orig != content:
        with open(path, "w") as f:
            f.write(content)

# Fix imports in client
for path in glob.glob("client/src/**/*.rs", recursive=True):
    with open(path, "r") as f:
        content = f.read()
    orig = content
    if "generic::HmacSha256::new_from_slice" in content and "use hmac::KeyInit;" not in content:
        if "use hmac::Mac;" in content:
            content = content.replace("use hmac::Mac;", "use hmac::{Mac, KeyInit};")
        else:
            content = "use hmac::KeyInit;\n" + content
    if "rand::rng().random" in content and "use rand::RngExt;" not in content:
        if "use rand::Rng;" in content:
            content = content.replace("use rand::Rng;", "use rand::{Rng, RngExt};")
        else:
            content = "use rand::RngExt;\n" + content
    if orig != content:
        with open(path, "w") as f:
            f.write(content)
