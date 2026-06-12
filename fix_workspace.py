import glob
import os

# Fix rand in client
for path in glob.glob("client/src/**/*.rs", recursive=True):
    with open(path, "r") as f:
        content = f.read()
    orig = content
    content = content.replace("rand::thread_rng().gen_range", "rand::rng().random_range")
    content = content.replace("rand::random::<", "rand::rng().random::<")
    content = content.replace("use rand::Rng;", "use rand::Rng;\nuse rand::RngCore;")
    if orig != content:
        with open(path, "w") as f:
            f.write(content)

# Fix rand in agent
for path in glob.glob("agent/src/**/*.rs", recursive=True):
    with open(path, "r") as f:
        content = f.read()
    orig = content
    content = content.replace("rand::thread_rng().gen_range", "rand::rng().random_range")
    content = content.replace("rand::random::<", "rand::rng().random::<")
    content = content.replace("use rand::Rng;", "use rand::Rng;\nuse rand::RngCore;")
    if orig != content:
        with open(path, "w") as f:
            f.write(content)

# Fix ipstack imports in client
for path in glob.glob("client/src/**/*.rs", recursive=True):
    with open(path, "r") as f:
        content = f.read()
    orig = content
    content = content.replace("ipstack::stream::IpStackStream", "ipstack::IpStackStream")
    content = content.replace("ipstack::stream::IpStackTcpStream", "ipstack::IpStackTcpStream")
    content = content.replace("ipstack::stream::IpStackUdpStream", "ipstack::IpStackUdpStream")
    if orig != content:
        with open(path, "w") as f:
            f.write(content)
