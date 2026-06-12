import glob

# Remove rand::RngCore
for path in glob.glob("client/src/**/*.rs", recursive=True) + glob.glob("agent/src/**/*.rs", recursive=True):
    with open(path, "r") as f:
        content = f.read()
    orig = content
    content = content.replace("\nuse rand::RngCore;", "")
    if orig != content:
        with open(path, "w") as f:
            f.write(content)
