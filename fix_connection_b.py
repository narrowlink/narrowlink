with open("gateway/src/state/connection.rs", "r") as f:
    content = f.read()

content = content.replace("response.map(|b|", "response.map(|_b|")

with open("gateway/src/state/connection.rs", "w") as f:
    f.write(content)
