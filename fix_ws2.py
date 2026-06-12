with open("gateway/src/service/ws.rs", "r") as f:
    content = f.read()

content = content.replace("Ok(res)", "res")
content = content.replace("Box::pin(handler)", "handler.await")

with open("gateway/src/service/ws.rs", "w") as f:
    f.write(content)
