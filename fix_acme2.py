with open("gateway/src/service/certificate/acme.rs", "r") as f:
    content = f.read()

content = content.replace("let instant_acme::AuthorizedIdentifier::Dns(identifier) = authorization.identifier() else {\n                continue;\n            };", "let identifier = authorization.identifier().to_string();")
content = content.replace("let instant_acme::AuthorizedIdentifier::Dns(identifier) = authorization.identifier();", "let identifier = authorization.identifier().to_string();")
content = content.replace("let instant_acme::AuthorizedIdentifier::Dns(identifier) = auth.identifier() else {\n                continue;\n            };", "let identifier = auth.identifier().to_string();")

with open("gateway/src/service/certificate/acme.rs", "w") as f:
    f.write(content)
