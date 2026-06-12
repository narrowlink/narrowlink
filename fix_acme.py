with open("gateway/src/service/certificate/acme.rs", "r") as f:
    content = f.read()

content = content.replace("let instant_acme::Identifier::Dns(identifier) = authorization.identifier() else {", "let instant_acme::AuthorizedIdentifier::Dns(identifier) = authorization.identifier() else {")
content = content.replace("let Identifier::Dns(identifier) = &authorization.identifier;", "let instant_acme::AuthorizedIdentifier::Dns(identifier) = authorization.identifier();")

with open("gateway/src/service/certificate/acme.rs", "w") as f:
    f.write(content)
