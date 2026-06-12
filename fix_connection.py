with open("gateway/src/state/connection.rs", "r") as f:
    content = f.read()

content = content.replace(
    "use hyper::{client::conn, http::HeaderValue, Body, Request, Response};",
    "use hyper::{http::HeaderValue, Request, Response, body::Incoming};\nuse hyper::client::conn::http1;\nuse http_body_util::Full;\nuse bytes::Bytes;"
)

content = content.replace(
    "Box<Request<Body>>",
    "Box<Request<Incoming>>"
)

content = content.replace(
    "oneshot::Sender<Result<Response<Body>, ResponseErrors>>",
    "oneshot::Sender<Result<Response<Full<Bytes>>, ResponseErrors>>"
)

content = content.replace(
    "conn::handshake(agent_socket)",
    "http1::handshake(hyper_util::rt::TokioIo::new(agent_socket))"
)

content = content.replace(
    "let request = request.map(|b| {",
    "let request = request.map(|b| {"
)
# wait, wait! The outgoing request from Gateway to Agent will use the same Body!
# We probably need to convert the body or map it, since http1::handshake expects a body that implements http_body::Body!
# Actually Incoming implements Body. But if it's already an Incoming, it works directly!
