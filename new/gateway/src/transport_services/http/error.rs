use askama::Template;
use hyper::{body::Bytes, StatusCode};
use serde::Serialize;

#[allow(dead_code)]
pub enum HttpErrors {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound(Option<&'static str>),
    NotAcceptable(Option<&'static str>),
    Conflict,
    InternalServerError,
    ServiceUnavailable,
    WenServerIsDown,
    OriginIsUnreachable,
}

impl HttpErrors {
    fn parts(&self) -> (&'static str, &'static str) {
        match self{
            HttpErrors::BadRequest => ("400 - Bad Request","The request was malformed or invalid."),
            HttpErrors::Unauthorized => ("401 - Unauthorized","The request requires authentication, either through a missing or invalid Authorization header."),
            HttpErrors::Forbidden => ("403 - Forbidden","The server understood the request, but it refuses to authorize it."),
            HttpErrors::NotFound(e) => ("404 Not Found",e.unwrap_or("The requested resource could not be found.")),
            HttpErrors::NotAcceptable(e) => ("406 Not Acceptable",e.unwrap_or("The resource you requested is not available in the format you requested.")),
            HttpErrors::Conflict => ("409 Conflict","A conflict has occurred, please check your inputs and try again."),
            HttpErrors::InternalServerError => ("500 Internal Server Error","An error occurred on the server while processing the request."),
            HttpErrors::ServiceUnavailable => ("503 - Service Unavailable", "The server is currently unable to handle the request due to maintenance or overloading."),
            HttpErrors::WenServerIsDown => ("521 - Web Server Is Down", "The agent is available, but its hosted web server is refusing connections from the agent. Make sure the agent can reach the web server."),
            HttpErrors::OriginIsUnreachable => ("523 - Agent Is Unreachable", "The agent is not available. Make sure the agent is connected to the service."),
        }
    }
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTemplate<'a> {
    title: &'a str,
    body: &'a str,
}

impl From<HttpErrors> for u16 {
    fn from(val: HttpErrors) -> Self {
        match val {
            HttpErrors::BadRequest => 400,
            HttpErrors::Unauthorized => 401,
            HttpErrors::Forbidden => 403,
            HttpErrors::NotFound(_) => 404,
            HttpErrors::NotAcceptable(_) => 406,
            HttpErrors::Conflict => 409,
            HttpErrors::InternalServerError => 500,
            HttpErrors::ServiceUnavailable => 503,
            HttpErrors::WenServerIsDown => 521,
            HttpErrors::OriginIsUnreachable => 523,
        }
    }
}

pub enum ErrorFormat {
    Json,
    Html,
}

pub fn response_error(
    error_format: ErrorFormat,
    err: HttpErrors,
) -> hyper::Response<http_body_util::Full<Bytes>> {
    let (status_title, body) = err.parts();
    let status_code = err.into();
    let msg: Result<String, Box<dyn std::error::Error>> = match error_format {
        ErrorFormat::Json => {
            #[derive(Serialize)]
            struct HttpErrorsHelper<'a> {
                status: u16,
                data: &'a str,
            }
            serde_json::to_string(&HttpErrorsHelper {
                status: status_code,
                data: body,
            })
            .map_err(|e| e.into())
        }
        ErrorFormat::Html => ErrorTemplate {
            title: status_title,
            body,
        }
        .render()
        .map_err(|e| e.into()),
    };
    let (status, msg) = if let (Ok(status), Ok(msg)) = (StatusCode::from_u16(status_code), msg) {
        (status, msg)
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            HttpErrors::InternalServerError.parts().1.to_owned(),
        )
    };
    dbg!(&msg);
    let response = hyper::Response::new(msg);
    let (mut parts, body) = response.into_parts();
    parts.status = status;
    dbg!(&body);
    hyper::Response::from_parts(parts, body.into())
}
