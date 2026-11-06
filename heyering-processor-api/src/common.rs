use reqwest::{Client, RequestBuilder, StatusCode};

/// Value for the Authorization header
///
/// In a real-world production scenario, this value would obviously not be
/// directly baked into the application's source code, but rather would be
/// fetched from some secrets store in the respective deployment environment.
const AUTHORIZATION_HEADER_VALUE: &'static str = "eye-am-hiring";

/// Heyering API base URL
const HEYERING_API_URL: &'static str = "https://api.heyering.com";

/// Create a `reqwest::RequestBuilder` to post to the Heyering API
pub fn request_builder(route: &str) -> RequestBuilder {
    Client::new()
        .post(format!("{}/{}", HEYERING_API_URL, route))
        .header("Authorization", AUTHORIZATION_HEADER_VALUE)
}

#[allow(unused)]
#[derive(Debug)]
pub struct Response(StatusCode, String);

impl Response {
    pub fn new(status: StatusCode, message: String) -> Self {
        Self(status, message)
    }
}
