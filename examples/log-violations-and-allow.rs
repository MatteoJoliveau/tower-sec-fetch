//! This setup doesn't block any requests, but logs violations to stderr
//!
//! It can be used to introduce CSRF incrementally and double check it's not blocking
//! any legitimate request

use axum::{Router, routing::get};
use tokio::net::TcpListener;
use tower_sec_fetch::{SecFetchLayer, SecFetchReporter};

struct LogReporter;

impl SecFetchReporter for LogReporter {
    fn on_request_denied<B>(&self, request: &http::Request<B>) {
        let uri = request.uri();
        let method = request.method();
        let headers = request.headers();

        eprintln!("request was denied: {method} {uri} {headers:?}");
    }
}

#[tokio::main]
async fn main() {
    let routes = Router::new().route("/hello", get(async || "hello")).layer(
        SecFetchLayer::default()
            .no_enforce()
            .with_reporter(LogReporter),
    );

    let listener = TcpListener::bind("[::1]:3000").await.unwrap();

    eprintln!("listening on http://localhost:3000");
    axum::serve(listener, routes).await.unwrap();
}
