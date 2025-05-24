use axum::{Router, routing::get};
use tokio::net::TcpListener;
use tower_sec_fetch::SecFetchLayer;

#[tokio::main]
async fn main() {
    let routes = Router::new()
        .route("/hello", get(async || "hello"))
        .layer(SecFetchLayer::new(|policy| {
            policy.reject_missing_metadata();
        }));

    let listener = TcpListener::bind("[::1]:3000").await.unwrap();

    eprintln!("listening on http://localhost:3000");
    axum::serve(listener, routes).await.unwrap();
}
