use axum::{Router, response::IntoResponse, routing::get};
use tokio::net::TcpListener;
use tower_sec_fetch::SecFetchLayer;

#[tokio::main]
async fn main() {
    let routes = Router::new()
        .route("/protected", get(hello))
        .layer(SecFetchLayer::default())
        .route("/not-protected", get(hello));

    let listener = TcpListener::bind("[::1]:3000").await.unwrap();

    eprintln!("listening on http://localhost:3000");
    axum::serve(listener, routes).await.unwrap();
}

#[axum::debug_handler]
async fn hello() -> impl IntoResponse {
    "hello"
}
