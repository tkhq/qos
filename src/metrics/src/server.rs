//! Http implementation for serving metrics
use crate::collector::Collector;
use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use std::{net::SocketAddr, sync::Arc};

/// Server serves metrics
#[derive(Debug, Default)]
pub struct Server {}

impl Server {
    /// returns a new `Server`
    #[must_use]
    pub fn new() -> Self {
        Server {}
    }

    /// listens on the provided socket
    pub async fn serve(&self, addr: SocketAddr, collector: Collector) {
        let app = Router::new()
            .route("/", get(Self::root))
            .route("/metrics", get(Self::metrics))
            .with_state(Arc::new(collector));

        println!("MetricsServer listening on {}", addr);
        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
    }

    async fn root() -> impl IntoResponse {
        (StatusCode::OK, "metrics available at /metrics\n")
    }

    async fn metrics(State(state): State<Arc<Collector>>) -> impl IntoResponse {
        match state.write() {
            Ok(bytes) => match std::str::from_utf8(&bytes) {
                Ok(metrics) => (StatusCode::OK, metrics.to_string()),
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to get metrics: {e}"),
                ),
            },
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to get metrics: {e}"),
            ),
        }
    }
}
