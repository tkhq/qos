//! useful metrics for requests
use axum::http::Request as HttpRequest;
use lazy_static::lazy_static;
use prometheus::{Error, HistogramOpts, HistogramVec, IntGauge, Registry};
use std::collections::HashSet;
use std::env;

const NAMESPACE: &str = "tk";
const LATENCY_MS_BUCKETS: [f64; 10] = [
    1.0, 5.0, 10.0, 20.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 5000.0,
];
const DETAIL_LATENCY_MS_BUCKETS: [f64; 10] = [
    1.0, 5.0, 10.0, 20.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 5000.0,
];

lazy_static! {
    /// release version of host
    pub static ref RELEASE: String = env::var("RELEASE").unwrap_or_else(|_| "unknown".to_string());

    /// request latency histogram
    pub static ref REQUEST_HISTOGRAM: HistogramVec = HistogramVec::new(
        HistogramOpts::new("enclave_latency_ms", "host-to-enclave request latency in milliseconds").buckets(LATENCY_MS_BUCKETS.to_vec()),
        &["result", "method", "release"],
    ).expect("metric can be created");

    /// request latency details histogram
    pub static ref REQUEST_DETAILS_HISTOGRAM: HistogramVec = HistogramVec::new(
        HistogramOpts::new("enclave_latency_details_ms", "enclave host request lifecycle details in milliseconds").buckets(DETAIL_LATENCY_MS_BUCKETS.to_vec()),
        &["result", "method", "stage", "release"],
    ).expect("metric can be created");

    /// gauge for waiting requests
    pub static ref WAITING_REQUESTS_GUAGE: IntGauge = IntGauge::new("waiting_requests_gauge", "Waiting Requests Gauge").expect("metric can be created");
}

/// returns a new Registry
pub fn registry() -> Result<Registry, Error> {
    let registry = Registry::new_custom(Some(NAMESPACE.to_string()), None)?;

    registry.register(Box::new(REQUEST_HISTOGRAM.clone()))?;
    registry.register(Box::new(REQUEST_DETAILS_HISTOGRAM.clone()))?;

    // Removing this for now - will add back when we have figured out the proper place for the middleware to go
    // registry.register(Box::new(WAITING_REQUESTS_GUAGE.clone()))?;
    Ok(registry)
}

/// generates middleware for incrememnting the waiting counter with every request
pub fn make_inc_waiting_middleware(
    target_uris: HashSet<String>,
) -> impl Fn(&HttpRequest<()>) -> tracing::Span {
    move |req: &HttpRequest<()>| {
        // Check if the request URI matches any of the target URIs
        if target_uris.contains(req.uri().path()) {
            inc_waiting(); // Call inc_waiting() only if the URI matches
        }

        // Create a trace span for the request
        tracing::info_span!(
            "request",
            method = %req.uri(),
            version = ?req.version(),
            headers = ?req.headers()
        )
    }
}

/// tracks enclave requests and their latency
pub fn track_enclave_request(method: &str, ok: bool, latency: std::time::Duration) {
    let result = if ok { "success" } else { "failure" };

    REQUEST_HISTOGRAM
        .with_label_values(&[result, method, &RELEASE])
        .observe(latency.as_secs_f64() * 1_000.0);
}

/// tracks enclave details requests and their latency
pub fn track_enclave_details(method: &str, ok: bool, stage: &str, latency: std::time::Duration) {
    let result = if ok { "success" } else { "failure" };

    REQUEST_DETAILS_HISTOGRAM
        .with_label_values(&[result, method, stage, &RELEASE])
        .observe(latency.as_secs_f64() * 1_000.0);
}

/// increment the request total
pub fn inc_waiting() {
    WAITING_REQUESTS_GUAGE.inc(); // DEBUG: testing if we call this at all
}

/// decrement the request total
pub fn dec_waiting() {
    WAITING_REQUESTS_GUAGE.dec();
}
