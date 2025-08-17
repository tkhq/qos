use metrics::{
    Collector, Server, lazy_static,
    prometheus::{Counter, Registry},
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    thread,
    time::Duration,
};

lazy_static! {
    pub static ref TEST_COUNT: Counter =
        Counter::new("count", "Test Counter").expect("metric can be created");
}

fn registry() -> Registry {
    let registry = Registry::new_custom(Some("test".to_string()), None).unwrap();
    registry.register(Box::new(TEST_COUNT.clone())).unwrap();
    registry
}

fn increment_count() {
    TEST_COUNT.inc();
}

#[tokio::main]
async fn main() {
    let mut collector = Collector::new();

    let registry = registry();
    collector.register(registry);

    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(1));
            increment_count();
            #[cfg(feature = "request")]
            {
                use metrics::request;
                request::track_enclave_request(
                    "test_method",
                    true,
                    std::time::Duration::from_millis(1),
                );
                request::track_enclave_request(
                    "test_method",
                    false,
                    std::time::Duration::from_millis(1),
                );
            }
        }
    });

    let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    Server::new().serve(socket, collector).await;
}
