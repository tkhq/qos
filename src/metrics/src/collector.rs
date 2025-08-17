//! Metric collector
use prometheus::{Encoder, Error, Registry, TextEncoder};

/// Collector registers, collects, and gathers metrics
#[derive(Debug, Default)]
pub struct Collector {
    registries: Vec<Registry>,
}

impl Collector {
    /// returns a new `Collector`
    #[must_use]
    pub fn new() -> Self {
        #![allow(unused_mut)]
        #[allow(clippy::let_and_return)]
        let mut collector = Collector { registries: vec![] };

        #[cfg(feature = "request")]
        collector.register(crate::metrics::request::registry().expect("it works"));

        collector
    }

    /// registers a Registry
    pub fn register(&mut self, registry: Registry) -> &mut Self {
        self.registries.push(registry);
        self
    }

    /// write all metrics to a buffer
    pub fn write(&self) -> Result<Vec<u8>, Error> {
        let mut buffer = vec![];
        let encoder = TextEncoder::new();

        for registry in &self.registries {
            if !buffer.is_empty() {
                buffer.push(b'\n');
            }

            let metric_families = registry.gather();
            encoder.encode(&metric_families, &mut buffer)?;
        }

        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::{Counter, Opts};

    fn request_metrics() -> &'static str {
        #[cfg(feature = "request")]
        return r#"
# HELP tk_enclave_latency_ms host-to-enclave request latency in milliseconds
# TYPE tk_enclave_latency_ms histogram
tk_enclave_latency_ms_bucket{method="test",release="unknown",result="success",le="1"} 0
tk_enclave_latency_ms_bucket{method="test",release="unknown",result="success",le="5"} 0
tk_enclave_latency_ms_bucket{method="test",release="unknown",result="success",le="10"} 1
tk_enclave_latency_ms_bucket{method="test",release="unknown",result="success",le="20"} 1
tk_enclave_latency_ms_bucket{method="test",release="unknown",result="success",le="50"} 1
tk_enclave_latency_ms_bucket{method="test",release="unknown",result="success",le="100"} 1
tk_enclave_latency_ms_bucket{method="test",release="unknown",result="success",le="250"} 1
tk_enclave_latency_ms_bucket{method="test",release="unknown",result="success",le="500"} 1
tk_enclave_latency_ms_bucket{method="test",release="unknown",result="success",le="1000"} 1
tk_enclave_latency_ms_bucket{method="test",release="unknown",result="success",le="5000"} 1
tk_enclave_latency_ms_bucket{method="test",release="unknown",result="success",le="+Inf"} 1
tk_enclave_latency_ms_sum{method="test",release="unknown",result="success"} 10
tk_enclave_latency_ms_count{method="test",release="unknown",result="success"} 1
"#;

        #[cfg(not(feature = "request"))]
        return "";
    }

    #[test]
    fn it_works() {
        let mut collector = Collector::new();

        let registry1 = Registry::new_custom(Some("hot_potato".to_string()), None).unwrap();
        let counter_opts = Opts::new("test_counter", "useful description");
        let counter = Counter::with_opts(counter_opts).unwrap();
        registry1.register(Box::new(counter)).unwrap();

        let registry2 = Registry::new_custom(Some("cold_potato".to_string()), None).unwrap();
        let counter_opts = Opts::new("test_counter", "useful description");
        let counter = Counter::with_opts(counter_opts).unwrap();
        registry2.register(Box::new(counter)).unwrap();

        collector.register(registry1).register(registry2);

        // track a request
        crate::request::track_enclave_request("test", true, std::time::Duration::from_millis(10));

        let message = collector.write().unwrap();
        let expected = request_metrics().to_owned()
            + r#"
# HELP hot_potato_test_counter useful description
# TYPE hot_potato_test_counter counter
hot_potato_test_counter 0

# HELP cold_potato_test_counter useful description
# TYPE cold_potato_test_counter counter
cold_potato_test_counter 0
"#;

        assert_eq!(
            "\n".to_owned() + std::str::from_utf8(&message).unwrap(),
            expected
        );
    }
}
