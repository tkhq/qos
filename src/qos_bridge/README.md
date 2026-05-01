# QOS app host bridge

QOS Host Bridge bridges TCP traffic from the host to the enclave's application by establishing a TCP → VSOCK connection. It fetches the enclave's manifest via qos_host and constructs the host-side bridge according to the configuration specified by the manifest. The enclave independently constructs the corresponding VSOCK → TCP half from the same manifest, completing the full bridge.

## Local Dev

To use on local, separate ports are required since we cannot bind the two sides of the bridge on the same port.
The `--host-port-override` argument can be used for that effect.

### Example local use

Provided a bridge configuration of
```json
{
  "type": "server",
  "port": "3000",
  "host": "127.0.0.1"
}
```

`cargo run -- --control-url http://localhost:3001/qos --usock /tmp/enclave-example/example.sock --
host-port-override 4000`

The pivot app will be available on `localhost:4000` via the bridge, and `localhost:3000` directly.
