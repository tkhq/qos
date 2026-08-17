# QOS app host bridge

QOS Host Bridge bridges TCP traffic from the host to the enclave's application by establishing a TCP → VSOCK connection. It receives the active server-bridge policy from the enclave over the bridge-control VSOCK connection, hashes that policy with QOS JSON, and constructs the host-side bridge only after the policy is received. The enclave independently constructs the corresponding VSOCK → TCP half from the same policy, completing the full bridge.

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

For local development, `--usock` selects a Unix-domain socket, which lets the
host-side bridge and a local test reaper use filesystem socket paths instead of
VSOCK. A real Nitro enclave is reached over VSOCK with `--cid`:

```bash
cargo run -- --usock /tmp/enclave-example/example.sock --host-port-override 4000
```

```bash
cargo run -- --cid 16 --host-port-override 4000
```

The pivot app will be available on `localhost:4000` via the bridge, and `localhost:3000` directly.
