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

`cargo run -- --control-url http://localhost:3001/qos --usock /tmp/enclave-example/example.sock --host-port-override 4000`

The pivot app will be available on `localhost:4000` via the bridge, and `localhost:3000` directly.

## Transparent Egress POC

The `qos_bridge` image runs `/enclave_egress_interfaces.sh` before starting the
bridge binary. The script is intentionally POSIX `sh`, not `bash`, so it can run
in the minimal Stagex-based image used on Talos Kubernetes.

For a Kubernetes proof of concept, the container must run as root with network
administration privileges and access to `/dev/net/tun`. The exact pod shape may
vary by cluster policy, but the relevant settings are:

```yaml
securityContext:
  runAsUser: 0
  runAsGroup: 0
  readOnlyRootFilesystem: false
  capabilities:
    add:
      - NET_ADMIN
volumeMounts:
  - name: dev-net-tun
    mountPath: /dev/net/tun
volumes:
  - name: dev-net-tun
    hostPath:
      path: /dev/net/tun
      type: CharDevice
```

Set `QOS_BRIDGE_EGRESS_INTERFACE` if the outbound interface is not `eth0`. Set
`QOS_BRIDGE_SKIP_EGRESS_SETUP=1` to bypass the setup script for local testing.
