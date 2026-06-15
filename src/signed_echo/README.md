# Signed Echo

`signed_echo` is a simple Axum pivot app for QOS bridge-based ingress. It
listens on localhost TCP, accepts UTF-8 POST bodies, and returns the body with
a quorum-key signature over the QOS JSON bytes of `signed_payload_json`:

```json
{"domain":"echo app signed","message":"hello","time":"1700000000"}
```

## Run Locally

```sh
cargo run -p signed_echo -- \
  --host 127.0.0.1 \
  --port 3000 \
  --quorum-file /path/to/qos.quorum.key
```

```sh
curl -X POST --data-binary 'hello' http://127.0.0.1:3000/echo
```

## Defaults

- host: `127.0.0.1`
- port: `3000`
- quorum key file: `/qos.quorum.key`

The POST handler is available at `/echo`.
