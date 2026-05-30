# Signed Echo

`signed_echo` is a simple Axum pivot app for QOS bridge-based ingress. It
listens on localhost TCP, accepts UTF-8 POST bodies, and returns the body with
a quorum-key signature over:

```text
b"echo app signed at" || unix_time_seconds_u64_be || message_utf8_bytes
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
- domain separator: `echo app signed at`

The POST handler is available at `/echo`, `/signed-echo`, and `/signed_echo`.
