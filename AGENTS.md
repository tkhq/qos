# Agent Notes

- Rust workspace root is `src/`.
- Prefer local commands for ordinary development:

```sh
# native
make -C src lint
make -C src test
```

- Only use the root Docker-backed commands when explicitly asked or when verifying the containerized CI path:

```sh
# docker
make lint
make test
```

- Plain `cargo clippy` is not CI-equivalent because it skips test targets. Use this when checking Clippy directly:

```sh
cd src
cargo clippy --all-targets --locked
```
