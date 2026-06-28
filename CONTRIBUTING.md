# Contributing

## Development Checks

Run these before submitting changes:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets --no-fail-fast
cd desktop && npm run check
```

Security-sensitive changes should include focused tests for failure modes, not only happy paths. Examples: malformed envelope rejection, replay rejection, wrong-key decrypt failure, expired relay envelope cleanup, and invalid prekey signature rejection.

## Crypto Rules

- Do not introduce custom cryptographic primitives.
- Do not silently downgrade cipher suites or KEM support.
- Do not store private keys, plaintext messages, plaintext files, or contact graphs on the relay.
- Keep new wire formats versioned and fail closed on unknown versions.
- Use constant-time comparison for secrets and capability tokens.

## Documentation

When changing a security property, update `README.md`, `docs/THREAT_MODEL.md`, `docs/CRYPTO_DESIGN.md`, and `docs/LIMITATIONS.md` so implemented, partial, and planned properties stay honest.
