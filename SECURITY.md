# Security Policy

## Supported Versions

Aegis Messenger is pre-release software. Security fixes target the `main` branch until the first tagged stable release exists.

## Reporting a Vulnerability

Please do not open public issues for exploitable vulnerabilities. Send a private report to the maintainers with:

- affected component and commit
- reproduction steps
- expected impact
- any proof-of-concept inputs

The project aims to acknowledge valid reports within 7 days. Do not include private keys, passphrases, message plaintext, or real user data in reports.

## Security Boundaries

The relay server must never receive message plaintext, file plaintext, private keys, contact graph exports, searchable message indexes, or plaintext attachment metadata. Server logs must not contain ciphertext blobs beyond short identifiers needed for diagnostics.

Cryptographic primitives must come from reviewed libraries. Protocol glue must fail closed on unknown cipher suites, protocol versions, malformed keys, failed signatures, downgrade attempts, replayed messages, and tampered ciphertext.

## Pre-Release Disclosure

This project has not completed an external security audit. Treat current builds as research/demo quality, not production-grade personal safety software.
