# OWASP MASVS Alignment Checklist

This checklist tracks security work for future mobile and desktop releases. It is not a certification claim.

| Area | MVP Status | Aegis Work Item |
|---|---|---|
| MASVS-STORAGE | Partial | Encrypted vault exists; add encrypted chat history schema and encrypted backup format |
| MASVS-CRYPTO | Partial | Use reviewed primitives; keep PQXDH, Double Ratchet, and ML-KEM vectors in CI |
| MASVS-AUTH | Planned | Add passkeys, hardware-key vault unlock, and device approval UX |
| MASVS-NETWORK | Partial | HTTPS enforced except localhost; add certificate pinning decision and Tor/I2P mode |
| MASVS-PLATFORM | Planned | Add OS lock/sleep hooks, anti-screenshot where supported, and secure clipboard handling |
| MASVS-CODE | Partial | Rust memory safety baseline; add cargo audit/deny, dependency review, fuzzing |
| MASVS-RESILIENCE | Planned | Define realistic tamper/debugging expectations per platform |
| MASVS-PRIVACY | Partial | Relay avoids plaintext and contact graph; traffic correlation remains a known limitation |
