# TLS test fixtures (THROWAWAY)

Self-signed certificates/keys used **only** by `iwf-security` unit tests
(CN `iwf-0.example.org`). They carry no real-world trust and protect nothing.
They are committed so `cargo test` works on a fresh clone.

Regenerate with `./generate.sh` if needed.
