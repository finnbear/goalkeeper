

# goalkeeper

[![Documentation](https://docs.rs/goalkeeper/badge.svg)](https://docs.rs/goalkeeper)
[![crates.io](https://img.shields.io/crates/v/goalkeeper.svg)](https://crates.io/crates/goalkeeper)
[![Build](https://github.com/finnbear/goalkeeper/actions/workflows/build.yml/badge.svg)](https://github.com/finnbear/goalkeeper/actions/workflows/build.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

DoS and DDoS protection library.

## Features
- [x] Custom `tokio` executor with task priorities
- [x] Connection count limits
- [x] Bandwidth limits/priorities
- [x] CPU limits/priorities
- [x] RAM limits/priorities
- [x] TLS handshake timeouts and concurrency limits
- [x] TCP timeouts, pacing, delaying, and buffer limits/priorities
- [x] HTTP timeouts and concurrency limits
- [x] Logging (`log`)
- [x] Metrics
- [ ] `nftables` firewall configuration
- [ ] OS network stack hardening

## Protocols (feature flags)
- [x] HTTP/1 and HTTP/2 (`hyper`/`axum`)
- [x] WebSocket (`axum-tws`/`tokio-websockets`)
- [x] WebTransport (`wtransport`/`quinn`)
- [x] TLS for all of the above (`rustls`)

## Limitations
- Not optimized for multi-core runtimes
- ~15% max throughput reduction
- Requires a `nightly` toolchain

## Status

Gradually migrating related functionality from other projects.

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
