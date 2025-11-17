# goalkeeper

[![Documentation](https://docs.rs/goalkeeper/badge.svg)](https://docs.rs/goalkeeper)
[![crates.io](https://img.shields.io/crates/v/goalkeeper.svg)](https://crates.io/crates/goalkeeper)
[![Build](https://github.com/finnbear/goalkeeper/actions/workflows/build.yml/badge.svg)](https://github.com/finnbear/goalkeeper/actions/workflows/build.yml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

DoS and DDoS protection library.

## Features

- [x] Rate limiting
- [x] Connection limiting
- [x] Bandwidth limiting
- [x] Optional `TCP_KEEPALIVE` and `TCP_NODELAY` helper function for `tokio::net::TcpStream`
- [x] Optional `axum` and `axum_server` support
- [x] Logging
- [ ] `nftables` firewall configuration
- [ ] OS network stack hardening

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