#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! DoS and DDoS mitigation utilities.

#[cfg(feature = "axum")]
pub mod axum;
pub mod ip_limiter;
pub mod rate_limiter;
#[cfg(feature = "tokio")]
pub mod tokio_net;
