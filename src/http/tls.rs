//! Hot-swappable TLS configuration.

use arc_swap::ArcSwap;
use rustls::ServerConfig;
use std::sync::Arc;

/// A TLS configuration that can be replaced while connections are being
/// served.
///
/// Listeners read the current configuration per connection, so a renewed
/// certificate takes effect without a restart.
#[derive(Clone)]
pub struct TlsConfig(Arc<ArcSwap<ServerConfig>>);

impl TlsConfig {
    /// Creates a `TlsConfig` with an initial configuration.
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self(Arc::new(ArcSwap::new(config)))
    }

    /// Returns the current configuration.
    pub fn current(&self) -> Arc<ServerConfig> {
        self.0.load_full()
    }

    /// Replaces the configuration for future connections.
    ///
    /// Established connections keep the configuration they handshook with.
    pub fn reload(&self, config: Arc<ServerConfig>) {
        self.0.store(config);
    }
}

impl std::fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConfig").finish_non_exhaustive()
    }
}
