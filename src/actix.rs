//! `actix-web` DoS mitigation utilities

use std::future::{ready, Ready};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use actix_http::ConnectionType;
use actix_web::body::{EitherBody, MessageBody};
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::{HttpResponse, HttpMessage};
use futures_util::future::LocalBoxFuture;

use crate::ip_limiter::{ConnectionPermit, ProvideIpLimiter, SystemIpLimiter};

/// A per request kill switch
///
/// Calling [`KillSwitch::kill`] marks the connection as "must be closed"
#[derive(Clone)]
pub struct KillSwitch {
    killed: Arc<AtomicBool>,
}

impl KillSwitch {
    /// Request connection to closed
    pub fn kill(&self) {
        self.killed.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether kill switch is activated
    pub fn is_killed(&self) -> bool {
        self.killed.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// DoS Mitigation middleware
///
/// Responsibilities:
/// - Enforce per-IP limits (via [`ProvideIpLimiter`]) per request
/// - Attach a [`KillSwitch`] to each request
///
/// If IP limits are exceeded, the Middleware returns:
/// `429 Too Many Requests` and `Connection::Close`
pub struct DosMitigation<P = SystemIpLimiter> {
    provider: P,
}

impl DosMitigation<SystemIpLimiter> {
    /// Create a default instance of the Mitigation using the default IP-Limiter
    pub fn default() -> Self {
        DosMitigation { provider: SystemIpLimiter }
    }
}

impl<P> DosMitigation<P> {
    /// Create a new instance of the Mitigation using a custom provider
    pub fn new(provider: P) -> Self {
        DosMitigation { provider }
    }
}

impl<S, B, P> Transform<S, ServiceRequest> for DosMitigation<P>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    S::Future: 'static,
    B: MessageBody + 'static,
    P: ProvideIpLimiter + Clone + Send + Sync + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = DosMitigationMiddleware<S, P>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(DosMitigationMiddleware {
            service,
            provider: self.provider.clone(),
        }))
    }
}

/// Inner Middleware for DoS Mitigation, see [`DosMitigation`]
pub struct DosMitigationMiddleware<S, P> {
    service: S,
    provider: P,
}

impl<S, B, P> Service<ServiceRequest> for DosMitigationMiddleware<S, P>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    S::Future: 'static,
    B: MessageBody + 'static,
    P: ProvideIpLimiter + Clone + Send + Sync + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let ip = req
            .peer_addr()
            .map(|addr| addr.ip());

        let permit = ip
            .and_then(|ip| {
                ConnectionPermit::new_with(ip, "HTTP request", self.provider.clone())
            });

        // Permit not retrievable (rate limit active or ip missing) -> 429 + force close
        if permit.is_none() {
            let (req_head, _pl) = req.into_parts();

            let mut res = HttpResponse::TooManyRequests()
                .json("Too many requests");

            res
                .head_mut()
                .set_connection_type(ConnectionType::Close);

            let srv_res = ServiceResponse::new(req_head, res).map_into_right_body();
            return Box::pin(async { Ok(srv_res) });
        }

        // Checked above
        let permit = permit.unwrap();

        // Create and insert kill switch into req
        let kill_switch = KillSwitch {
            killed: Arc::new(AtomicBool::new(false)),
        };

        req.extensions_mut().insert(kill_switch.clone());

        let fut = self.service.call(req);

        Box::pin(async move {
            let mut res = fut.await?;
            if kill_switch.is_killed() {
                res
                    .response_mut()
                    .head_mut()
                    .set_connection_type(ConnectionType::Close);
            }
            drop(permit);
            Ok(res.map_into_left_body())
        })
    }
}
