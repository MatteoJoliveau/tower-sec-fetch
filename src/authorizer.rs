use std::{ops::Deref, sync::Arc};

/// Custom request authorization logic
pub trait SecFetchAuthorizer {
    /// Authorizes the current request
    fn authorize<B>(&self, request: &http::Request<B>) -> AuthorizationDecision;
}

#[doc(hidden)]
pub struct NoopAuthorizer;

impl SecFetchAuthorizer for NoopAuthorizer {
    fn authorize<B>(&self, _: &http::Request<B>) -> AuthorizationDecision {
        AuthorizationDecision::Continue
    }
}

/// The decision made by a [SecFetchAuthorizer]
pub enum AuthorizationDecision {
    /// The request can be passed to the server
    /// Short-circuits the evaluation policy
    Allowed,
    /// The request is denied
    /// Short-circuits the evaluation policy
    Denied,
    /// The request is neither denied nor allowed, deferring
    /// to the evaluation policy
    Continue,
}

impl<T, A> SecFetchAuthorizer for T
where
    T: Deref<Target = A>,
    A: SecFetchAuthorizer,
{
    fn authorize<B>(&self, request: &http::Request<B>) -> AuthorizationDecision {
        self.deref().authorize(request)
    }
}

/// A [SecFetchAuthorizer] that allows requests based on their path
pub struct PathAuthorizer(Arc<[&'static str]>);

impl PathAuthorizer {
    pub fn new(allowed_paths: impl Into<Arc<[&'static str]>>) -> Self {
        Self(allowed_paths.into())
    }
}

impl SecFetchAuthorizer for PathAuthorizer {
    fn authorize<B>(&self, request: &http::Request<B>) -> AuthorizationDecision {
        if self.0.contains(&request.uri().path()) {
            return AuthorizationDecision::Allowed;
        }

        AuthorizationDecision::Continue
    }
}
