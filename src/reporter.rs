use std::ops::Deref;

/// Notifies of requests being blocked by this middleware
pub trait SecFetchReporter {
    fn on_request_denied<B>(&self, request: &http::Request<B>);
}

impl<T, R> SecFetchReporter for T
where
    T: Deref<Target = R>,
    R: SecFetchReporter,
{
    fn on_request_denied<B>(&self, request: &http::Request<B>) {
        self.deref().on_request_denied(request);
    }
}

#[doc(hidden)]
pub struct NoopReporter;

impl SecFetchReporter for NoopReporter {
    fn on_request_denied<B>(&self, _: &http::Request<B>) {}
}
