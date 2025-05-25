//! # Cookieless CSRF protection library
//!
//! This crate provides a [Tower] middleware that implements [Cross-Site-Request-Forgery] protection by validating the [Fetch Metadata] headers of the incoming HTTP request. It does not require cookies, or signing keys, or tokens.
//!
//! If you're looking for a classic CSRF cookie implementation, try [tower-surf] instead.
//!
//! ## Overview
//!
//! For a more in-depth explanation of the problem CSRF protection is trying to solve, and why using signed cookies is not always the best solution, refer to [this excellent writeup](https://github.com/golang/go/issues/73626) by [Filippo Valsorda](https://filippo.io).
//!
//! In short, this crate allows to protect web resources from cross-site inclusion and abuse by validating the [Fetch Metadata] headers and ensuring that only "safe" cross-site requests are allowed. In this context, "safe" means:
//!
//! - the request comes from the same origin (the site's exact scheme, host, and port), same site (any subdomain of the current domain), or are user-initiated (e.g. clicking on a bookmark, directly entering the website's address), OR...
//! - the request is a simple GET request coming from a navigation event (e.g. clicking on a link on another website), as long as it's not being embedded in elements like `<object>` or `<iframe>`.
//!
//! <div class="warning">
//!
//! If the request does not include the Fetch Metadata, such as a request coming from a non-browser user-agent, or a browser released before [2023](https://caniuse.com/mdn-http_headers_sec-fetch-site), the request will be accepted.
//!
//! You can change this behaviour by setting the [reject_missing_metadata](PolicyBuilder::reject_missing_metadata) flag on the evaluation policy, but it might make your website not accessible to some users. Note that this is not a good protection against non-browser clients, as they can set the necessary headers anyway.
//!
//! </div>
//!
//! ## Usage
//!
//! Add the library to your Cargo.toml
//!
//! ```toml
//! [dependencies]
//! tower-sec-fetch = "*"
//! ```
//!
//! Here's how to use it with [Axum], but it works with any tower-based server.
//!
//! ```
//! # use axum::routing::get;
//! # use tower_sec_fetch::SecFetchLayer;
//! #
//! # fn main() {
//! let routes = axum::Router::new()
//!     .route("/hello", get(async || "hello"))
//!     .layer(SecFetchLayer::default());
//! #
//! # let routes: axum::Router = routes;
//! # }
//! ```
//!
//! Specific paths can be explicitely allowed.
//!
//! ```
//! # use axum::routing::get;
//! # use tower_sec_fetch::SecFetchLayer;
//! #
//! # fn main() {
//! let routes = axum::Router::new()
//!     .route("/hello", get(async || "hello"))
//!     .route("/unprotected", get(async || "unprotected"))
//!     .layer(SecFetchLayer::default().allowing(["/unprotected"]));
//! #
//! # let routes: axum::Router = routes;
//! # }
//! ```
//!
//! You can override the default authorization logic with a custom [SecFetchAuthorizer].
//!
//! ```
//! use tower_sec_fetch::{AuthorizationDecision, SecFetchAuthorizer, SecFetchLayer};
//!
//! struct MyAuthorizer;
//!
//! impl SecFetchAuthorizer for MyAuthorizer {
//!    fn authorize<B>(&self, request: &http::Request<B>) -> AuthorizationDecision {
//!        // allow all requests that come from a specific domain
//!        if request.uri().host() == Some("my-domain.com") {
//!            return AuthorizationDecision::Allowed;
//!        }
//!
//!        // otherwise, continue with the regular evaluation policy
//!        AuthorizationDecision::Continue
//!    }
//! }
//!
//! SecFetchLayer::default().with_authorizer(MyAuthorizer);
//! ```
//!
//! You can provide a [SecFetchReporter] implementation to be notified of a request being blocked. This can be useful for analytics and monitoring, but also to incrementally introduce this middleware in an existing system where there might be the risk of blocking legitimate requests by accident, when combined with the [no_enforce](SecFetchLayer::no_enforce) flag.
//!
//! ```
//! use tower_sec_fetch::{SecFetchLayer, SecFetchReporter};
//!
//! struct LogReporter;
//!
//! impl SecFetchReporter for LogReporter {
//!     fn on_request_denied<B>(&self, request: &http::Request<B>) {
//!         let uri = request.uri();
//!         let method = request.method();
//!         let headers = request.headers();
//!
//!         eprintln!("request was denied: {method} {uri} {headers:?}");
//!     }
//! }
//!
//! SecFetchLayer::default().no_enforce().with_reporter(LogReporter);
//! ```
//!
//! [Safe methods](https://developer.mozilla.org/en-US/docs/Glossary/Safe/HTTP) are not allowed for cross-origin requests, but this can optionally be disabled by setting the [allow_safe_methods](PolicyBuilder::allow_safe_methods) flag on the evaluation policy.
//!
//! ```
//! # use tower_sec_fetch::SecFetchLayer;
//! #
//! SecFetchLayer::new(|policy| {
//!     policy.allow_safe_methods();
//! });
//! ```
//!
//! If the Fetch Metadata headers are missing, the request is allowed. This can be disabled by setting the [reject_missing_metadata](PolicyBuilder::reject_missing_metadata) flag on the evaluation policy.
//!
//! ```
//! # use tower_sec_fetch::SecFetchLayer;
//! #
//! SecFetchLayer::new(|policy| {
//!     policy.reject_missing_metadata();
//! });
//! ```
//!
//! [Tower]: https://docs.rs/tower
//! [Cross-Site-Request-Forgery]: https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/CSRF
//! [Fetch Metadata]: https://developer.mozilla.org/en-US/docs/Glossary/Fetch_metadata_request_header
//! [tower-surf]: https://docs.rs/tower-surf
//! [Axum]: https://docs.rs/axum

use std::sync::Arc;

use futures::future::{self, Either, Ready};
use http::StatusCode;
use policy::Policy;
use tower::{Layer, Service};

pub use authorizer::*;
pub use policy::PolicyBuilder;
pub use reporter::*;

mod authorizer;
pub mod header;
mod policy;
mod reporter;

/// Layer that applies [SecFetch] which validates request against CSRF attacks
pub struct SecFetchLayer<A = NoopAuthorizer, R = NoopReporter> {
    enforce: bool,
    policy: Policy,
    authorizer: Arc<A>,
    reporter: Arc<R>,
}

impl<A, R> Clone for SecFetchLayer<A, R> {
    fn clone(&self) -> Self {
        Self {
            enforce: self.enforce,
            policy: self.policy,
            authorizer: self.authorizer.clone(),
            reporter: self.reporter.clone(),
        }
    }
}

impl Default for SecFetchLayer {
    fn default() -> Self {
        Self {
            enforce: true,
            policy: Policy::default(),
            authorizer: Arc::new(NoopAuthorizer),
            reporter: Arc::new(NoopReporter),
        }
    }
}

impl SecFetchLayer {
    pub fn new<F>(make_policy: F) -> Self
    where
        F: FnOnce(&mut PolicyBuilder),
    {
        let mut builder = PolicyBuilder::new();
        make_policy(&mut builder);
        let policy = builder.build();
        Self {
            policy,
            ..Default::default()
        }
    }
}

impl<OldA, OldR> SecFetchLayer<OldA, OldR> {
    pub fn allowing(
        self,
        paths: impl Into<Arc<[&'static str]>>,
    ) -> SecFetchLayer<PathAuthorizer, OldR> {
        self.with_authorizer(PathAuthorizer::new(paths))
    }

    pub fn no_enforce(mut self) -> Self {
        self.enforce = false;
        self
    }

    pub fn with_authorizer<A: SecFetchAuthorizer>(self, authorizer: A) -> SecFetchLayer<A, OldR> {
        SecFetchLayer {
            enforce: self.enforce,
            policy: self.policy,
            authorizer: Arc::from(authorizer),
            reporter: self.reporter,
        }
    }

    pub fn with_reporter<R: SecFetchReporter>(self, reporter: R) -> SecFetchLayer<OldA, R> {
        SecFetchLayer {
            enforce: self.enforce,
            policy: self.policy,
            authorizer: self.authorizer,
            reporter: Arc::from(reporter),
        }
    }
}

impl<A, R, S> Layer<S> for SecFetchLayer<A, R> {
    type Service = SecFetch<A, R, S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecFetch {
            enforce: self.enforce,
            policy: self.policy,
            authorizer: self.authorizer.clone(),
            reporter: self.reporter.clone(),
            inner,
        }
    }
}

/// Middleware protecting against CSRF attacks
pub struct SecFetch<A, R, S> {
    enforce: bool,
    policy: Policy,
    authorizer: Arc<A>,
    reporter: Arc<R>,
    inner: S,
}

impl<A, R, S> Clone for SecFetch<A, R, S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            enforce: self.enforce,
            policy: self.policy,
            authorizer: self.authorizer.clone(),
            reporter: self.reporter.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<A, R, ReqB, ResB, S> Service<http::Request<ReqB>> for SecFetch<A, R, S>
where
    A: SecFetchAuthorizer,
    R: SecFetchReporter,
    S: Service<http::Request<ReqB>, Response = http::Response<ResB>>,
    ResB: Default,
{
    type Response = S::Response;

    type Error = S::Error;

    type Future = Either<S::Future, Ready<Result<Self::Response, Self::Error>>>;

    #[inline]
    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<ReqB>) -> Self::Future {
        #[cfg(feature = "tracing")]
        tracing::debug!(
            method = %request.method(),
            path = request.uri().path(),
            "processing request",
        );

        let mut allow = |request: http::Request<ReqB>| {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                method = %request.method(),
                path = request.uri().path(),
                "request allowed",
            );

            Either::Left(self.inner.call(request))
        };

        let deny = || {
            #[cfg(feature = "tracing")]
            tracing::debug!(
                method = %request.method(),
                path = request.uri().path(),
                "request",
            );

            Either::Right(future::ready(Ok(http::Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(ResB::default())
                .expect("valid response"))))
        };

        match self.authorizer.authorize(&request) {
            AuthorizationDecision::Allowed => return allow(request),
            AuthorizationDecision::Denied => return deny(),
            AuthorizationDecision::Continue => {}
        }

        if self.policy.allow(&request) {
            return allow(request);
        }

        self.reporter.on_request_denied(&request);

        // the request was denied, but we are not enforcing it
        // we report the failure and let the request continue
        if !self.enforce {
            return allow(request);
        }

        deny()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use assert2::{check, let_assert};
    use http::Method;
    use tower::ServiceExt;
    use tower_test::mock;

    use super::*;

    macro_rules! request {
        (site => $site:expr, mode => $mode:expr, dest => $dest:expr) => {
            request!(::http::Method::GET, "/", site => $site, mode => $mode, dest => $dest)
        };

        ($path:expr, site => $site:expr, mode => $mode:expr, dest => $dest:expr) => {
            request!(::http::Method::GET, $path, site => $site, mode => $mode, dest => $dest)
        };

        ($method:expr, $path:expr, site => $site:expr, mode => $mode:expr, dest => $dest:expr) => {
            ::http::Request::builder()
                .method($method)
                .uri(format!("https://example.com{}", $path))
                .header(header::SEC_FETCH_SITE, $site)
                .header(header::SEC_FETCH_MODE, $mode)
                .header(header::SEC_FETCH_DEST, $dest)
                .body(())
                .unwrap()
        };
    }

    macro_rules! assert_request {
        ($req:expr, $assert_resp:expr) => {
            assert_request!($req, $assert_resp, SecFetchLayer::default())
        };

        ($req:expr, $assert_resp:expr, $layer:expr) => {
            let (service, mut handler) =
                mock::spawn_layer::<http::Request<()>, http::Response<()>, _>($layer);

            tokio::spawn(async move {
                let_assert!(Some((_, send)) = handler.next_request().await);
                send.send_response(http::Response::new(()));
            });

            let response = service.into_inner().oneshot($req).await.unwrap();

            ($assert_resp)(response);
        };
    }

    #[tokio::test]
    async fn it_allows_requests_missing_the_fetch_metadata() {
        let request = http::Request::new(());

        assert_request!(request, |response: http::Response<()>| {
            check!(response.status().is_success());
        });
    }

    #[tokio::test]
    async fn it_rejects_requests_missing_the_fetch_metadata_if_configured() {
        let layer = SecFetchLayer::new(|policy| {
            policy.reject_missing_metadata();
        });
        let request = http::Request::new(());

        assert_request!(
            request,
            |response: http::Response<()>| {
                check!(response.status() == StatusCode::FORBIDDEN);
            },
            layer
        );
    }

    #[tokio::test]
    async fn it_allows_same_site_requests() {
        let request = request!(site => "same-site", mode => "navigate", dest => "document");

        assert_request!(request, |response: http::Response<()>| {
            check!(response.status().is_success());
        });
    }

    #[tokio::test]
    async fn it_disallows_cross_origin_requests() {
        let request = request!(site => "cross-site", mode => "cors", dest => "empty");

        assert_request!(request, |response: http::Response<()>| {
            check!(response.status() == StatusCode::FORBIDDEN);
        });
    }

    #[tokio::test]
    async fn it_allows_cross_origin_requests_safe_methods_if_configured() {
        let layer = SecFetchLayer::new(|policy| {
            policy.allow_safe_methods();
        });
        let request =
            request!(Method::GET, "/", site => "cross-site", mode => "cors", dest => "empty");

        assert_request!(
            request,
            |response: http::Response<()>| {
                check!(response.status().is_success());
            },
            layer
        );
    }

    #[tokio::test]
    async fn it_allows_navigation_requests() {
        let request = request!(site => "cross-site", mode => "navigate", dest => "document");

        assert_request!(request, |response: http::Response<()>| {
            check!(response.status().is_success());
        });
    }

    #[tokio::test]
    async fn it_ignores_explicitely_authorized_requests() {
        let layer = SecFetchLayer::default().allowing(["/allowed"]);
        let request = request!("/allowed", site => "cross-site", mode => "cors", dest => "empty");

        assert_request!(
            request,
            |response: http::Response<()>| {
                check!(response.status().is_success());
            },
            layer
        );
    }

    #[tokio::test]
    async fn it_allows_denied_requests_if_enforcement_is_turned_off() {
        let layer = SecFetchLayer::default().no_enforce();
        let request = request!(site => "cross-site", mode => "cors", dest => "empty");

        assert_request!(
            request,
            |response: http::Response<()>| {
                check!(response.status().is_success());
            },
            layer
        );
    }

    #[derive(Default)]
    struct TestReporter {
        called: AtomicBool,
    }

    impl SecFetchReporter for TestReporter {
        fn on_request_denied<B>(&self, _: &http::Request<B>) {
            self.called.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn it_reports_a_denied_requests() {
        let reporter = Arc::new(TestReporter::default());
        let layer = SecFetchLayer::default().with_reporter(reporter.clone());
        let request = request!(site => "cross-site", mode => "cors", dest => "empty");

        assert_request!(
            request,
            |response: http::Response<()>| {
                check!(response.status() == StatusCode::FORBIDDEN);
            },
            layer
        );

        let called = reporter.called.load(Ordering::SeqCst);
        check!(
            called,
            "reporter was not called despite the request being rejected"
        );
    }
}
