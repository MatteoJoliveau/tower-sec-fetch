use http::{HeaderValue, Method};

use crate::header;

#[derive(Copy, Clone, Default)]
pub struct Policy {
    reject_missing_metadata: bool,
    allow_safe_methods: bool,
}

impl Policy {
    // Resource Isolation Policy
    // Implemented following https://web.dev/articles/fetch-metadata
    pub fn allow<B>(&self, request: &http::Request<B>) -> bool {
        if self.allow_safe_methods
            && method_in(
                request.method(),
                [Method::GET, Method::HEAD, Method::OPTIONS],
            )
        {
            #[cfg(feature = "tracing")]
            tracing::trace!(
                method = %request.method(),
                path = request.uri().path(),
                "request uses a safe method: allowed",
            );

            return true;
        }

        let sec_fetch_site = request.headers().get(header::SEC_FETCH_SITE);
        let sec_fetch_mode = request.headers().get(header::SEC_FETCH_MODE);
        let sec_fetch_dest = request.headers().get(header::SEC_FETCH_DEST);

        let sec_fetch = zip3(sec_fetch_site, sec_fetch_mode, sec_fetch_dest);

        let Some((sec_fetch_site, sec_fetch_mode, sec_fetch_dest)) = sec_fetch else {
            #[cfg(feature = "tracing")]
            tracing::trace!(
                method = %request.method(),
                path = request.uri().path(),
                "request is missing fetch metadata: {}",
                if self.reject_missing_metadata { "denied" } else { "allowed" },
            );

            // Fetch metadata headers are missing.
            // Either the request doesn't come from a browser, or the browser is too old.
            return !self.reject_missing_metadata;
        };

        if header_in(sec_fetch_site, ["same-origin", "same-site", "none"]) {
            #[cfg(feature = "tracing")]
            tracing::trace!(
                method = %request.method(),
                path = request.uri().path(),
                "request is same-site or user initiated: allowed",
            );

            // request is same-site or user initiated
            return true;
        }

        if sec_fetch_mode == "navigate"
            && request.method() == Method::GET
            && header_in(sec_fetch_dest, ["empty", "document"])
        {
            #[cfg(feature = "tracing")]
            tracing::trace!(
                method = %request.method(),
                path = request.uri().path(),
                "request is a non-embed navigation: allowed",
            );

            // request is a regular navigation event and is not being embedded
            return true;
        }

        #[cfg(feature = "tracing")]
        tracing::trace!(
            method = %request.method(),
            path = request.uri().path(),
            "request denied",
        );

        // request is denied
        false
    }
}

/// Allows customizing the behaviour of the default evaluation policy
pub struct PolicyBuilder {
    reject_missing_metadata: bool,
    allow_safe_methods: bool,
}

impl PolicyBuilder {
    pub(crate) fn new() -> Self {
        Self {
            reject_missing_metadata: false,
            allow_safe_methods: false,
        }
    }

    /// Reject requests that do not provide all three Fetch Metadata headers:
    /// `sec-fetch-site`, `sec-fetch-mode`, `sec-fetch-dest`
    pub fn reject_missing_metadata(&mut self) -> &mut Self {
        self.reject_missing_metadata = true;
        self
    }

    /// Allow safe requests (`GET`, `HEAD`, and `OPTIONS`) regardless of their origin
    pub fn allow_safe_methods(&mut self) -> &mut Self {
        self.allow_safe_methods = true;
        self
    }

    pub(crate) fn build(self) -> Policy {
        Policy {
            reject_missing_metadata: self.reject_missing_metadata,
            allow_safe_methods: self.allow_safe_methods,
        }
    }
}

fn zip3<T1, T2, T3>(a: Option<T1>, b: Option<T2>, c: Option<T3>) -> Option<(T1, T2, T3)> {
    match (a, b, c) {
        (Some(a), Some(b), Some(c)) => Some((a, b, c)),
        _ => None,
    }
}

fn header_in(header: &HeaderValue, values: impl IntoIterator<Item = &'static str>) -> bool {
    values
        .into_iter()
        .map(HeaderValue::from_static)
        .any(|value| value == header)
}

fn method_in(method: &Method, values: impl IntoIterator<Item = Method>) -> bool {
    values.into_iter().any(|value| value == method)
}
