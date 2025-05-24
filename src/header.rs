use http::HeaderName;

pub const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");
pub const SEC_FETCH_MODE: HeaderName = HeaderName::from_static("sec-fetch-mode");
pub const SEC_FETCH_DEST: HeaderName = HeaderName::from_static("sec-fetch-dest");
