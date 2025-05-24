# tower-sec-fetch

[![CI](https://github.com/MatteoJoliveau/tower-sec-fetch/actions/workflows/ci.yml/badge.svg)](https://github.com/MatteoJoliveau/tower-sec-fetch/actions/workflows/ci.yml)
[![Release](https://github.com/MatteoJoliveau/tower-sec-fetch/actions/workflows/release.yml/badge.svg)](https://github.com/MatteoJoliveau/tower-sec-fetch/actions/workflows/release.yml)
[![docs.rs build](https://img.shields.io/docsrs/tower-sec-fetch)](https://docs.rs/tower-sec-fetch)
[![Crates.io Version](https://img.shields.io/crates/v/tower-sec-fetch)](https://crates.io/crates/tower-sec-fetch)

**Cookieless CSRF protection library**

This crate provides a [Tower] middleware that implements [Cross-Site-Request-Forgery] protection by validating the [Fetch Metadata] headers of the incoming HTTP request. It does not require cookies, or signing keys, or tokens.

If you're looking for a classic CSRF cookie implementation, try [tower-surf] instead.

Check the [docs](https://docs.rs/tower-sec-fetch) for more information and usage examples.

## Overview

For a more in-depth explanation of the problem CSRF protection is trying to solve, and why using signed cookies is not always the best solution, refer to [this excellent writeup](https://github.com/golang/go/issues/73626) by [Filippo Valsorda](https://filippo.io).

In short, this crate allows to protect web resources from cross-site inclusion and abuse by validating the [Fetch Metadata] headers and ensuring that only "safe" cross-site requests are allowed. In this context, "safe" means:

- the request comes from the same origin (the site's exact scheme, host, and port), same site (any subdomain of the current domain), or are user-initiated (e.g. clicking on a bookmark, directly entering the website's address), OR...
- the request is a simple GET request coming from a navigation event (e.g. clicking on a link on another website), as long as it's not being embedded in elements like `<object>` or `<iframe>`.

## Examples

The [examples](examples) folder contains various examples of how to use tower-sec-fetch:

- [axum](examples/axum.rs): the simplest way to add CSRF protection to an [Axum](https://docs.rs/axum) application.
- [report-violations-and-allow](examples/report-violations-and-allow.rs): how to detect potentially unsafe requests without actually blocking them. This is useful for incrementally adopting tower-sec-fetch without breaking existing applications.
- [reject-missing-metadata](examples/reject-missing-metadata.rs): disallow even requests that don't supply the Fetch Metadata. Note that this usually includes non-browser clients, and might make your website unusable for some users.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
</sub>

[Tower]: https://docs.rs/tower
[Cross-Site-Request-Forgery]: https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/CSRF
[Fetch Metadata]: https://developer.mozilla.org/en-US/docs/Glossary/Fetch_metadata_request_header
