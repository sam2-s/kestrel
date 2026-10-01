//! The help page, served from the relay's own origin.
//!
//! A help link has to open somewhere. Putting it on the relay's origin rather than
//! on a separate site means one thing to run, one thing to keep up, and no second
//! origin for a link to leak through.
//!
//! The page is served with a strict content policy and no third-party requests.
//! It does load map tiles, because a helper opening a link needs to see a street
//! rather than a dot on a blank field; that request goes to the tile host, which
//! sees the helper's address and the area of the emergency. That is a real cost
//! and it is stated in the privacy note on the page itself, because a helper
//! should be able to see it without being told.
//!
//! There is no registration, no storage, no service worker and no key here. The
//! page derives what it needs from the fragment in the URL and forgets it.

use axum::{
    Router,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};

/// The page itself.
const PAGE: &str = include_str!("../../../web/help/index.html");

/// The viewer script.
const SCRIPT: &str = include_str!("../../../web/help/help.js");

/// The stylesheet.
const STYLE: &str = include_str!("../../../web/help/help.css");

/// The path a help link points at.
pub const PATH: &str = "/help";

/// The strictest content policy that still allows map tiles.
///
/// `default-src 'none'` and an explicit allowlist, so a bug that injects a script
/// from anywhere else fails to load rather than loading quietly. `connect-src`
/// includes `https:` because the relay's own origin may be either scheme
/// depending on how it is deployed, and the beacon's channel is derived from the
/// link rather than from this page.
fn policy() -> HeaderValue {
    HeaderValue::from_static(
        "default-src 'none'; \
         script-src 'self'; \
         style-src 'self'; \
         img-src 'self' data: blob: https://tile.openstreetmap.org; \
         connect-src 'self' https:; \
         base-uri 'none'; \
         form-action 'none'; \
         frame-ancestors 'none'",
    )
}

async fn index() -> Response {
    let mut out = (StatusCode::OK, PAGE).into_response();
    apply(&mut out, "text/html; charset=utf-8", true);
    out
}

async fn script() -> Response {
    let mut out = (StatusCode::OK, SCRIPT).into_response();
    apply(&mut out, "text/javascript; charset=utf-8", false);
    out
}

async fn style() -> Response {
    let mut out = (StatusCode::OK, STYLE).into_response();
    apply(&mut out, "text/css; charset=utf-8", false);
    out
}

fn apply(out: &mut Response, content_type: &'static str, frame_ancestors: bool) {
    let h = out.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::HeaderName::from_static("content-security-policy"), policy());
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let _ = frame_ancestors;
}

/// The help routes.
pub fn router() -> Router {
    Router::new()
        .route(PATH, get(index))
        .route("/help/help.js", get(script))
        .route("/help/help.css", get(style))
}
