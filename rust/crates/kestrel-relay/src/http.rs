//! The relay's HTTP surface.
//!
//! The validation order here is load-bearing and is not the order that reads most
//! naturally. Each stage is cheaper than the next, and two of the orderings are
//! security decisions rather than optimisations:
//!
//! 1. **Rate limits run before anything else** — before the body is read, before
//!    any signature is checked, before the database is touched. Any 32 hex
//!    characters name a channel, so a client that picks a fresh channel for every
//!    request never meets the per-channel limit; the only limit that stops it is
//!    the per-address one, and that one has to run first.
//! 2. **The body size is bounded before it is parsed**, so a hostile client cannot
//!    make the relay buffer an arbitrary amount of memory.
//! 3. **The signature is checked before the channel is trusted with a row.**
//!    Storing a forged post wastes every member's bandwidth and fills the table
//!    with rows nobody can open.
//! 4. **The origin check runs before the rate limiter** on writes, because a
//!    cross-origin write is not a rate-limited request, it is a request from a
//!    page that has no business writing.
//!
//! The error bodies are exactly `{"error":"..."}` with a single key, and the
//! `400 clock` case is distinct from `400 bad request` on purpose: the first means
//! the sender's device clock is wrong, which is a problem the user can fix, and
//! the second means the request is malformed.

use std::sync::Arc;

use axum::{
    Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use kestrel_core::{
    b64, identity, kdf,
    wire::{self, Alg, Post},
};
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::{
    limits::Limiter,
    store::{self, StoreError},
};

/// Headers on every JSON reply.
fn json_headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );
    h
}

/// A JSON reply, with the standard headers.
fn json(status: StatusCode, body: String) -> Response {
    let mut out = (status, body).into_response();
    *out.headers_mut() = json_headers();
    out
}

/// An error reply. The body has exactly one key, and the tests assert that.
fn err(status: StatusCode, message: &str) -> Response {
    // Serialised by hand rather than with serde so the key order and the escaping
    // are fixed, and an error can never fail to serialise. Every message is a
    // literal from this file, so there is nothing to escape.
    json(status, format!(r#"{{"error":"{message}"}}"#))
}

/// The largest body the relay will read, in bytes.
///
/// An order of magnitude above the 2 KB protocol limit, so a legitimate post is
/// never refused and a hostile one is bounded.
pub const MAX_RAW_BODY: usize = 64 * 1024;

/// The largest post the protocol allows.
pub const MAX_BODY: usize = wire::MAX_BODY;

/// The origin that is always allowed to write: the page the app is bundled with.
pub const DEFAULT_WRITE_ORIGINS: &[&str] = &[
    // The host an Android WebView is given for bundled assets.
    "https://appassets.androidplatform.net",
];

/// Shared relay state.
pub struct App {
    pub store: Mutex<store::Store>,
    pub limits: Mutex<Limiter>,
    pub config: Arc<Config>,
}

/// Configuration, from the environment.
#[derive(Debug, Clone)]
pub struct Config {
    /// The origin the relay treats as its own, for the same-origin check.
    pub public_origin: String,
    /// Extra origins allowed to write, comma separated.
    pub allowed_origins: Vec<String>,
    /// Writes per channel per minute.
    pub rate_post_min: i64,
    /// Requests per address per minute, reads and writes together.
    pub rate_get_min: i64,
    /// The signing certificate fingerprint for Android's asset links.
    pub cert_fingerprint: String,
    /// Whether to read the client address from `X-Forwarded-For`. Off unless a
    /// reverse proxy is in front and configured to set it, because a client can
    /// otherwise choose its own rate-limit bucket.
    pub trust_proxy: bool,
}

impl Config {
    /// Whether an origin may write.
    ///
    /// Three cases pass: the relay's own origin, an origin on the allowlist, and
    /// *no* `Origin` header at all. The third is the native app, which does not
    /// send one. A literal `Origin: null` is never allowed, because that is what a
    /// sandboxed iframe sends and it is not a thing a real client does.
    pub fn may_write(&self, origin: Option<&str>) -> bool {
        let Some(origin) = origin else {
            return true;
        };
        if origin == "null" {
            return false;
        }
        if origin == self.public_origin {
            return true;
        }
        DEFAULT_WRITE_ORIGINS.contains(&origin)
            || self.allowed_origins.iter().any(|o| o == origin)
    }

    /// Whether a CORS preflight should be answered.
    pub fn may_preflight(&self, origin: Option<&str>) -> bool {
        self.may_write(origin)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            public_origin: "http://127.0.0.1:8788".to_string(),
            allowed_origins: Vec::new(),
            rate_post_min: (wire::MEMBER_CAP * 4 * 4) as i64,
            rate_get_min: 240,
            cert_fingerprint: String::new(),
            trust_proxy: false,
        }
    }
}

/// Build the router.
///
/// The help page is merged in here rather than in `main`, so a test drives the
/// same routing the server does. A test that used a different router would pass
/// while the deployed relay 404'd on the one page an emergency link needs.
pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/api/v2/health", get(health))
        // The v1 surface is answered with a pointer, not a redirect, so an old
        // client cannot be walked forward into a channel nobody else is on.
        .route("/api/v1/{*rest}", get(v1_retired).post(v1_retired))
        .route("/api/v2/f/{channel}", get(feed).post(post_feed).options(preflight))
        .route("/api/v2/f/{channel}/loc", post(post_loc).options(preflight))
        .route("/.well-known/assetlinks.json", get(assetlinks))
        .fallback(not_found)
        // Axum answers an unsupported method with a bare 405 and an empty body.
        // Every other refusal from this relay is a JSON object with one key, and a
        // client that has to special-case this one path is a client that will
        // eventually forget to.
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(app)
        .merge(crate::help::router())
}

/// The only endpoint that says which protocol a deployment speaks.
///
/// A relay is fronted by caches, load balancers and, in the case of a stale
/// container, an older build. A client that can read this cannot be silently
/// talking to the wrong thing.
async fn health(State(app): State<Arc<App>>) -> Response {
    let store = app.store.lock().await;
    let limits = app.limits.lock().await;
    let body = format!(
        r#"{{"ok":true,"protocol":"{}","now":{},"channels":{},"addresses":{}}}"#,
        kdf::PROTO,
        store.now(),
        limits.tracked_channels(),
        limits.tracked_addresses(),
    );
    json(StatusCode::OK, body)
}

async fn v1_retired() -> Response {
    json(
        StatusCode::GONE,
        r#"{"error":"protocol v1 retired","upgrade":"https://starlingmap.app"}"#
            .to_string(),
    )
}

async fn assetlinks(State(app): State<Arc<App>>) -> Response {
    if app.config.cert_fingerprint.is_empty() {
        return err(StatusCode::NOT_FOUND, "not found");
    }
    let body = format!(
        r#"[{{"relation":["delegate_permission/common.handle_all_urls"],"target":{{"namespace":"android_app","package_name":"{}","sha256_cert_fingerprints":["{}"]}}}}]"#,
        crate::PACKAGE_NAME,
        app.config.cert_fingerprint
    );
    let mut out = json(StatusCode::OK, body);
    out.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("max-age=3600"));
    out
}

async fn not_found() -> Response {
    err(StatusCode::NOT_FOUND, "not found")
}

async fn method_not_allowed() -> Response {
    err(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
}

async fn preflight(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let origin = header_str(&headers, header::ORIGIN);
    if !app.config.may_preflight(origin.as_deref()) {
        return err(StatusCode::FORBIDDEN, "forbidden");
    }
    let mut out = StatusCode::NO_CONTENT.into_response();
    let h = out.headers_mut();
    if let Some(o) = origin {
        h.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            o.parse().unwrap_or(HeaderValue::from_static("null")),
        );
    }
    h.insert(header::VARY, HeaderValue::from_static("origin"));
    h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST"));
    h.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type"),
    );
    h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("86400"));
    // The CORS headers set above win; the standard set fills in the rest.
    for entry in json_headers() {
        if let Some(name) = entry.0
            && !out.headers().contains_key(&name)
        {
            out.headers_mut().insert(name, entry.1);
        }
    }
    out
}

fn header_str(headers: &HeaderMap, name: header::HeaderName) -> Option<String> {
    headers.get(name).and_then(|v| v.to_str().ok()).map(String::from)
}

/// A channel id is exactly 32 lowercase hex characters. Checked before anything
/// else, so no work is done on behalf of a name that is not a channel.
fn is_channel_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[derive(Debug, Deserialize)]
struct SinceQuery {
    since: Option<String>,
}

/// The largest cursor a client can represent.
///
/// 2^53 - 1, the largest integer a JavaScript `Number` holds exactly. A JavaScript
/// client reading this relay's timestamp could not tell 2^53 from 2^53 + 1, so a
/// cursor above this is refused rather than answered with a range the client
/// cannot reason about.
pub const MAX_CURSOR: i64 = 9_007_199_254_740_991;

/// Parse the `since` cursor.
///
/// Rejected unless it is a non-negative integer a client could have meant, so a
/// caller cannot pass `"1e999"`, a negative value, or a magnitude beyond what a
/// browser can represent and have it silently become something else.
///
/// A cursor the relay does not recognise is an error rather than a default,
/// because defaulting to zero would return the whole channel's history.
fn parse_since(raw: Option<&String>) -> Option<i64> {
    // An absent parameter and an empty one mean the same thing, because
    // `?since=` is what a client that built the URL from an unset variable sends.
    match raw.map(|s| s.as_str()) {
        None | Some("") => Some(0),
        Some(s) => {
            if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            s.parse::<i64>().ok().filter(|v| (0..=MAX_CURSOR).contains(v))
        }
    }
}

/// The client address, for the per-address rate limit.
fn client_ip(
    headers: &HeaderMap,
    peer: Option<std::net::SocketAddr>,
    trust_proxy: bool,
) -> String {
    if trust_proxy
        && let Some(forwarded) =
            headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
    {
        // Only the last hop is trusted. A client can prepend anything it likes to
        // this header, so trusting the first entry would let it pick its own rate
        // limit bucket.
        if let Some(last) = forwarded.rsplit(',').next() {
            let last = last.trim();
            if !last.is_empty() {
                return last.to_string();
            }
        }
    }
    if let Some(ip) = headers.get("cf-connecting-ip").and_then(|v| v.to_str().ok()) {
        return ip.to_string();
    }
    peer.map(|a| a.ip().to_string()).unwrap_or_default()
}

/// Shared by both write paths, so a post on `/loc` and a post on the feed are
/// validated identically.
async fn accept_post(
    app: Arc<App>,
    channel: String,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Origin first: a cross-origin write is not a rate-limited request.
    let origin = header_str(&headers, header::ORIGIN);
    if !app.config.may_write(origin.as_deref()) {
        return err(StatusCode::FORBIDDEN, "forbidden");
    }

    let ip = client_ip(&headers, None, app.config.trust_proxy);
    {
        let mut limits = app.limits.lock().await;
        if limits.limited_per_ip(&ip, app.config.rate_get_min) {
            return err(StatusCode::TOO_MANY_REQUESTS, "rate limited");
        }
        if limits.limited_per_channel(&channel, app.config.rate_post_min) {
            return err(StatusCode::TOO_MANY_REQUESTS, "rate limited");
        }
    }

    // Bound the body before parsing it, so a hostile length cannot make the
    // relay allocate.
    if body.len() > MAX_RAW_BODY {
        return err(StatusCode::PAYLOAD_TOO_LARGE, "too large");
    }
    if body.len() > MAX_BODY {
        return err(StatusCode::PAYLOAD_TOO_LARGE, "too large");
    }

    let post: Post = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return err(StatusCode::BAD_REQUEST, "bad request"),
    };
    if post.validate_shape().is_err() {
        return err(StatusCode::BAD_REQUEST, "bad request");
    }

    let (Some(pk), Some(epk)) = (post.pk_bytes(), post.epk_bytes()) else {
        return err(StatusCode::BAD_REQUEST, "bad request");
    };
    // The agreement key must be a real curve point, so a member cannot be pinned
    // against 65 bytes that merely start with 0x04 and would produce a shared
    // secret of zero for every peer.
    if !identity::valid_ecdh_key(&epk) {
        return err(StatusCode::BAD_REQUEST, "bad request");
    }

    // The id must be the one those keys hash to. Without this, a post could
    // present one keypair and claim another's id, and the pin would be made on
    // the claim rather than on the key.
    if !post.keys_match_claimed_id() {
        return err(StatusCode::FORBIDDEN, "forbidden");
    }

    let now = {
        let store = app.store.lock().await;
        store.now()
    };

    if post.ts > now + wire::FUTURE_SKEW_MS {
        return err(StatusCode::BAD_REQUEST, "bad request");
    }
    // A distinct error string, so a device with a wrong clock is told that
    // rather than being left to guess from a generic rejection.
    if !wire::epoch_plausible(post.e, now) {
        return err(StatusCode::BAD_REQUEST, "clock");
    }

    // Verify the signature before storing. The relay does not need to: every
    // receiver verifies independently. But storing a forged post wastes every
    // member's bandwidth on a row none of them can open, and the verification is
    // cheap next to the write.
    let Some(sig) = b64::decode(&post.sig) else {
        return err(StatusCode::FORBIDDEN, "forbidden");
    };
    let Some(alg) = Alg::from_pk(&pk) else {
        return err(StatusCode::FORBIDDEN, "forbidden");
    };
    let signed = wire::sig_base(&channel, &post.m, post.e, post.ts, &post.n, &post.c);
    if !identity::verify_sig(alg, &pk, &sig, signed.as_bytes()) {
        return err(StatusCode::FORBIDDEN, "forbidden");
    }

    let mut store = app.store.lock().await;
    let result = store.insert(&channel, &post);
    let now = store.now();
    drop(store);

    match result {
        Ok(()) => {
            let mut out = json(StatusCode::OK, format!(r#"{{"ok":true,"now":{now}}}"#));
            // Echoed only for an origin that was allowed, which is the one case a
            // browser reads the header on. `Vary` so a shared cache does not serve
            // one origin's response to another.
            if let Some(v) = origin.as_deref().and_then(|o| o.parse::<HeaderValue>().ok()) {
                out.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
                out.headers_mut().insert(header::VARY, HeaderValue::from_static("origin"));
            }
            out
        }
        Err(e) => match e {
            StoreError::PinMismatch | StoreError::Full => {
                err(StatusCode::FORBIDDEN, "forbidden")
            }
            // Both a non-monotonic timestamp and a byte-identical replay. The
            // client cannot tell them apart, and it does not need to: either way
            // the post is not new information.
            StoreError::NotMonotonic | StoreError::Duplicate => {
                err(StatusCode::CONFLICT, "conflict")
            }
            StoreError::Internal => err(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
        },
    }
}

async fn post_loc(
    State(app): State<Arc<App>>,
    Path(channel): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_channel_id(&channel) {
        return err(StatusCode::NOT_FOUND, "not found");
    }
    accept_post(app, channel, headers, body).await
}

async fn post_feed(
    State(app): State<Arc<App>>,
    Path(channel): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !is_channel_id(&channel) {
        return err(StatusCode::NOT_FOUND, "not found");
    }
    accept_post(app, channel, headers, body).await
}

async fn feed(
    State(app): State<Arc<App>>,
    Path(channel): Path<String>,
    Query(q): Query<SinceQuery>,
    headers: HeaderMap,
) -> Response {
    if !is_channel_id(&channel) {
        return err(StatusCode::NOT_FOUND, "not found");
    }
    let Some(since) = parse_since(q.since.as_ref()) else {
        return err(StatusCode::BAD_REQUEST, "bad request");
    };
    let ip = client_ip(&headers, None, app.config.trust_proxy);
    {
        let mut limits = app.limits.lock().await;
        if limits.limited_per_ip(&ip, app.config.rate_get_min) {
            return err(StatusCode::TOO_MANY_REQUESTS, "rate limited");
        }
    }

    let mut store = app.store.lock().await;
    match store.feed(&channel, since) {
        Ok(page) => match serde_json::to_string(&page.feed) {
            Ok(body) => json(StatusCode::OK, body),
            Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
        },
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
    }
}

/// The path a circle's feed lives at. The same two paths the client builds, kept
/// here so a test can assert the two agree.
pub fn feed_path(channel: &str) -> String {
    format!("/api/v2/f/{channel}")
}

/// The path a circle's posts live at.
pub fn loc_path(channel: &str) -> String {
    format!("/api/v2/f/{channel}/loc")
}
