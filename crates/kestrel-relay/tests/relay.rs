//! The relay, driven over HTTP, the way a phone drives it.
//!
//! Every test here builds a real post with a real keypair and a real signature.
//! A test that used a hand-written envelope would pass whether or not the
//! cryptographic path worked, and the cryptographic path is the part that
//! matters.
//!
//! The cases mirror the reference relay's own test suite, because that suite is
//! the specification of the status codes and bodies Kestrel has to produce for
//! the two to be interchangeable.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use kestrel_core::{
    b64,
    identity::Identity,
    msg::{self, CircleMsg, Who},
    seal,
    wire::{self, Post},
};
use kestrel_relay::{
    http::{self, App, Config},
    limits::Limiter,
    store,
};
use tokio::sync::Mutex;
use tower::ServiceExt;

/// A relay on an in-memory store, with the clock under the test's control.
struct TestRelay {
    app: Arc<App>,
    now: std::cell::Cell<i64>,
}

impl TestRelay {
    fn new() -> Self {
        Self::with_config(Config::default())
    }

    fn with_config(config: Config) -> Self {
        let now = 1_788_282_959_714;
        Self {
            app: Arc::new(App {
                store: Mutex::new(store::open_memory(now).expect("in-memory store")),
                limits: Mutex::new(Limiter::new()),
                config: Arc::new(config),
            }),
            now: std::cell::Cell::new(now),
        }
    }

    fn now(&self) -> i64 {
        self.now.get()
    }

    /// Move the relay's clock forward. Expiry is a twenty-four hour window, so
    /// testing it any other way means waiting.
    async fn advance(&self, ms: i64) {
        let now = self.now.get() + ms;
        self.now.set(now);
        self.app.store.lock().await.set_now(now);
    }

    /// A router over *this* relay's state.
    ///
    /// Built per call so each request sees the store as it is now. The real router,
    /// not a stand-in: a test against a reimplementation of the routing would pass
    /// while the deployed relay failed.
    fn router(&self) -> axum::Router {
        http::router(self.app.clone())
    }

    async fn send(
        &self,
        req: Request<Body>,
    ) -> (StatusCode, String, axum::http::HeaderMap) {
        let res = self.router().oneshot(req).await.expect("the router answers");
        let status = res.status();
        let headers = res.headers().clone();
        let body = res.into_body().collect().await.expect("a body").to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned(), headers)
    }

    fn post_req(&self, channel: &str, body: &Post) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(http::loc_path(channel))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap()
    }

    fn get_req(&self, path: &str) -> Request<Body> {
        Request::builder().method("GET").uri(path).body(Body::empty()).unwrap()
    }
}

/// Build a real, signed post from a real identity.
fn a_post(identity: &Identity, channel: &str, ts: i64, name: &str) -> Post {
    let body =
        CircleMsg::loc(ts, Who::plain(name, "", 210), msg::Fix::new(44.98, -93.27, 5.0));
    let json = serde_json::to_string(&body).unwrap();
    // One fixed generation seed, so every post in this suite is sealed under a key
    // a real member would derive.
    let ck = kestrel_core::kdf::chain0(&[42u8; 32]);
    let key = seal::ContentKey::new(kestrel_core::kdf::msg_key(&ck, identity.member_id()));
    seal::build_post(identity, channel, &key, wire::epoch_at(ts), ts, &json)
        .expect("a post builds")
}

const CHANNEL: &str = "f1c695a80bae6baf8bb34828bc177bc9";

// ---------------------------------------------------------------- routing

#[tokio::test]
async fn health_reports_the_protocol() {
    let r = TestRelay::new();
    let (status, body, headers) = r.send(r.get_req("/api/v2/health")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#""ok":true"#), "{body}");
    assert!(
        body.contains(r#""protocol":"starling/v2""#),
        "a client must be able to tell which protocol this is: {body}"
    );
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/json; charset=utf-8"
    );
    assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(
        headers.get("x-content-type-options").unwrap(),
        "nosniff",
        "a JSON reply must not be sniffed into something else"
    );
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
}

#[tokio::test]
async fn unknown_paths_are_not_found() {
    let r = TestRelay::new();
    for path in [
        "/",
        "/api",
        "/api/v2",
        "/api/v2/nope",
        "/api/v2/f",
        "/api/v2/f/",
        "/api/v3/health",
        "/api/v2/health/",
    ] {
        let (status, body, _) = r.send(r.get_req(path)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path} should be 404");
        assert_eq!(body, r#"{"error":"not found"}"#, "{path} body");
    }
}

#[tokio::test]
async fn a_channel_id_must_be_exactly_thirty_two_lowercase_hex() {
    let r = TestRelay::new();
    for bad in [
        "f1c695a80bae6baf8bb34828bc177bc",   // 31
        "f1c695a80bae6baf8bb34828bc177bc99", // 33
        "F1C695A80BBAE6BAF8BB34828BC177BC9", // uppercase
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",  // not hex
        "f1c695a80bae6baf8bb34828bc177bc-",  // not hex
    ] {
        let (status, body, _) = r.send(r.get_req(&http::feed_path(bad))).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{bad} should be 404");
        assert_eq!(body, r#"{"error":"not found"}"#);
    }
}

#[tokio::test]
async fn an_unknown_but_valid_channel_is_an_empty_feed() {
    // A channel id is unguessable but not secret, and the relay must not confirm
    // or deny which ones exist. An empty feed is the same answer either way.
    let r = TestRelay::new();
    let (status, body, _) = r.send(r.get_req(&http::feed_path(CHANNEL))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#""members":[]"#), "{body}");
}

#[tokio::test]
async fn the_wrong_method_is_refused() {
    let r = TestRelay::new();
    let (status, body, _) = r
        .send(
            Request::builder()
                .method("DELETE")
                .uri(http::feed_path(CHANNEL))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body, r#"{"error":"method not allowed"}"#);
}

#[tokio::test]
async fn protocol_v1_is_gone_with_a_pointer() {
    // Not a redirect: an old client must not be walked forward into a channel
    // nobody else is on, because v1 and v2 derive different channel ids from the
    // same circle secret.
    let r = TestRelay::new();
    for method in ["GET", "POST"] {
        let (status, body, _) = r
            .send(
                Request::builder()
                    .method(method)
                    .uri("/api/v1/f/abc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::GONE, "{method} /api/v1");
        assert!(body.contains("protocol v1 retired"), "{body}");
        assert!(body.contains("upgrade"), "{body}");
    }
}

#[tokio::test]
async fn health_refuses_methods_other_than_get() {
    let r = TestRelay::new();
    let (status, _, _) = r
        .send(
            Request::builder()
                .method("POST")
                .uri("/api/v2/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

// ---------------------------------------------------------------- writes

#[tokio::test]
async fn a_valid_post_is_stored_and_served_back() {
    let r = TestRelay::new();
    let alice = Identity::generate();
    let post = a_post(&alice, CHANNEL, r.now(), "Ana");
    let (status, body, _) = r.send(r.post_req(CHANNEL, &post)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains(r#""ok":true"#), "{body}");
    assert!(body.contains(&format!(r#""now":{}"#, r.now())), "{body}");

    let (_, feed, _) = r.send(r.get_req(&http::feed_path(CHANNEL))).await;
    let parsed: wire::Feed = serde_json::from_str(&feed).expect("the feed parses");
    assert_eq!(parsed.members.len(), 1);
    let m = &parsed.members[0];
    assert_eq!(m.m, alice.member_id());
    assert_eq!(m.alg, "ed25519");
    assert_eq!(m.points.len(), 1);
    assert_eq!(m.points[0].c, post.c);
    assert_eq!(m.points[0].srv, r.now());
}

#[tokio::test]
async fn a_post_on_either_path_is_accepted_identically() {
    // The client uses one, but a relay that treated them differently would be a
    // surprise for anyone testing against it by hand.
    let r = TestRelay::new();
    let a = Identity::generate();
    let (status, _, _) =
        r.send(r.post_req(CHANNEL, &a_post(&a, CHANNEL, r.now(), "A"))).await;
    assert_eq!(status, StatusCode::OK);
    let b = Identity::generate();
    let (status, body, _) =
        r.send(r.post_req(CHANNEL, &a_post(&b, CHANNEL, r.now() + 1, "B"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_malformed_body_is_a_bad_request() {
    let r = TestRelay::new();
    for body in [
        "not json",
        "{}",
        "[]",
        r#"{"m":"x"}"#,
        r#"{"m":"dc73c74c3f57c6ff0c2d9016c333507f","alg":"ed25519","pk":"!!","epk":"!!","e":1,"ts":1,"n":"a","c":"a","sig":"a"}"#,
    ] {
        let req = Request::builder()
            .method("POST")
            .uri(http::loc_path(CHANNEL))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, text, _) = r.send(req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body} gave {text}");
        assert_eq!(text, r#"{"error":"bad request"}"#);
    }
}

#[tokio::test]
async fn an_oversized_body_is_refused() {
    let r = TestRelay::new();
    let big = "x".repeat(wire::MAX_BODY + 1);
    let req = Request::builder()
        .method("POST")
        .uri(http::loc_path(CHANNEL))
        .body(Body::from(big))
        .unwrap();
    let (status, text, _) = r.send(req).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(text, r#"{"error":"too large"}"#);
}

#[tokio::test]
async fn a_post_whose_keys_do_not_hash_to_its_id_is_forbidden() {
    // Otherwise a client could be admitted under an identity it does not hold,
    // and the pin would be made on the claim rather than on the key.
    let r = TestRelay::new();
    let alice = Identity::generate();
    let mallory = Identity::generate();
    let mut post = a_post(&alice, CHANNEL, r.now(), "Ana");
    post.m = mallory.member_id().to_string();

    let (status, text, _) = r.send(r.post_req(CHANNEL, &post)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(text, r#"{"error":"forbidden"}"#);
}

#[tokio::test]
async fn a_forged_signature_is_forbidden() {
    // The relay is not trusted to verify, and every receiver verifies anyway. But
    // storing a forged post wastes every member's bandwidth on a row none of them
    // can open.
    let r = TestRelay::new();
    let alice = Identity::generate();
    let mut post = a_post(&alice, CHANNEL, r.now(), "Ana");
    post.c = b64::encode(&[0u8; 528]);

    let (status, text, _) = r.send(r.post_req(CHANNEL, &post)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(text, r#"{"error":"forbidden"}"#);
}

#[tokio::test]
async fn a_post_signed_for_another_channel_is_forbidden() {
    // The signature covers the channel, so a post cannot be lifted from one circle
    // into another even though the relay would happily store the bytes.
    let r = TestRelay::new();
    let alice = Identity::generate();
    let post = a_post(&alice, "00000000000000000000000000000000", r.now(), "Ana");

    let (status, text, _) = r.send(r.post_req(CHANNEL, &post)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(text, r#"{"error":"forbidden"}"#);
}

#[tokio::test]
async fn a_timestamp_too_far_in_the_future_is_a_bad_request() {
    let r = TestRelay::new();
    let alice = Identity::generate();
    let post = a_post(&alice, CHANNEL, r.now() + wire::FUTURE_SKEW_MS + 1, "Ana");
    let (status, text, _) = r.send(r.post_req(CHANNEL, &post)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(text, r#"{"error":"bad request"}"#);
}

#[tokio::test]
async fn an_implausible_epoch_says_so() {
    // A distinct string, so a device with a wrong clock is told that rather than
    // left guessing from a generic rejection.
    let r = TestRelay::new();
    let alice = Identity::generate();
    let mut post = a_post(&alice, CHANNEL, r.now(), "Ana");
    post.e = wire::epoch_at(r.now()) + 50;
    // Re-signed, so what refuses it is the epoch check and not the signature.
    let post = resign(&alice, &post, CHANNEL);
    let (status, text, _) = r.send(r.post_req(CHANNEL, &post)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(text, r#"{"error":"clock"}"#);
}

#[tokio::test]
async fn a_tampered_timestamp_is_forbidden_by_the_signature() {
    let r = TestRelay::new();
    let alice = Identity::generate();
    let mut post = a_post(&alice, CHANNEL, r.now(), "Ana");
    post.ts += 1;
    let (status, _, _) = r.send(r.post_req(CHANNEL, &post)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Re-sign a post after changing a header field, so a test can isolate one check.
fn resign(identity: &Identity, post: &Post, channel: &str) -> Post {
    let mut post = post.clone();
    post.sig = identity
        .sign_text(&wire::sig_base(channel, &post.m, post.e, post.ts, &post.n, &post.c));
    post.clone()
}

// ---------------------------------------------------------------- pinning

#[tokio::test]
async fn a_member_is_pinned_on_first_write_and_cannot_change_keys() {
    let r = TestRelay::new();
    let alice = Identity::generate();
    let bob = Identity::generate();

    let (status, _, _) =
        r.send(r.post_req(CHANNEL, &a_post(&alice, CHANNEL, r.now(), "A"))).await;
    assert_eq!(status, StatusCode::OK);

    // A second post presenting a different keypair under the same member id.
    // The id commits to both keys, so this is the one thing a client cannot do.
    let mut forged = a_post(&bob, CHANNEL, r.now() + 1, "A");
    forged.m = alice.member_id().to_string();
    let (status, text, _) = r.send(r.post_req(CHANNEL, &forged)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(text, r#"{"error":"forbidden"}"#);

    // The pin survived, and the feed still shows the original keys.
    let (_, feed, _) = r.send(r.get_req(&http::feed_path(CHANNEL))).await;
    let parsed: wire::Feed = serde_json::from_str(&feed).unwrap();
    assert_eq!(parsed.members[0].pk, alice.pk_b64());
}

#[tokio::test]
async fn a_tampered_algorithm_field_is_refused() {
    // `alg` is not covered by the member id, so a relay could flip it. The pin
    // compares it anyway, and every receiver ignores it in favour of the key
    // length. Two defences; this is the first.
    let r = TestRelay::new();
    let alice = Identity::generate();
    r.send(r.post_req(CHANNEL, &a_post(&alice, CHANNEL, r.now(), "A"))).await;

    let mut post = a_post(&alice, CHANNEL, r.now() + 1, "A");
    post.alg = "p256".to_string();
    let (status, _, _) = r.send(r.post_req(CHANNEL, &post)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_timestamp_may_only_move_forward() {
    let r = TestRelay::new();
    let alice = Identity::generate();
    r.send(r.post_req(CHANNEL, &a_post(&alice, CHANNEL, r.now(), "A"))).await;

    // Older.
    let (status, text, _) =
        r.send(r.post_req(CHANNEL, &a_post(&alice, CHANNEL, r.now() - 1, "A"))).await;
    assert_eq!(status, StatusCode::CONFLICT, "{text}");
    assert_eq!(text, r#"{"error":"conflict"}"#);

    // Identical. A whole-body replay collides on the primary key and lands in the
    // same place, which is the point: the client cannot tell the two apart and
    // does not need to.
    let first = a_post(&alice, CHANNEL, r.now(), "A");
    let (status, text, _) = r.send(r.post_req(CHANNEL, &first)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{text}");

    // Newer is fine.
    let (status, _, _) =
        r.send(r.post_req(CHANNEL, &a_post(&alice, CHANNEL, r.now() + 1, "A"))).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_channel_holds_at_most_sixteen_members() {
    let r = TestRelay::new();
    for i in 0..wire::MEMBER_CAP {
        let id = Identity::generate();
        let (status, body, _) = r
            .send(r.post_req(CHANNEL, &a_post(&id, CHANNEL, r.now() + i as i64, "M")))
            .await;
        assert_eq!(status, StatusCode::OK, "member {i}: {body}");
    }
    let extra = Identity::generate();
    let (status, text, _) =
        r.send(r.post_req(CHANNEL, &a_post(&extra, CHANNEL, r.now() + 100, "M"))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(text, r#"{"error":"forbidden"}"#);
}

#[tokio::test]
async fn a_refused_member_writes_no_point_either() {
    // The cap is enforced inside the write, so a request that would exceed it
    // leaves nothing behind rather than a point with no member row.
    let r = TestRelay::new();
    for i in 0..wire::MEMBER_CAP {
        let id = Identity::generate();
        r.send(r.post_req(CHANNEL, &a_post(&id, CHANNEL, r.now() + i as i64, "M"))).await;
    }
    let extra = Identity::generate();
    let before = r.app.store.lock().await.count_points(CHANNEL).unwrap();
    r.send(r.post_req(CHANNEL, &a_post(&extra, CHANNEL, r.now() + 100, "M"))).await;
    let after = r.app.store.lock().await.count_points(CHANNEL).unwrap();
    assert_eq!(before, after, "a refused post wrote a point anyway");
}

// ---------------------------------------------------------------- the feed

#[tokio::test]
async fn the_cursor_filters_by_the_relays_own_receive_time() {
    // Filtering by the sender's timestamp would let one device with a skewed
    // clock hide another's points from everyone.
    let r = TestRelay::new();
    let a = Identity::generate();
    let b = Identity::generate();

    // The first point's receive time is remembered, because the relay's clock
    // moves on and the cursor is compared against receive time.
    let first_srv = r.now();
    r.send(r.post_req(CHANNEL, &a_post(&a, CHANNEL, first_srv, "A"))).await;
    r.advance(1_000).await;
    let second_srv = r.now();
    r.send(r.post_req(CHANNEL, &a_post(&a, CHANNEL, second_srv + 2, "A"))).await;

    // From zero: both.
    let (_, feed, _) =
        r.send(r.get_req(&format!("{}?since=0", http::feed_path(CHANNEL)))).await;
    let parsed: wire::Feed = serde_json::from_str(&feed).unwrap();
    assert_eq!(parsed.members[0].points.len(), 2);

    // From the first point's own receive time: both, because the comparison is
    // inclusive. It has to be, because `srv` is not unique per insert and an
    // exclusive comparison would drop points sharing a timestamp.
    let (_, feed, _) =
        r.send(r.get_req(&format!("{}?since={first_srv}", http::feed_path(CHANNEL)))).await;
    let parsed: wire::Feed = serde_json::from_str(&feed).unwrap();
    assert_eq!(parsed.members[0].points.len(), 2, "the cursor is inclusive");

    // One millisecond later: the second only.
    let (_, feed, _) = r
        .send(r.get_req(&format!("{}?since={}", http::feed_path(CHANNEL), first_srv + 1)))
        .await;
    let parsed: wire::Feed = serde_json::from_str(&feed).unwrap();
    assert_eq!(parsed.members[0].points.len(), 1);
    let _ = b;

    // Members are not filtered by the cursor: a device needs the roster even for
    // a member with nothing new.
    assert_eq!(parsed.members.len(), 1);
}

#[tokio::test]
async fn a_bad_cursor_is_refused_rather_than_defaulted() {
    // Defaulting to zero would return the whole channel's history to a client
    // that asked for something else, which for a private app is a disclosure.
    let r = TestRelay::new();
    for bad in [
        "abc",
        "-1",
        "1.5",
        "1e999",
        // One past the largest integer a browser represents exactly. A client that
        // could not tell this from its predecessor must not be answered with a
        // range it cannot reason about.
        "9007199254740992",
    ] {
        let (status, text, _) =
            r.send(r.get_req(&format!("{}?since={bad}", http::feed_path(CHANNEL)))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "since={bad} gave {text}");
        assert_eq!(text, r#"{"error":"bad request"}"#);
    }
    // Zero, an empty value and an absent parameter all mean "everything". A client
    // that built the URL from an unset variable sends `?since=`, and refusing that
    // would break a client doing nothing unusual.
    for good in ["0", ""] {
        let (status, _, _) =
            r.send(r.get_req(&format!("{}?since={good}", http::feed_path(CHANNEL)))).await;
        assert_eq!(status, StatusCode::OK, "since={good} should be accepted");
    }
    let (status, _, _) = r.send(r.get_req(&http::feed_path(CHANNEL))).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_member_with_no_points_still_appears_in_the_feed() {
    // A member admitted by a re-key has not posted yet, and a device still needs
    // to know they exist.
    let r = TestRelay::new();
    let a = Identity::generate();
    r.send(r.post_req(CHANNEL, &a_post(&a, CHANNEL, r.now(), "A"))).await;
    // Pin a second member, then remove only their point. A member admitted by a
    // re-key is visible in the roster before they have posted a position, and the
    // feed has to return their keys even with nothing to show.
    let newcomer = Identity::generate();
    r.app
        .store
        .lock()
        .await
        .insert(CHANNEL, &a_post(&newcomer, CHANNEL, r.now() + 1, "B"))
        .expect("the second member is pinned");
    r.app
        .store
        .lock()
        .await
        .delete_points_for(CHANNEL, newcomer.member_id())
        .expect("their point is removed");

    let (_, feed, _) = r.send(r.get_req(&http::feed_path(CHANNEL))).await;
    let parsed: wire::Feed = serde_json::from_str(&feed).unwrap();
    assert_eq!(parsed.members.len(), 2);
    let empty: Vec<_> = parsed.members.iter().filter(|m| m.points.is_empty()).collect();
    assert_eq!(empty.len(), 1, "one member has no points yet");
}

#[tokio::test]
async fn the_feed_reports_the_relays_clock() {
    // So a client can correct its own drift without a separate endpoint.
    let r = TestRelay::new();
    let (status, body, _) = r.send(r.get_req(&http::feed_path(CHANNEL))).await;
    assert_eq!(status, StatusCode::OK);
    let parsed: wire::Feed = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed.now, r.now());
}

// ---------------------------------------------------------------- expiry

#[tokio::test]
async fn everything_expires_after_a_day() {
    // Every row, on every read and write. There is no cron: an idle channel would
    // otherwise keep a person's positions for ever.
    let r = TestRelay::new();
    let a = Identity::generate();
    r.send(r.post_req(CHANNEL, &a_post(&a, CHANNEL, r.now(), "A"))).await;
    assert_eq!(r.app.store.lock().await.count_points(CHANNEL).unwrap(), 1);

    // Almost a day later, still there.
    r.advance(wire::TTL_MS - 1_000).await;
    r.send(r.get_req(&http::feed_path(CHANNEL))).await;
    assert_eq!(r.app.store.lock().await.count_points(CHANNEL).unwrap(), 1);

    // Past it, gone.
    r.advance(2_000).await;
    r.send(r.get_req(&http::feed_path(CHANNEL))).await;
    let store = r.app.store.lock().await;
    assert_eq!(store.count_points(CHANNEL).unwrap(), 0, "points survived the TTL");
    assert_eq!(
        store.count_channel_members(CHANNEL).unwrap(),
        0,
        "members survived the TTL"
    );
}

#[tokio::test]
async fn a_write_also_sweeps() {
    // The read path is not the only one that cleans up: a channel nobody ever
    // reads must still expire.
    let r = TestRelay::new();
    let a = Identity::generate();
    r.send(r.post_req(CHANNEL, &a_post(&a, CHANNEL, r.now(), "A"))).await;
    r.advance(wire::TTL_MS + 1_000).await;
    let b = Identity::generate();
    r.send(r.post_req(CHANNEL, &a_post(&b, CHANNEL, r.now() + 2, "B"))).await;
    let store = r.app.store.lock().await;
    assert_eq!(store.count_points(CHANNEL).unwrap(), 1, "only the new point");
    assert_eq!(store.count_channel_members(CHANNEL).unwrap(), 1);
}

#[tokio::test]
async fn a_trail_is_trimmed_to_two_hundred_and_forty_points() {
    // Two hundred and eighty posts in a minute is far more than any circle does,
    // so the limits are lifted here. They have their own tests, and this one is
    // about what the store keeps rather than about what it admits.
    let r = TestRelay::with_config(Config {
        rate_post_min: 10_000,
        rate_get_min: 10_000,
        ..Config::default()
    });
    let a = Identity::generate();
    // More points than the cap, spaced so each is a distinct timestamp.
    for i in 0..(wire::TRAIL_CAP as i64 + 40) {
        let ts = r.now() + i * 1_000;
        let (status, body, _) =
            r.send(r.post_req(CHANNEL, &a_post(&a, CHANNEL, ts, "A"))).await;
        assert_eq!(status, StatusCode::OK, "{i}: {body}");
    }
    let count = r.app.store.lock().await.count_points(CHANNEL).unwrap();
    // The cap plus at most one trim interval: the trim runs one write in sixteen,
    // so between two trims the trail can sit above the cap. A hard cap of exactly
    // 240 would mean trimming on every write, which is a second write per post on
    // a phone's battery. Sixteen points of slack is the price and it is bounded.
    let ceiling = wire::TRAIL_CAP as i64 + kestrel_relay::store::TRAIL_TRIM_EVERY - 1;
    assert!(count <= ceiling, "the trail grew to {count}, past the bound of {ceiling}");
    // And the newest are the ones kept.
    let (_, feed, _) = r.send(r.get_req(&http::feed_path(CHANNEL))).await;
    let parsed: wire::Feed = serde_json::from_str(&feed).unwrap();
    let last = parsed.members[0].points.last().unwrap();
    assert_eq!(last.ts, r.now() + (wire::TRAIL_CAP as i64 + 39) * 1_000);
}

// ---------------------------------------------------------------- origins

#[tokio::test]
async fn a_write_from_a_disallowed_origin_is_forbidden() {
    let r = TestRelay::new();
    let a = Identity::generate();
    let post = a_post(&a, CHANNEL, r.now(), "A");
    let req = Request::builder()
        .method("POST")
        .uri(http::loc_path(CHANNEL))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, "https://evil.example")
        .body(Body::from(serde_json::to_vec(&post).unwrap()))
        .unwrap();
    let (status, text, _) = r.send(req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(text, r#"{"error":"forbidden"}"#);
}

#[tokio::test]
async fn the_null_origin_is_never_allowed() {
    // `Origin: null` is what a sandboxed iframe sends. Treating it as allowed
    // would let any page on the internet write to any circle.
    let r = TestRelay::new();
    let a = Identity::generate();
    let post = a_post(&a, CHANNEL, r.now(), "A");
    let req = Request::builder()
        .method("POST")
        .uri(http::loc_path(CHANNEL))
        .header(header::ORIGIN, "null")
        .body(Body::from(serde_json::to_vec(&post).unwrap()))
        .unwrap();
    let (status, _, _) = r.send(req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn no_origin_header_at_all_is_allowed() {
    // The native app does not send one. Refusing it would mean the app could not
    // talk to a self-hosted relay at all.
    let r = TestRelay::new();
    let a = Identity::generate();
    let (status, body, _) =
        r.send(r.post_req(CHANNEL, &a_post(&a, CHANNEL, r.now(), "A"))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn a_preflight_is_answered_only_for_an_allowed_origin() {
    let r = TestRelay::new();
    let allowed = Request::builder()
        .method("OPTIONS")
        .uri(http::feed_path(CHANNEL))
        .header(header::ORIGIN, "https://appassets.androidplatform.net")
        .body(Body::empty())
        .unwrap();
    let (status, _, headers) = r.send(allowed).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        headers.get("access-control-allow-origin").unwrap(),
        "https://appassets.androidplatform.net"
    );
    assert_eq!(headers.get("access-control-allow-methods").unwrap(), "GET, POST");
    assert_eq!(headers.get("vary").unwrap(), "origin");

    let denied = Request::builder()
        .method("OPTIONS")
        .uri(http::feed_path(CHANNEL))
        .header(header::ORIGIN, "https://evil.example")
        .body(Body::empty())
        .unwrap();
    let (status, text, _) = r.send(denied).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(text, r#"{"error":"forbidden"}"#);
}

#[tokio::test]
async fn an_extra_allowed_origin_is_honoured() {
    let r = TestRelay::with_config(Config {
        allowed_origins: vec!["https://my.front.example".to_string()],
        ..Config::default()
    });
    let a = Identity::generate();
    let post = a_post(&a, CHANNEL, r.now(), "A");
    let req = Request::builder()
        .method("POST")
        .uri(http::loc_path(CHANNEL))
        .header(header::ORIGIN, "https://my.front.example")
        .body(Body::from(serde_json::to_vec(&post).unwrap()))
        .unwrap();
    let (status, body, _) = r.send(req).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

// ---------------------------------------------------------------- rate limits

#[tokio::test]
async fn too_many_writes_to_one_channel_are_refused() {
    let r = TestRelay::with_config(Config { rate_post_min: 3, ..Config::default() });
    let a = Identity::generate();

    let mut accepted = 0;
    for i in 0..5 {
        let (status, _, _) =
            r.send(r.post_req(CHANNEL, &a_post(&a, CHANNEL, r.now() + i, "A"))).await;
        if status == StatusCode::OK {
            accepted += 1;
        } else {
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        }
    }
    assert!(accepted <= 3, "the limit was not applied, accepted {accepted}");
}

#[tokio::test]
async fn too_many_requests_from_one_address_are_refused() {
    // The address limit is shared by reads and writes, and the write limit here is
    // high, so only the address limit can be the one firing.
    let r = TestRelay::with_config(Config {
        rate_post_min: 10_000,
        rate_get_min: 4,
        ..Config::default()
    });

    let mut limited = 0;
    for _ in 0..8 {
        let (status, _, _) = r.send(r.get_req(&http::feed_path(CHANNEL))).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            limited += 1;
        }
    }
    assert!(limited > 0, "the per-address limit never fired");
}

#[tokio::test]
async fn a_spray_of_channel_ids_does_not_escape_the_address_limit() {
    // The reason the two limits live in separate maps: a client naming a fresh
    // channel per request never meets the per-channel cap, so only the per-address
    // one stands in its way, and it must not be evictable.
    let r = TestRelay::with_config(Config {
        rate_post_min: 10_000,
        rate_get_min: 3,
        ..Config::default()
    });

    for _ in 0..3 {
        r.send(r.get_req(&http::feed_path(CHANNEL))).await;
    }
    let mut limited = 0;
    for i in 0..20 {
        let channel = format!("{i:032x}");
        let (status, _, _) = r.send(r.get_req(&http::feed_path(&channel))).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            limited += 1;
        }
    }
    assert_eq!(limited, 20, "every request after the first three was over the limit");
}

#[tokio::test]
async fn the_rate_limit_runs_before_the_body_is_read() {
    // Any 32 hex characters name a channel, so a client that picks a fresh one
    // per request would otherwise make the relay do work for every one of them.
    let r = TestRelay::with_config(Config { rate_post_min: 1, ..Config::default() });
    let a = Identity::generate();

    r.send(r.post_req(CHANNEL, &a_post(&a, CHANNEL, r.now(), "A"))).await;
    // The second one is over the limit, and is refused even though its body is
    // nonsense that would otherwise be a bad request.
    let req = Request::builder()
        .method("POST")
        .uri(http::loc_path(CHANNEL))
        .body(Body::from("not json at all"))
        .unwrap();
    let (status, text, _) = r.send(req).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(text, r#"{"error":"rate limited"}"#);
}

// ---------------------------------------------------------------- help page

#[tokio::test]
async fn the_help_page_is_served_with_a_strict_policy() {
    let r = TestRelay::new();
    let (status, body, headers) = r.send(r.get_req("/help")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("/help/help.js"), "the page loads the viewer, got: {body}");

    let policy = headers
        .get("content-security-policy")
        .expect("a content policy is mandatory on the one page that handles a secret")
        .to_str()
        .unwrap();
    assert!(policy.contains("default-src 'none'"), "{policy}");
    assert!(policy.contains("frame-ancestors 'none'"), "{policy}");
    assert!(policy.contains("img-src"), "map tiles are allowed: {policy}");
    assert!(
        !policy.contains("unsafe-inline"),
        "an inline script would defeat the point of the policy: {policy}"
    );
    assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
}

#[tokio::test]
async fn the_help_page_assets_are_served() {
    let r = TestRelay::new();
    for (path, kind) in [("/help/help.js", "javascript"), ("/help/help.css", "text/css")] {
        let (status, body, headers) = r.send(r.get_req(path)).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(!body.is_empty(), "{path} is empty");
        assert!(
            headers.get(header::CONTENT_TYPE).unwrap().to_str().unwrap().contains(kind),
            "{path} has the wrong content type"
        );
    }
}

// ---------------------------------------------------------------- privacy

#[tokio::test]
async fn the_relay_database_contains_no_name_and_no_coordinate() {
    // The claim the whole design rests on. A name and a coordinate are inside the
    // ciphertext, so neither may appear anywhere in the file: not in a column, not
    // in an index, not in a free-text field.
    let r = TestRelay::new();
    // A name containing a character that is not in the base64url or hex
    // alphabets. A short name like "Ana" can appear by chance inside a run of
    // base64, and a test that trips over that teaches the wrong lesson: it is a
    // false positive about the relay rather than a real leak.
    const SECRET_NAME: &str = "Ana Ångström";
    const OTHER_NAME: &str = "Bo Ñuñez";
    let a = Identity::generate();
    let b = Identity::generate();
    r.send(r.post_req(CHANNEL, &a_post(&a, CHANNEL, r.now(), SECRET_NAME))).await;
    r.send(r.post_req(CHANNEL, &a_post(&b, CHANNEL, r.now() + 1, OTHER_NAME))).await;

    // Dump every value in every table.
    let conn = {
        let store = r.app.store.lock().await;
        store.dump_everything()
    };
    assert!(!conn.contains(SECRET_NAME), "a member name reached the database");
    assert!(!conn.contains(OTHER_NAME), "a member name reached the database");
    assert!(!conn.contains("44.98"), "a latitude reached the database");
    assert!(!conn.contains("-93.27"), "a longitude reached the database");
    // But the things the relay legitimately holds are there.
    assert!(conn.contains(a.member_id()), "the member id should be there");
    assert!(conn.contains(CHANNEL), "the channel id should be there");
}
