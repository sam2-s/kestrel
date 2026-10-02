//! Talking to a relay.
//!
//! Deliberately small: two operations, one cursor, one retry policy. Everything
//! about *what* to send lives in `kestrel-core::session`, and everything about
//! *whether to trust* what comes back lives there too. This crate moves bytes.
//!
//! Three decisions worth stating:
//!
//! * **TLS roots are bundled, not taken from the system.** Android has no
//!   certificate store a Rust TLS stack can read without a Java bridge, and a
//!   bridge is a dependency and a failure mode. A bundled set of roots means a
//!   self-hosted relay with a Let's Encrypt certificate works on day one.
//! * **The relay's clock is learned from every response.** A device whose clock
//!   is wrong by a day would otherwise be refused every post with a `clock`
//!   error it could not diagnose, and the fix is one field away.
//! * **Backoff is jittered.** Without jitter, a relay that goes down has every
//!   device in every circle retrying on the same second, and comes back to a
//!   thundering herd it could have served.

use std::{collections::VecDeque, time::Duration};

use kestrel_core::wire::{Feed, Post, RelayError};
use serde::Deserialize;

/// A relay to talk to.
pub struct Relay {
    /// The relay's origin, without a trailing slash.
    base: String,
    client: reqwest::Client,
    /// How the last request went, for the UI.
    pub last_error: Option<RelayError>,
    /// The relay's clock as last reported, for correcting a device with a bad one.
    pub server_now: Option<i64>,
}

/// How long to wait before retrying, and how far to back off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// The longest wait between attempts.
    pub ceiling: Duration,
    /// Consecutive failures.
    pub failures: u32,
}

impl Default for Backoff {
    fn default() -> Self {
        Self { ceiling: Duration::from_secs(120), failures: 0 }
    }
}

impl Backoff {
    /// The wait before the next attempt, and the new failure count.
    ///
    /// Exponential from ten seconds, capped, with a random factor. The randomness
    /// is not decoration: without it every device that lost the relay at the same
    /// moment comes back at the same moment.
    pub fn next_delay(&mut self) -> Duration {
        let base = 10u64.saturating_mul(1u64 << self.failures.min(4));
        let capped = base.min(self.ceiling.as_secs());
        // A full-width jitter around the nominal delay.
        let spread = capped / 2;
        let offset = jitter(capped.saturating_sub(spread), spread);
        self.failures = self.failures.saturating_add(1);
        Duration::from_millis(offset)
    }

    /// Back to the start, after a request succeeds.
    pub fn reset(&mut self) {
        self.failures = 0;
    }
}

/// A value in `[low, high]`, using the system entropy source.
///
/// A counter would be cheaper, but a counter makes the backoff predictable, and a
/// predictable backoff is one an attacker can line up. If the entropy source is
/// unavailable the result is the low end: a shorter-than-nominal wait is a busy
/// loop, not a synchronised one, and a synchronised retry is the thing this
/// exists to prevent.
fn jitter(low: u64, span: u64) -> u64 {
    if span == 0 {
        return low;
    }
    match kestrel_core::seal::random_bytes_8() {
        Some(b) => low + u64::from_le_bytes(b) % (span + 1),
        None => low,
    }
}

/// A post waiting to go out.
///
/// A position is not dropped because the network was down. It is replaced by the
/// next one: a queue of positions is a history the circle did not ask for, and a
/// stale one is worse than a gap. Anything that is *not* a position — a re-key, a
/// goodbye, a join request — is kept until it has been sent, because those are
/// messages with a meaning that a later position cannot carry.
#[derive(Debug, Clone)]
pub struct Queued {
    pub post: Post,
    /// Whether a newer post of the same kind makes this one unnecessary.
    pub coalescible: bool,
    pub label: String,
}

#[derive(Debug, Default)]
pub struct Outbox {
    queue: VecDeque<Queued>,
    /// How many posts have been sent, for diagnostics.
    pub sent: u64,
}

impl Outbox {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a post.
    ///
    /// A coalescible post replaces any earlier coalescible one, so a device that
    /// is offline for a minute sends one position when it comes back rather than
    /// sixty.
    pub fn push(&mut self, post: Post, label: impl Into<String>, coalescible: bool) {
        let label = label.into();
        if coalescible {
            self.queue.retain(|q| !(q.coalescible && q.label == label));
        }
        self.queue.push_back(Queued { post, coalescible, label });
    }

    /// The next post to try, without removing it.
    pub fn peek(&self) -> Option<&Post> {
        self.queue.front().map(|q| &q.post)
    }

    /// Remove the post at the front, after it has been sent.
    pub fn pop(&mut self) -> Option<Queued> {
        self.sent = self.sent.saturating_add(1);
        self.queue.pop_front()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Remove everything. For a panic wipe.
    pub fn clear(&mut self) {
        self.queue.clear();
    }
}

/// What a poll returned.
pub enum Polled {
    /// A feed, with the new cursor.
    Feed { feed: Feed, cursor: i64 },
    /// The relay answered `410 Gone`: it speaks a protocol this build does not.
    Retired,
}

/// A response that needs interpreting rather than parsing.
#[derive(Deserialize)]
struct ApiError {
    error: String,
}

impl Relay {
    /// Point at a relay.
    ///
    /// A trailing slash is stripped, because a path built by appending to a base
    /// with a trailing slash produces a double slash that some proxies answer
    /// with a redirect.
    pub fn new(base: &str) -> Result<Self, String> {
        let trimmed = base.trim().trim_end_matches('/');
        if trimmed.is_empty() {
            return Err("a relay needs an address".to_string());
        }
        if !(trimmed.starts_with("https://") || trimmed.starts_with("http://")) {
            return Err(format!(
                "{trimmed} is not an address; it needs to start with https:// or, for a \
                 relay on your own network, http://"
            ));
        }
        if trimmed.starts_with("http://") && !is_local(trimmed) {
            return Err(format!(
                "{trimmed} is plain http. Positions and keys would cross the network in \
                 the clear, so a relay has to be https unless it is on this machine or \
                 your own network."
            ));
        }
        Ok(Self {
            base: trimmed.to_string(),
            client: reqwest::Client::builder()
                .user_agent(concat!("kestrel/", env!("CARGO_PKG_VERSION")))
                // The relay answers with `cache-control: no-store` on everything;
                // this is belt and braces for a proxy in between.
                .timeout(Duration::from_secs(20))
                .build()
                .map_err(|e| format!("could not open a connection: {e}"))?,
            last_error: None,
            server_now: None,
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    /// Where a circle's feed lives.
    pub fn feed_url(&self, channel: &str) -> String {
        format!("{}/api/v2/f/{channel}", self.base)
    }

    /// Where a circle's posts go.
    pub fn post_url(&self, channel: &str) -> String {
        format!("{}/api/v2/f/{channel}/loc", self.base)
    }

    /// Whether the relay is reachable, and what it says.
    ///
    /// Also records the relay's clock, so a device with a wrong one can correct
    /// itself before it posts anything.
    pub async fn health(&mut self) -> Result<String, RelayError> {
        let url = format!("{}/api/v2/health", self.base);
        let res = self.client.get(&url).send().await.map_err(|_| offline())?;
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(RelayError::new(status.as_u16(), body));
        }
        // The clock and the protocol tag, both learned here rather than by the
        // caller unpacking the body. A device whose own clock is wrong needs the
        // relay's before it can post anything, and this is the call that teaches
        // it.
        self.server_now = health_now(&body);
        Ok(body)
    }

    /// Send one post.
    pub async fn post(&mut self, channel: &str, post: &Post) -> Result<(), RelayError> {
        let url = self.post_url(channel);
        let res = self
            .client
            .post(&url)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(post).unwrap_or_default())
            .send()
            .await
            .map_err(|_| offline())?;

        let status = res.status();
        if status.is_success() {
            let body = res.text().await.unwrap_or_default();
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body)
                && let Some(now) = v.get("now").and_then(|n| n.as_i64())
            {
                self.server_now = Some(now);
            }
            self.last_error = None;
            return Ok(());
        }
        let status = status.as_u16();
        let body = res.text().await.unwrap_or_default();
        let message = serde_json::from_str::<ApiError>(&body)
            .map(|e| e.error)
            .unwrap_or_else(|_| format!("{status}"));
        let err = RelayError::new(status, message);
        self.last_error = Some(err.clone());
        Err(err)
    }

    /// Read a feed from a cursor.
    pub async fn poll(&mut self, channel: &str, since: i64) -> Result<Polled, RelayError> {
        let url = format!("{}?since={since}", self.feed_url(channel));
        let res = self.client.get(&url).send().await.map_err(|_| offline())?;
        let status = res.status();
        if status.as_u16() == 410 {
            return Ok(Polled::Retired);
        }
        if !status.is_success() {
            let status = status.as_u16();
            let body = res.text().await.unwrap_or_default();
            let message = serde_json::from_str::<ApiError>(&body)
                .map(|e| e.error)
                .unwrap_or_else(|_| format!("{status}"));
            let err = RelayError::new(status, message);
            self.last_error = Some(err.clone());
            return Err(err);
        }
        let feed: Feed = res
            .json()
            .await
            .map_err(|_| RelayError::new(502, "the relay sent something unreadable"))?;
        self.server_now = Some(feed.now);
        self.last_error = None;
        // The cursor is the newest receive time in the feed, not the one asked
        // for: asking for the same value again would return the same rows for ever.
        let cursor = feed
            .members
            .iter()
            .flat_map(|m| m.points.iter())
            .map(|p| p.srv)
            .max()
            .unwrap_or(since)
            .max(since);
        Ok(Polled::Feed { feed, cursor })
    }

    /// How far this device's clock is from the relay's.
    ///
    /// Positive means the device is ahead. Used to correct a device that would
    /// otherwise be refused every post with a `clock` error it cannot act on.
    pub fn clock_skew(&self, device_now: i64) -> i64 {
        self.server_now.map(|s| device_now - s).unwrap_or(0)
    }
}

/// A network failure, as the UI sees it.
///
/// Not a `RelayError` with a status, because there is no status: the request never
/// arrived. Confusing the two is how an app ends up telling a user their relay
/// rejected a post when the truth is that the train went into a tunnel.
fn offline() -> RelayError {
    RelayError::new(0, "no connection")
}

fn is_local(base: &str) -> bool {
    let host =
        base.split("://").nth(1).unwrap_or("").split(['/', ':']).next().unwrap_or("");
    host.is_empty()
        || host == "localhost"
        || host == "127.0.0.1"
        || host == "::1"
        || host.ends_with(".local")
        || host.starts_with("192.168.")
        || host.starts_with("10.")
        || (host.starts_with("172.") && {
            let second: u32 =
                host.split('.').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            (16..=31).contains(&second)
        })
}

/// The default poll interval, and the one used when the app is in the background.
pub const POLL_VISIBLE_MS: u64 = 10_000;
pub const POLL_HIDDEN_MS: u64 = 30_000;

/// How often to share while moving.
pub const SHARE_INTERVAL_MS: u64 = 15_000;

/// How far a device must move before it posts again, even before the interval.
pub const MOVE_THRESHOLD_M: f64 = 25.0;

/// The relay's clock, from a health response body.
pub fn health_now(body: &str) -> Option<i64> {
    serde_json::from_str::<serde_json::Value>(body).ok()?.get("now")?.as_i64()
}

/// The protocol tag from a health response, so a client can refuse a relay that
/// speaks something else before it posts a position at it.
pub fn health_protocol(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get("protocol")?
        .as_str()
        .map(str::to_string)
}

/// The protocol this build speaks.
pub fn our_protocol() -> &'static str {
    kestrel_core::PROTO
}

// ---------------------------------------------------------------- the runtime

/// The one runtime this crate creates.
///
/// Kestrel does not run an async application: there is no task, no scheduler of
/// its own, and every future is driven to completion on the thread that wanted
/// the answer. What cannot be faked that way is the machinery underneath — a
/// socket registers with a reactor, a name resolves on a blocking pool, a
/// timeout is a timer, and all three refuse to work outside a runtime's
/// context. Polling such a future in a loop does not advance it: it panics,
/// which under `panic = "abort"` means a failed post closes the app.
///
/// So the runtime exists for the transport, entered by [`block_on`] and by
/// nothing else. Two workers, which is enough for a request and a name lookup
/// to be in flight at once and few enough that nobody is running a second
/// scheduler for fun.
static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();

/// The runtime, created the first time something needs to talk to a relay.
pub fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("kestrel-io")
            // The I/O driver and the timers. Without the first a socket has
            // nowhere to report readiness to; without the second a client
            // timeout is a duration nobody counts down.
            .enable_all()
            .build()
            .expect("a runtime for the relay")
    })
}

/// Drive one future to completion, on the calling thread.
///
/// Safe from as many threads as care to call it at once: the caller parks until
/// the future is ready rather than spinning on it, so a relay that takes a
/// second costs a sleeping thread and not a core.
pub fn block_on<F: std::future::Future>(future: F) -> F::Output {
    runtime().block_on(future)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relay_address_must_be_an_address() {
        assert!(Relay::new("").is_err());
        assert!(Relay::new("   ").is_err());
        assert!(Relay::new("relay.example").is_err());
        assert!(Relay::new("starlingmap.app").is_err());
        assert!(Relay::new("https://relay.example").is_ok());
    }

    #[test]
    fn a_trailing_slash_is_stripped() {
        // Appending to a base with a trailing slash produces `//api`, which some
        // proxies answer with a redirect that loses the method.
        let r = Relay::new("https://relay.example/").unwrap();
        assert_eq!(r.base(), "https://relay.example");
        assert_eq!(
            r.feed_url("a".repeat(32).as_str()),
            format!("https://relay.example/api/v2/f/{}", "a".repeat(32))
        );
        assert!(!r.post_url("abc").contains("//api"));
    }

    #[test]
    fn plain_http_is_refused_except_on_a_local_network() {
        assert!(Relay::new("http://relay.example").is_err());
        assert!(Relay::new("http://localhost:8788").is_ok());
        assert!(Relay::new("http://127.0.0.1:8788").is_ok());
        assert!(Relay::new("http://192.168.1.10:8788").is_ok());
        assert!(Relay::new("http://10.0.0.5:8788").is_ok());
        assert!(Relay::new("http://172.16.0.1:8788").is_ok());
        assert!(Relay::new("http://172.32.0.1:8788").is_err(), "not the private range");
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        let mut b = Backoff::default();
        let first = b.next_delay();
        let second = b.next_delay();
        let third = b.next_delay();
        assert!(second > first, "{first:?} then {second:?}");
        assert!(third > second);
        for _ in 0..20 {
            assert!(b.next_delay() <= b.ceiling);
        }
        b.reset();
        assert_eq!(b.failures, 0);
    }

    #[test]
    fn backoff_is_jittered_rather_than_fixed() {
        // Fixed backoff means every device that lost the relay at the same moment
        // comes back at the same moment.
        let mut delays = std::collections::HashSet::new();
        for _ in 0..20 {
            let mut b = Backoff { failures: 3, ..Default::default() };
            delays.insert(b.next_delay());
        }
        assert!(delays.len() > 1, "the delay never varied: {delays:?}");
    }

    #[test]
    fn an_outbox_replaces_a_queued_position_but_keeps_a_rekey() {
        let mut outbox = Outbox::new();
        // Two positions collapse to one; a re-key and a goodbye are kept, because
        // neither means anything a later position could carry.
        outbox.push(a_placeholder_post(1), "position", true);
        outbox.push(a_placeholder_post(2), "position", true);
        outbox.push(a_placeholder_post(3), "rekey", false);
        outbox.push(a_placeholder_post(4), "goodbye", false);
        assert_eq!(outbox.len(), 3, "two positions, a re-key and a goodbye");
        assert_eq!(outbox.peek().unwrap().ts, 2, "the newer position is the one kept");
    }

    #[test]
    fn a_control_message_is_never_dropped_for_being_older() {
        // A goodbye posted at the end of an offline stretch must still go out: the
        // circle needs to see "stopped", not a position from ten minutes ago.
        let mut outbox = Outbox::new();
        outbox.push(a_placeholder_post(1), "position", true);
        outbox.push(a_placeholder_post(2), "goodbye", false);
        outbox.push(a_placeholder_post(3), "position", true);
        let mut seen = Vec::new();
        while let Some(q) = outbox.pop() {
            seen.push((q.label.clone(), q.post.ts));
        }
        assert_eq!(seen, vec![("goodbye".to_string(), 2), ("position".to_string(), 3)]);
    }

    /// A post with the right shape and nothing else. The outbox does not look
    /// inside one, and a real one would need a circle to seal.
    fn a_placeholder_post(ts: i64) -> Post {
        Post {
            m: "dc73c74c3f57c6ff0c2d9016c333507f".into(),
            alg: "ed25519".into(),
            pk: "p".into(),
            epk: "e".into(),
            e: 1,
            ts,
            n: "n".into(),
            c: "c".into(),
            sig: "s".into(),
        }
    }

    #[test]
    fn an_outbox_can_be_emptied_for_a_panic_wipe() {
        let mut outbox = Outbox::new();
        assert!(outbox.is_empty());
        outbox.clear();
        assert!(outbox.is_empty());
    }

    #[test]
    fn a_health_body_is_read_for_its_clock_and_protocol() {
        let body = r#"{"ok":true,"protocol":"starling/v2","now":1788282959714}"#;
        assert_eq!(health_now(body), Some(1_788_282_959_714));
        assert_eq!(health_protocol(body).as_deref(), Some("starling/v2"));
        assert_eq!(health_now("not json"), None);
        assert_eq!(health_protocol("{}"), None);
    }

    #[test]
    fn a_relay_speaking_another_protocol_is_refused() {
        // A client that cannot tell is a client that will post a position at
        // something that has no idea what to do with it.
        let body = r#"{"ok":true,"protocol":"something-else"}"#;
        assert_ne!(health_protocol(body).as_deref(), Some(our_protocol()));
    }

    #[test]
    fn clock_skew_is_zero_until_the_relay_has_spoken() {
        // Nothing is claimed before the relay has said anything, rather than
        // guessed from the device's own clock.
        let mut r = Relay::new("https://relay.example").unwrap();
        assert_eq!(r.clock_skew(1_000), 0, "nothing is known yet");
        assert!(r.server_now.is_none());
        r.server_now = Some(1_000);
        assert_eq!(r.clock_skew(4_000), 3_000, "the device is ahead by 3 seconds");
    }

    #[test]
    fn an_offline_failure_is_not_a_status() {
        // Telling a user their relay rejected a post when the truth is that the
        // train went into a tunnel is the mistake this distinction prevents.
        let e = offline();
        assert_eq!(e.status, 0);
        assert_eq!(e.message, "no connection");
        assert!(!e.clock);
    }

    #[test]
    fn a_clock_error_is_distinguishable_from_a_malformed_one() {
        let clock = RelayError::new(400, "clock");
        let bad = RelayError::new(400, "bad request");
        assert!(clock.clock);
        assert!(!bad.clock);
    }

    #[test]
    fn the_cadence_defaults_suit_a_moving_device() {
        // Asserted as a `const` block so a change to a constant is a compile
        // error rather than a test that quietly stops meaning anything.
        const {
            assert!(MOVE_THRESHOLD_M > 0.0, "a threshold of zero posts on every fix");
            assert!(SHARE_INTERVAL_MS >= 10_000, "faster than this is a battery cost");
            assert!(POLL_HIDDEN_MS > POLL_VISIBLE_MS, "a hidden app should poll less");
            assert!(SHARE_INTERVAL_MS < POLL_HIDDEN_MS, "but a share stays live");
        }
    }
}
