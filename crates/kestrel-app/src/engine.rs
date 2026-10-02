//! The share loop: what happens between a position arriving and a post going out.
//!
//! This is the module that has to be right about *timing and ordering*, and both are
//! impossible to check by hand. A share that drops the first position, or that sends an
//! old one after a newer one, or that keeps a minute of history because the network was
//! down, all look fine in a demo and all fail in a pocket.
//!
//! Every decision here is a pure function of the shared state plus an input, so the
//! whole loop can be driven by hand in a test: no network, no clock, no phone. The
//! async parts — actually calling the relay — are behind a trait so the tests supply a
//! fake that can be told to fail, to be slow, or to be offline.

use std::sync::Arc;

use kestrel_core::{
    msg::ShareMode,
    session::Circle,
    wire::{Feed, Post},
};
use kestrel_net::{Outbox, Relay};

use crate::{
    logic,
    permissions::Permissions,
    state::{Fix, Shared},
    store,
};

/// What the relay can be asked to do.
///
/// A trait rather than [`Relay`] directly so the tests can make it fail, be slow, or
/// hand back a feed with someone else's post in it. The failure paths are the interesting
/// ones and they are exactly the ones a real relay will not produce on demand.
pub trait Sink: Send + Sync {
    /// Send one post. An error means "not sent"; the outbox decides what to do about it.
    fn send<'a>(
        &'a self,
        channel: &'a str,
        post: &'a Post,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>;

    /// Fetch what is new since a cursor.
    fn fetch<'a>(
        &'a self,
        channel: &'a str,
        since: i64,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Feed, String>> + Send + 'a>,
    >;
}

/// The real relay.
pub struct NetSink {
    /// A tokio mutex rather than a std one, because the guard is held across an await.
    /// A `std::sync::MutexGuard` across an await makes the future non-`Send`, which would
    /// force every caller onto one thread — which is to say, make this async for nothing.
    relay: tokio::sync::Mutex<Relay>,
    base: String,
}

impl NetSink {
    pub fn new(base: &str) -> Result<Self, String> {
        Ok(Self {
            relay: tokio::sync::Mutex::new(Relay::new(base)?),
            base: base.trim_end_matches('/').to_string(),
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }
}

impl Sink for NetSink {
    fn send<'a>(
        &'a self,
        channel: &'a str,
        post: &'a Post,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>
    {
        // The lock is taken inside the future rather than before it, for the same reason
        // as the tokio mutex above.
        Box::pin(async move {
            // A tokio mutex cannot be poisoned, which is one of the reasons to use it
            // here: there is no window where a panic inside a send leaves a lock that
            // nothing can ever take again.
            let mut relay = self.relay.lock().await;
            relay.post(channel, post).await.map_err(|e| format!("{e:?}"))
        })
    }

    fn fetch<'a>(
        &'a self,
        channel: &'a str,
        since: i64,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Feed, String>> + Send + 'a>,
    > {
        Box::pin(async move {
            let mut relay = self.relay.lock().await;
            match relay.poll(channel, since).await {
                Ok(kestrel_net::Polled::Feed { feed, .. }) => Ok(feed),
                // The relay speaking a protocol this build does not is not a transient
                // failure: retrying forever would be a share that claims to be running
                // and posts nothing.
                Ok(kestrel_net::Polled::Retired) => {
                    Err("the relay no longer speaks this protocol".to_string())
                }
                Err(e) => Err(format!("{e:?}")),
            }
        })
    }
}

/// Everything the share loop owns.
pub struct Engine {
    shared: Arc<Shared>,
    sink: Arc<dyn Sink>,
    outbox: std::sync::Mutex<Outbox>,
    /// The last cursor fetched, so a poll asks only for what is new.
    cursor: std::sync::Mutex<i64>,
    /// Whether a send is in flight. Without this, two threads could both decide to post
    /// the same position and the circle would see it twice.
    posting: std::sync::Mutex<bool>,
    /// Backoff after a failure, so a relay that is down is not hammered.
    backoff: std::sync::Mutex<kestrel_net::Backoff>,
    /// The channel of the circle being served. Cached because it is on the path of every
    /// send and every poll and a `String` clone per post is not free.
    channel: std::sync::Mutex<String>,
    /// The last fix that was queued, as the baseline for the next movement decision.
    last_queued: std::sync::Mutex<Option<Fix>>,
}

impl Engine {
    pub fn new(shared: Arc<Shared>, sink: Arc<dyn Sink>) -> Self {
        Self {
            shared,
            sink,
            outbox: std::sync::Mutex::new(Outbox::new()),
            cursor: std::sync::Mutex::new(0),
            posting: std::sync::Mutex::new(false),
            backoff: std::sync::Mutex::new(kestrel_net::Backoff::default()),
            channel: std::sync::Mutex::new(String::new()),
            last_queued: std::sync::Mutex::new(None),
        }
    }

    /// Point the engine at a circle.
    pub fn attach(&self, channel: &str) {
        if let Ok(mut slot) = self.channel.lock() {
            *slot = channel.to_string();
        }
        // A new circle starts from zero: a cursor from a previous one would ask for
        // everything since then on a channel that has none of it.
        if let Ok(mut cursor) = self.cursor.lock() {
            *cursor = 0;
        }
        if let Ok(mut last) = self.last_queued.lock() {
            *last = None;
        }
    }

    /// The channel this engine serves.
    fn channel(&self) -> String {
        self.channel.lock().map(|c| c.clone()).unwrap_or_default()
    }

    /// Queue this device's position, if it is worth sending.
    ///
    /// Returns whether anything was queued. A false here is the common case and is not a
    /// problem: it means the person has not moved.
    pub fn offer_position(&self) -> bool {
        let Some(fix) = self.shared.newest_fix() else {
            return false;
        };
        let permissions = self.permissions();
        if !should_be_posting(&permissions, true) {
            // No point queueing a position nobody may send, and no point continuing to
            // claim that a share is running.
            return false;
        }
        let name = store::load_settings().name;

        // The baseline is the last fix that was *queued*, not the newest one to arrive.
        // Using the newest would mean the very first offer compares a fix with itself,
        // finds no movement, and decides there is nothing to send.
        let last = self.last_queued.lock().ok().and_then(|slot| *slot);

        // The same fix again is not a new position, whether or not the last one went out.
        // `worth_posting` treats a missing baseline as "first position, always send", so
        // without this an offer made after a successful send would put the same
        // coordinate on the wire a second time — once per poll, for as long as the share
        // ran.
        if last.is_some_and(|l| l.ts == fix.ts) {
            return false;
        }

        // Built under the circle's lock, via Shared, so no key material is ever copied
        // out of it.
        let post = self
            .shared
            .with_circle(|circle| {
                logic::build_post(circle, &fix, &permissions, &name, last.as_ref())
            })
            .flatten();
        let Some(post) = post else {
            return false;
        };
        if let Ok(mut slot) = self.last_queued.lock() {
            *slot = Some(fix);
        }
        self.push(post, "position", true);
        true
    }

    /// Fold a poll's events into the circle.
    ///
    /// `None` when there is no circle, which is the normal state on the welcome screen
    /// and after a duress wipe.
    fn ingest(&self, feed: &Feed, now: i64) -> usize {
        self.shared.with_circle(|circle| circle.ingest_feed(feed, now).len()).unwrap_or(0)
    }

    fn permissions(&self) -> Permissions {
        self.shared.permissions.lock().map(|p| *p).unwrap_or_default()
    }

    /// Add a post to the outbox.
    pub fn push(&self, post: Post, label: &str, coalescible: bool) {
        if let Ok(mut outbox) = self.outbox.lock() {
            outbox.push(post, label, coalescible);
        }
    }

    /// Send whatever is queued, oldest first.
    ///
    /// A failure stops the pass. Keeping the order matters: a goodbye that arrives before
    /// the position it follows would tell the circle someone stopped before it knew where
    /// they were.
    pub async fn flush(&self) -> Result<usize, String> {
        let channel = self.channel();
        if channel.is_empty() {
            return Err("no circle attached".to_string());
        }
        // One sender at a time. Two threads both sending would either interleave posts or
        // post the same position twice, and neither is a thing a circle can explain.
        {
            let Ok(mut posting) = self.posting.lock() else {
                return Err("the engine is unusable".to_string());
            };
            if *posting {
                return Ok(0);
            }
            *posting = true;
        }
        let result = self.flush_inner(&channel).await;
        if let Ok(mut posting) = self.posting.lock() {
            *posting = false;
        }
        match &result {
            Ok(_) => {
                if let Ok(mut backoff) = self.backoff.lock() {
                    backoff.reset();
                }
            }
            Err(_) => {
                if let Ok(mut backoff) = self.backoff.lock() {
                    backoff.next_delay();
                }
            }
        }
        result
    }

    async fn flush_inner(&self, channel: &str) -> Result<usize, String> {
        let mut sent = 0;
        loop {
            let front = {
                let Ok(outbox) = self.outbox.lock() else {
                    return Err("the outbox is locked".to_string());
                };
                match outbox.peek() {
                    Some(post) => post.clone(),
                    None => return Ok(sent),
                }
            };
            if self.sink.send(channel, &front).await.is_err() {
                // Left in the queue. A position is coalescible, so a later position will
                // replace it rather than both going out; a goodbye or a re-key is not, and
                // will still be there when the network comes back.
                return Err("could not reach the relay".to_string());
            }
            let Ok(mut outbox) = self.outbox.lock() else {
                return Err("the outbox is locked".to_string());
            };
            outbox.pop();
            sent += 1;
        }
    }

    /// Fetch what is new, and fold it into the circle.
    pub async fn poll(&self, now: i64) -> Result<usize, String> {
        let channel = self.channel();
        if channel.is_empty() {
            return Err("no circle attached".to_string());
        }
        let since = self.cursor.lock().map(|c| *c).unwrap_or(0);
        let feed = self.sink.fetch(&channel, since).await?;
        let count = self.ingest(&feed, now);
        // The cursor advances even when nothing was accepted: a post this build
        // rejects should not be re-fetched every fifteen seconds for the life of the app.
        // The relay's own clock, not a device-side one: a phone with a wrong clock
        // would otherwise ask for a window the relay considers empty and sit there.
        if let Ok(mut cursor) = self.cursor.lock() {
            *cursor = feed.now.max(since);
        }
        Ok(count)
    }

    /// How long to wait before trying again.
    pub fn next_delay_ms(&self) -> i64 {
        self.backoff.lock().map(|mut b| b.next_delay().as_millis() as i64).unwrap_or(1000)
    }

    /// Forget everything queued.
    ///
    /// For the duress passcode: a wiped device must not have a queue of positions that
    /// the next launch would send.
    pub fn clear(&self) {
        if let Ok(mut outbox) = self.outbox.lock() {
            outbox.clear();
        }
        if let Ok(mut cursor) = self.cursor.lock() {
            *cursor = 0;
        }
        // The movement baseline too. Kept across a circle switch it would suppress the
        // first post from the new circle, which is exactly the one a circle needs.
        if let Ok(mut last) = self.last_queued.lock() {
            *last = None;
        }
    }

    /// How many posts are waiting.
    pub fn queued(&self) -> usize {
        self.outbox.lock().map(|o| o.len()).unwrap_or(0)
    }
}

/// Whether this device should be posting at all.
///
/// A single question, asked from one place, because the answer is what the notification
/// claims and what the map says and what the relay receives. Three places deciding it
/// separately is how the app ends up claiming to share while posting nothing.
pub fn should_be_posting(permissions: &Permissions, sharing: bool) -> bool {
    sharing && permissions.can_share() && permissions.service_is_visible()
}

/// The sharing mode implied by the permissions.
pub fn mode_for(permissions: &Permissions) -> ShareMode {
    logic::share_mode(permissions)
}

/// The post a fix would produce, or `None`.
pub fn post_for(
    circle: &mut Circle,
    fix: &Fix,
    permissions: &Permissions,
    name: &str,
) -> Option<Post> {
    logic::build_post(circle, fix, permissions, name, None)
}

/// Whether a feed is worth fetching again right now.
///
/// Empty feeds are common: nobody moved. Polling an empty feed every fifteen seconds for
/// an hour is 240 requests saying nothing changed.
pub fn worth_polling(last_empty: bool, elapsed_ms: i64) -> bool {
    if !last_empty {
        return true;
    }
    // An empty feed is polled far less often than a busy one.
    elapsed_ms >= 60_000
}

/// Whether a position is worth telling the user about.
///
/// Not the same question as whether it is worth sending: the user does not need to be
/// told that the app is still working, once a minute, for as long as a share is running.
pub fn worth_telling(last_told_ms: i64, now_ms: i64) -> bool {
    if last_told_ms == 0 {
        return true;
    }
    now_ms.saturating_sub(last_told_ms) >= 15 * 60 * 1000
}

#[cfg(test)]
mod tests {
    use super::{block_on, *};
    use std::sync::Mutex;

    /// A relay that records what it was sent and can be told to fail.
    struct Fake {
        sent: Mutex<Vec<String>>,
        feed: Mutex<Feed>,
        fail_send: Mutex<bool>,
        fail_fetch: Mutex<bool>,
        /// Every channel this was asked about, in order.
        channels: Mutex<Vec<String>>,
    }

    impl Fake {
        fn new() -> Arc<Fake> {
            Arc::new(Fake {
                sent: Mutex::new(Vec::new()),
                feed: Mutex::new(Feed { now: 0, members: Vec::new() }),
                fail_send: Mutex::new(false),
                fail_fetch: Mutex::new(false),
                channels: Mutex::new(Vec::new()),
            })
        }

        fn sent(&self) -> Vec<String> {
            self.sent.lock().map(|s| s.clone()).unwrap_or_default()
        }

        fn set_feed(&self, feed: Feed) {
            if let Ok(mut slot) = self.feed.lock() {
                *slot = feed;
            }
        }

        fn channels(&self) -> Vec<String> {
            self.channels.lock().map(|c| c.clone()).unwrap_or_default()
        }
    }

    impl Sink for Fake {
        fn send<'a>(
            &'a self,
            channel: &'a str,
            post: &'a Post,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>,
        > {
            Box::pin(async move {
                if *self.fail_send.lock().unwrap() {
                    return Err("offline".to_string());
                }
                self.channels.lock().unwrap().push(channel.to_string());
                self.sent.lock().unwrap().push(post.c.clone());
                Ok(())
            })
        }

        fn fetch<'a>(
            &'a self,
            channel: &'a str,
            _since: i64,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Feed, String>> + Send + 'a>,
        > {
            Box::pin(async move {
                if *self.fail_fetch.lock().unwrap() {
                    return Err("offline".to_string());
                }
                self.channels.lock().unwrap().push(channel.to_string());
                Ok(self.feed.lock().unwrap().clone())
            })
        }
    }

    /// A shared state holding one circle, which is what the engine reads through.
    fn with_circle() -> (Arc<Shared>, String) {
        let shared = Arc::new(Shared::default());
        let identity = kestrel_core::identity::Identity::generate();
        let seed = kestrel_core::seal::random_bytes::<32>();
        let circle = Circle::create(identity, &seed, 1_700_000_000_000);
        let channel = circle.channel().to_string();
        *shared.circles.lock().unwrap() = vec![circle];
        (shared, channel)
    }

    /// A circle whose permissions allow posting, and whose user has asked to share.
    ///
    /// `sharing` is recorded in both places it is read from. That they must agree is the
    /// sort of thing a test exists for; the helper sets both because forgetting one
    /// produces a loop that runs but sends nothing, or a notification claiming a share
    /// that is not running.
    fn shareable() -> (Arc<Shared>, String) {
        let (shared, channel) = with_circle();
        let mut p = permitted();
        p.set_sharing(true);
        *shared.permissions.lock().unwrap() = p;
        if let Ok(mut state) = shared.state.lock() {
            state.sharing = true;
        }
        (shared, channel)
    }

    /// A post for `ts`, built from the circle in `shared`.
    fn a_post(shared: &Shared, ts: i64) -> Option<Post> {
        shared
            .with_circle(|circle| {
                logic::build_post(circle, &fix(ts), &permitted(), "Ada", None)
            })
            .flatten()
    }

    fn fix(ts: i64) -> Fix {
        Fix { lat: 44.98, lon: -93.27, acc: 5.0, ts, battery: 0.8 }
    }

    fn permitted() -> Permissions {
        use crate::permissions::{Report, apply_report};
        let mut p = Permissions::default();
        apply_report(
            &Report {
                fine: "granted".into(),
                coarse: "granted".into(),
                background: "granted".into(),
                notifications: "granted".into(),
                camera: "unknown".into(),
            },
            &mut p,
        );
        p
    }

    #[test]
    fn an_empty_engine_sends_nothing() {
        let sink = Fake::new();
        let engine = Engine::new(Arc::new(Shared::default()), sink.clone());
        assert_eq!(engine.queued(), 0);
    }

    #[test]
    fn a_post_goes_out_and_the_queue_empties() {
        let sink = Fake::new();
        let (shared, channel) = with_circle();
        let engine = Engine::new(shared.clone(), sink.clone());
        engine.attach(&channel);
        let post = a_post(&shared, 1_700_000_001_000)
            .expect("a first position should produce a post");
        engine.push(post, "position", true);
        assert_eq!(engine.queued(), 1);
        block_on(async {
            engine.flush().await.expect("the sink accepts this");
        });
        assert_eq!(engine.queued(), 0);
        assert_eq!(sink.sent().len(), 1);
        // And it went to the circle's own channel, not somewhere else.
        assert_eq!(
            sink.channels().first().map(|s| s.as_str()),
            Some(channel.as_str()),
            "the post went somewhere other than the circle's channel"
        );
    }

    #[test]
    fn a_relay_that_is_down_keeps_the_post() {
        // The whole reason the outbox exists. A position dropped because the network was
        // down is a hole in the circle's picture of someone.
        let sink = Fake::new();
        *sink.fail_send.lock().unwrap() = true;
        let (shared, channel) = with_circle();
        let engine = Engine::new(shared.clone(), sink.clone());
        engine.attach(&channel);
        let post = a_post(&shared, 1_700_000_001_000).unwrap();
        engine.push(post, "position", true);
        let result = block_on(async { engine.flush().await });
        assert!(result.is_err());
        assert_eq!(engine.queued(), 1, "the post was dropped");
    }

    #[test]
    fn a_long_offline_period_sends_one_position_not_a_hundred() {
        // A queue of positions is a history the circle did not ask for, and every one of
        // them is a coordinate the relay held.
        let sink = Fake::new();
        *sink.fail_send.lock().unwrap() = true;
        let (shared, channel) = with_circle();
        let engine = Engine::new(shared.clone(), sink.clone());
        engine.attach(&channel);
        for step in 0..40 {
            let post = a_post(&shared, 1_700_000_001_000 + step * 15_000).unwrap();
            engine.push(post, "position", true);
        }
        assert_eq!(engine.queued(), 1, "positions were not coalesced");
        // And a goodbye is not coalescible: its meaning cannot be carried by a later one.
        let goodbye = shared
            .with_circle(|circle| {
                let msg = kestrel_core::msg::CircleMsg::bye(
                    0,
                    kestrel_core::session::me(
                        circle.identity(),
                        "Ada",
                        "",
                        0.8,
                        ShareMode::Precise,
                    ),
                );
                circle.seal(&msg, 1_700_000_002_000)
            })
            .flatten();
        if let Some(post) = goodbye {
            engine.push(post, "goodbye", false);
        }
        assert_eq!(engine.queued(), 2);
    }

    #[test]
    fn a_failed_send_does_not_wedge_the_engine() {
        // A flag left set after a failure would mean the second flush silently did
        // nothing, forever.
        let sink = Fake::new();
        let (shared, channel) = with_circle();
        let engine = Engine::new(shared.clone(), sink.clone());
        engine.attach(&channel);
        *sink.fail_send.lock().unwrap() = true;
        let post = a_post(&shared, 1_700_000_001_000).unwrap();
        engine.push(post, "position", true);
        assert!(block_on(async { engine.flush().await }).is_err());
        *sink.fail_send.lock().unwrap() = false;
        assert!(block_on(async { engine.flush().await }).is_ok());
        assert_eq!(engine.queued(), 0);
    }

    #[test]
    fn an_engine_with_no_circle_sends_nothing() {
        let sink = Fake::new();
        let engine = Engine::new(Arc::new(Shared::default()), sink.clone());
        let result = block_on(async { engine.flush().await });
        assert!(result.is_err());
        assert!(sink.sent().is_empty());
    }

    #[test]
    fn attaching_a_second_circle_starts_the_cursor_over() {
        // A cursor from the first circle would ask the second for everything since then,
        // which it has none of.
        let sink = Fake::new();
        let engine = Engine::new(Arc::new(Shared::default()), sink.clone());
        engine.attach("aaaaaaaa");
        block_on(async {
            engine.poll(1_700_000_000_000).await.ok();
        });
        engine.attach("bbbbbbbb");
        block_on(async { engine.poll(1_700_000_000_000).await }).ok();
        let asked = sink.channels();
        assert_eq!(asked.first().map(|s| s.as_str()), Some("aaaaaaaa"));
        assert_eq!(asked.last().map(|s| s.as_str()), Some("bbbbbbbb"));
    }

    #[test]
    fn a_poll_advances_the_cursor_and_folds_the_feed() {
        // A cursor that does not advance re-fetches the same window every fifteen seconds
        // for the life of the app.
        let sink = Fake::new();
        let (shared, channel) = with_circle();
        let engine = Engine::new(shared, sink.clone());
        engine.attach(&channel);
        sink.set_feed(kestrel_core::wire::Feed {
            now: 1_700_000_060_000,
            members: Vec::new(),
        });
        block_on(async {
            engine.poll(1_700_000_060_000).await.ok();
        });
        assert_eq!(engine.cursor.lock().unwrap().to_owned(), 1_700_000_060_000);

        // And a feed the relay stamps with an *older* clock than we already have does not
        // rewind the cursor, which would re-deliver everything after it.
        sink.set_feed(kestrel_core::wire::Feed {
            now: 1_000_000_000_000,
            members: Vec::new(),
        });
        block_on(async {
            engine.poll(1_700_000_060_000).await.ok();
        });
        assert_eq!(engine.cursor.lock().unwrap().to_owned(), 1_700_000_060_000);
    }

    #[test]
    fn a_relay_that_is_down_does_not_move_the_cursor() {
        // The failure case that matters: a failed fetch must leave the cursor alone, or
        // the posts that were missed while it was down are never fetched.
        let sink = Fake::new();
        *sink.fail_fetch.lock().unwrap() = true;
        let (shared, channel) = with_circle();
        let engine = Engine::new(shared, sink.clone());
        engine.attach(&channel);
        assert!(block_on(async { engine.poll(1).await }).is_err());
        assert_eq!(engine.cursor.lock().unwrap().to_owned(), 0);
    }

    #[test]
    fn a_wiped_device_sends_nothing_queued() {
        // A duress wipe with a queue full of positions would post them on the next
        // launch, from a key the user believes is gone.
        let sink = Fake::new();
        let (shared, channel) = with_circle();
        let engine = Engine::new(shared.clone(), sink.clone());
        engine.attach(&channel);
        let post = a_post(&shared, 1_700_000_001_000).unwrap();
        engine.push(post, "position", true);
        assert_eq!(engine.queued(), 1);
        engine.clear();
        assert_eq!(engine.queued(), 0);
        block_on(async {
            engine.flush().await.ok();
        });
        assert!(sink.sent().is_empty());
    }

    #[test]
    fn posting_needs_sharing_and_both_permissions() {
        // One question, asked in one place, because the notification, the map and the
        // relay must all say the same thing.
        assert!(should_be_posting(&permitted(), true));
        assert!(!should_be_posting(&permitted(), false));
        // Location refused.
        assert!(!should_be_posting(&Permissions::default(), true));
        // Location fine but notifications off: Android would run the service silently.
        use crate::permissions::{Report, apply_report};
        let mut p = Permissions::default();
        apply_report(
            &Report {
                fine: "granted".into(),
                coarse: "granted".into(),
                background: "granted".into(),
                notifications: "denied".into(),
                camera: "unknown".into(),
            },
            &mut p,
        );
        assert!(!should_be_posting(&p, true));
    }

    #[test]
    fn an_empty_feed_is_polled_less_often() {
        // 240 requests an hour saying nothing changed is 240 requests.
        assert!(worth_polling(false, 0));
        assert!(worth_polling(false, 1000));
        assert!(!worth_polling(true, 1000));
        assert!(worth_polling(true, 60_000));
        assert!(worth_polling(true, 120_000));
    }

    #[test]
    fn the_user_is_not_told_the_app_is_still_working() {
        // Once a minute for an hour is a stream of notifications about nothing.
        assert!(worth_telling(0, 1_700_000_000_000));
        assert!(!worth_telling(1_700_000_000_000, 1_700_000_060_000));
        assert!(worth_telling(1_700_000_000_000, 1_700_000_000_000 + 16 * 60 * 1000));
    }

    #[test]
    fn the_mode_follows_the_permission() {
        use crate::permissions::{Report, apply_report};
        let mut p = permitted();
        assert_eq!(mode_for(&p), ShareMode::Precise);
        apply_report(
            &Report {
                fine: "denied".into(),
                coarse: "granted".into(),
                ..Report::default()
            },
            &mut p,
        );
        assert_eq!(mode_for(&p), ShareMode::Coarse);
    }

    #[test]
    fn an_unusable_fix_produces_no_post() {
        let (shared, _channel) = with_circle();
        // A timestamp inside the circle's own epoch: the ratchet refuses a post from
        // before it was created, which is correct and is checked elsewhere.
        let now = 1_700_000_001_000;
        assert!(a_post(&shared, now).is_some(), "a usable position should produce a post");
        let zero = Fix { lat: 0.0, lon: 0.0, acc: 0.0, ts: now + 1000, battery: 0.0 };
        let refused = shared
            .with_circle(|circle| {
                logic::build_post(circle, &zero, &permitted(), "Ada", None)
            })
            .flatten();
        // The core refuses a null-island position outright, so nothing is queued rather
        // than a marker appearing in the Gulf of Guinea.
        assert!(refused.is_none());
    }

    #[test]
    fn the_share_loop_posts_a_fix_and_folds_the_feed() {
        let sink = Fake::new();
        let (shared, channel) = shareable();
        let engine = Arc::new(Engine::new(shared.clone(), sink.clone()));
        engine.attach(&channel);
        let mut loop_ = ShareLoop::new(engine, shared.clone());

        // A first tick with nothing to do: a person has not moved, so there is nothing
        // to send, and the feed is worth one fetch.
        let tick = loop_.tick(1_700_000_001_000);
        assert_eq!(tick.posted, 0, "nothing to send yet");
        assert!(!tick.offline);
        assert!(tick.sending, "sharing was on and permitted");

        // Now a fix. The loop offers it, flushes it, and the relay is told.
        shared.record_fix(fix(1_700_000_001_500));
        let tick = loop_.tick(1_700_000_001_500);
        assert_eq!(tick.posted, 1, "the fix was not sent");
        assert_eq!(sink.sent().len(), 1);

        // And a poll on the same pass. The cursor now exists, so the cursor-only tests
        // above describe the general case.
        assert_eq!(tick.polled, 0, "the feed was empty");
    }

    #[test]
    fn the_share_loop_does_not_poll_an_empty_feed_every_pass() {
        // An empty feed is worth one fetch a minute, not one fetch a second: four tests
        // a minute of "nobody has moved" is four minutes of electricity.
        let sink = Fake::new();
        let (shared, channel) = shareable();
        let engine = Arc::new(Engine::new(shared.clone(), sink.clone()));
        engine.attach(&channel);
        let mut loop_ = ShareLoop::new(engine, shared.clone());

        let first = loop_.tick(1_700_000_001_000);
        assert_eq!(first.polled, 0);
        let second = loop_.tick(1_700_000_001_500);
        assert_eq!(second.polled, 0);
        // The second tick did not even ask: the fetch count on the fake is one, not two.
        // The fake records the channel in `channels` on every fetch.
        assert_eq!(sink.channels().len(), 1, "fetched again within the empty-feed window");
    }

    #[test]
    fn the_share_loop_is_quiet_when_sharing_is_off() {
        let sink = Fake::new();
        let (shared, channel) = with_circle(); // permissions default: not sharing
        let engine = Arc::new(Engine::new(shared.clone(), sink.clone()));
        engine.attach(&channel);
        let mut loop_ = ShareLoop::new(engine, shared.clone());
        shared.record_fix(fix(1_700_000_001_000));
        let tick = loop_.tick(1_700_000_001_000);
        assert!(!tick.sending);
        assert_eq!(tick.posted, 0);
        assert_eq!(tick.polled, 0, "no poll while nobody is sharing");
        assert!(sink.channels().is_empty());
    }

    #[test]
    fn the_share_loop_stays_alive_when_the_relay_is_down() {
        // The ordinary case: the phone is in a lift. Nothing panics, nothing blocks on a
        // timeout beyond the HTTP client's, and the next pass tries again.
        let sink = Fake::new();
        *sink.fail_send.lock().unwrap() = true;
        *sink.fail_fetch.lock().unwrap() = true;
        let (shared, channel) = shareable();
        let engine = Arc::new(Engine::new(shared.clone(), sink.clone()));
        engine.attach(&channel);
        let mut loop_ = ShareLoop::new(engine.clone(), shared.clone());
        shared.record_fix(fix(1_700_000_001_000));
        let tick = loop_.tick(1_700_000_001_000);
        assert!(tick.offline);
        assert_eq!(tick.posted, 0);
        assert_eq!(engine.queued(), 1, "the post was dropped rather than queued");

        // And it comes back.
        *sink.fail_send.lock().unwrap() = false;
        *sink.fail_fetch.lock().unwrap() = false;
        let tick = loop_.tick(1_700_000_061_000);
        assert!(!tick.offline);
        assert_eq!(tick.posted, 1);
        assert_eq!(engine.queued(), 0);
    }

    #[test]
    fn the_share_loop_interval_is_a_sane_cadence() {
        // Fast enough that a person who starts moving posts within the patience people
        // have for a map; slow enough that the loop is not a battery drain.
        let interval = ShareLoop::interval();
        assert!(interval.as_millis() >= 100, "polling more than ten times a second");
        assert!(interval.as_millis() <= 2_000, "a position could wait two seconds to post");
    }

    #[test]
    fn a_position_is_queued_and_sent_by_the_loop() {
        // The whole path end to end, minus the network: a fix arrives, the engine notices,
        // and the relay is told. This is the test that would have caught a share running,
        // showing a notification, and posting nothing.
        let sink = Fake::new();
        let (shared, channel) = shareable();
        let engine = Engine::new(shared.clone(), sink.clone());
        engine.attach(&channel);

        assert!(!engine.offer_position(), "no fix yet, so nothing to send");
        assert!(
            !shared.record_fix(Fix { lat: 0.0, lon: 0.0, acc: 0.0, ts: 1, battery: 0.0 }),
            "a null-island fix should be refused outright"
        );
        assert!(shared.record_fix(fix(1_700_000_001_000)));
        assert!(engine.offer_position(), "the first position should be queued");
        block_on(async { engine.flush().await }).expect("the sink accepts it");
        assert_eq!(sink.sent().len(), 1);
        assert!(engine.queued() == 0);

        // A second offer at the same fix sends nothing: it is the same place.
        assert!(!engine.offer_position(), "the same fix was queued twice");
    }

    #[test]
    fn moving_queues_another_position_and_standing_still_does_not() {
        let sink = Fake::new();
        let (shared, channel) = shareable();
        let engine = Engine::new(shared.clone(), sink.clone());
        engine.attach(&channel);
        shared.record_fix(fix(1_700_000_001_000));
        assert!(engine.offer_position());
        // Flushed between each step: an unflushed position is coalesced away by the next
        // one, which is the whole point of the queue and would otherwise mask the result.
        block_on(async { engine.flush().await }).ok();

        // Same place, fifteen seconds later: nothing.
        shared.record_fix(fix(1_700_000_016_000));
        assert!(!engine.offer_position(), "a stationary device queued again");
        block_on(async { engine.flush().await }).ok();
        assert_eq!(sink.sent().len(), 1, "a stationary device sent again");

        // A kilometre away: something.
        shared.record_fix(Fix {
            lat: 44.989,
            lon: -93.27,
            acc: 5.0,
            ts: 1_700_000_031_000,
            battery: 0.8,
        });
        assert!(engine.offer_position(), "a kilometre of movement queued nothing");
        block_on(async { engine.flush().await }).ok();
        assert_eq!(sink.sent().len(), 2);
    }

    #[test]
    fn a_share_without_permission_queues_nothing() {
        // The engine is asked to post while the location permission is refused. It must
        // queue nothing: a post that cannot be sent sitting in a queue is a claim the
        // app cannot back up.
        let sink = Fake::new();
        let (shared, channel) = with_circle();
        let engine = Engine::new(shared.clone(), sink.clone());
        engine.attach(&channel);
        shared.record_fix(fix(1_700_000_001_000));
        assert!(!engine.offer_position());
        assert_eq!(engine.queued(), 0);
    }

    #[test]
    fn a_share_with_no_circle_queues_nothing() {
        // First run: a fix arrives before a circle exists.
        let sink = Fake::new();
        let shared = Arc::new(Shared::default());
        let engine = Engine::new(shared.clone(), sink.clone());
        shared.record_fix(fix(1_700_000_001_000));
        assert!(!engine.offer_position());
        assert!(block_on(async { engine.flush().await }).is_err());
    }
}

/// What one pass of the share loop did, as data.
///
/// Returned rather than logged, so a test can assert on it and so the caller can decide
/// what is worth saying out loud. A successful pass that did nothing is the common case;
/// it does not become a log line, because an hour of those is not an hour of news.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tick {
    /// How many posts went out.
    pub posted: usize,
    /// How many events a poll folded in.
    pub polled: usize,
    /// Whether the device was trying to post.
    pub sending: bool,
    /// The relay could not be reached this pass.
    pub offline: bool,
}

/// Runs a future to completion without a runtime.
///
/// No async runtime of its own: the engine's futures are driven to completion on the
/// calling thread, which for this app is the share loop thread. A `std::task::Waker`
/// that never wakes is enough, because every future here is polled to readiness
/// immediately — `Relay` responds, and the outbox either accepts the post or it does
/// not, both of which settle without waiting.
fn block_on<F: std::future::Future>(mut future: F) -> F::Output {
    use std::task::{Context, Poll, Waker};
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    // A pinned future polled to completion on one thread and not shared is safe: there
    // is no move once polling starts, and nothing here outlives the call.
    let mut future = unsafe { std::pin::Pin::new_unchecked(&mut future) };
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => return value,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

/// The loop that keeps a share alive: queue the fix when it moves, flush the outbox,
/// fold in what the circle said back.
///
/// Not a task. Kestrel does not carry a runtime of its own, so this is driven by a
/// thread that sleeps between passes. The cadence is the decisions in
/// [`logic::worth_posting`] and [`worth_polling`], not the sleep: a position posts when
/// the person moves, not when the timer happens to fire.
pub struct ShareLoop {
    engine: Arc<Engine>,
    shared: Arc<Shared>,
    last_poll_ms: i64,
    last_poll_was_empty: bool,
}

impl ShareLoop {
    pub fn new(engine: Arc<Engine>, shared: Arc<Shared>) -> Self {
        Self { engine, shared, last_poll_ms: 0, last_poll_was_empty: false }
    }

    /// One pass. Returns what happened rather than doing anything with it.
    pub fn tick(&mut self, now: i64) -> Tick {
        let mut tick = Tick::default();

        let sharing = self.shared.state.lock().map(|s| s.sharing).unwrap_or(false);
        let permissions = self.shared.permissions.lock().map(|p| *p).unwrap_or_default();

        tick.sending = should_be_posting(&permissions, sharing);
        if tick.sending {
            // Offers the newest fix if it moved enough. The movement decision is in
            // logic, where it is tested; this only drives it.
            self.engine.offer_position();
        }

        match block_on(self.engine.flush()) {
            Ok(sent) => tick.posted = sent,
            // An unreachable relay is ordinary, not something to log every half second:
            // the outbox keeps the post, and the next pass tries again.
            Err(_) => tick.offline = true,
        }

        // Fetching is the expensive thing on the wire. An empty feed is worth asking
        // about once a minute, not every pass, or every phone in a quiet circle spends
        // its day asking about a circle nobody has spoken in.
        let elapsed = now.saturating_sub(self.last_poll_ms);
        if sharing && worth_polling(self.last_poll_was_empty, elapsed) {
            match block_on(self.engine.poll(now)) {
                Ok(events) => {
                    tick.polled = events;
                    self.last_poll_was_empty = events == 0;
                }
                Err(_) => {
                    tick.offline = true;
                    self.last_poll_was_empty = true;
                }
            }
            self.last_poll_ms = now;
        }
        tick
    }

    /// How long to sleep until the next pass.
    ///
    /// The loop must be awake often enough to catch a position the moment a person
    /// starts moving. Somewhere between the lowest postable interval and that.
    pub fn interval() -> std::time::Duration {
        std::time::Duration::from_millis(500)
    }
}
