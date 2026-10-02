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
    pub fn offer_position(&self, circle: &Arc<std::sync::Mutex<Circle>>) -> bool {
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
        let last =
            self.last_queued.lock().ok().and_then(|slot| slot.filter(|f| f.ts != fix.ts));

        let Ok(mut circle) = circle.lock() else {
            return false;
        };
        let Some(post) =
            logic::build_post(&mut circle, &fix, &permissions, &name, last.as_ref())
        else {
            return false;
        };
        if let Ok(mut slot) = self.last_queued.lock() {
            *slot = Some(fix);
        }
        self.push(post, "position", true);
        true
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
    pub async fn poll(
        &self,
        circle: &Arc<std::sync::Mutex<Circle>>,
        now: i64,
    ) -> Result<usize, String> {
        let channel = self.channel();
        if channel.is_empty() {
            return Err("no circle attached".to_string());
        }
        let since = self.cursor.lock().map(|c| *c).unwrap_or(0);
        let feed = self.sink.fetch(&channel, since).await?;
        let Ok(mut circle) = circle.lock() else {
            return Err("the circle is locked".to_string());
        };
        let events = circle.ingest_feed(&feed, now);
        let count = events.len();
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
    use super::*;
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

    fn a_circle() -> Arc<Mutex<Circle>> {
        let identity = kestrel_core::identity::Identity::generate();
        let seed = kestrel_core::seal::random_bytes::<32>();
        Arc::new(Mutex::new(Circle::create(identity, &seed, 1_700_000_000_000)))
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
        let engine = Engine::new(Arc::new(Shared::default()), sink.clone());
        let circle = a_circle();
        engine.attach(circle.lock().unwrap().channel());
        let post = post_for(
            &mut circle.lock().unwrap(),
            &fix(1_700_000_001_000),
            &permitted(),
            "Ada",
        )
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
            Some(circle.lock().unwrap().channel()),
            "the post went somewhere other than the circle's channel"
        );
    }

    #[test]
    fn a_relay_that_is_down_keeps_the_post() {
        // The whole reason the outbox exists. A position dropped because the network was
        // down is a hole in the circle's picture of someone.
        let sink = Fake::new();
        *sink.fail_send.lock().unwrap() = true;
        let engine = Engine::new(Arc::new(Shared::default()), sink.clone());
        let circle = a_circle();
        engine.attach(circle.lock().unwrap().channel());
        let post = post_for(
            &mut circle.lock().unwrap(),
            &fix(1_700_000_001_000),
            &permitted(),
            "Ada",
        )
        .unwrap();
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
        let engine = Engine::new(Arc::new(Shared::default()), sink.clone());
        let circle = a_circle();
        engine.attach(circle.lock().unwrap().channel());
        for step in 0..40 {
            let post = post_for(
                &mut circle.lock().unwrap(),
                &fix(1_700_000_001_000 + step * 15_000),
                &permitted(),
                "Ada",
            )
            .unwrap();
            engine.push(post, "position", true);
        }
        assert_eq!(engine.queued(), 1, "positions were not coalesced");
        // And a goodbye is not coalescible: its meaning cannot be carried by a later one.
        let goodbye = kestrel_core::msg::CircleMsg::bye(
            0,
            kestrel_core::session::me(
                circle.lock().unwrap().identity(),
                "Ada",
                "",
                0.8,
                ShareMode::Precise,
            ),
        );
        let post = circle.lock().unwrap().seal(&goodbye, 1_700_000_002_000);
        if let Some(post) = post {
            engine.push(post, "goodbye", false);
        }
        assert_eq!(engine.queued(), 2);
    }

    #[test]
    fn a_failed_send_does_not_wedge_the_engine() {
        // A flag left set after a failure would mean the second flush silently did
        // nothing, forever.
        let sink = Fake::new();
        let engine = Engine::new(Arc::new(Shared::default()), sink.clone());
        let circle = a_circle();
        engine.attach(circle.lock().unwrap().channel());
        *sink.fail_send.lock().unwrap() = true;
        let post = post_for(
            &mut circle.lock().unwrap(),
            &fix(1_700_000_001_000),
            &permitted(),
            "Ada",
        )
        .unwrap();
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
            engine.poll(&a_circle(), 1_700_000_000_000).await.ok();
        });
        engine.attach("bbbbbbbb");
        let circle = a_circle();
        block_on(async { engine.poll(&circle, 1_700_000_000_000).await }).ok();
        let asked = sink.channels();
        assert_eq!(asked.first().map(|s| s.as_str()), Some("aaaaaaaa"));
        assert_eq!(asked.last().map(|s| s.as_str()), Some("bbbbbbbb"));
    }

    #[test]
    fn a_poll_advances_the_cursor_and_folds_the_feed() {
        // A cursor that does not advance re-fetches the same window every fifteen seconds
        // for the life of the app.
        let sink = Fake::new();
        let engine = Engine::new(Arc::new(Shared::default()), sink.clone());
        let circle = a_circle();
        engine.attach(circle.lock().unwrap().channel());
        sink.set_feed(kestrel_core::wire::Feed {
            now: 1_700_000_060_000,
            members: Vec::new(),
        });
        block_on(async {
            engine.poll(&circle, 1_700_000_060_000).await.ok();
        });
        assert_eq!(engine.cursor.lock().unwrap().to_owned(), 1_700_000_060_000);

        // And a feed the relay stamps with an *older* clock than we already have does not
        // rewind the cursor, which would re-deliver everything after it.
        sink.set_feed(kestrel_core::wire::Feed {
            now: 1_000_000_000_000,
            members: Vec::new(),
        });
        block_on(async {
            engine.poll(&circle, 1_700_000_060_000).await.ok();
        });
        assert_eq!(engine.cursor.lock().unwrap().to_owned(), 1_700_000_060_000);
    }

    #[test]
    fn a_relay_that_is_down_does_not_move_the_cursor() {
        // The failure case that matters: a failed fetch must leave the cursor alone, or
        // the posts that were missed while it was down are never fetched.
        let sink = Fake::new();
        *sink.fail_fetch.lock().unwrap() = true;
        let engine = Engine::new(Arc::new(Shared::default()), sink.clone());
        let circle = a_circle();
        engine.attach(circle.lock().unwrap().channel());
        assert!(block_on(async { engine.poll(&circle, 1).await }).is_err());
        assert_eq!(engine.cursor.lock().unwrap().to_owned(), 0);
    }

    #[test]
    fn a_wiped_device_sends_nothing_queued() {
        // A duress wipe with a queue full of positions would post them on the next
        // launch, from a key the user believes is gone.
        let sink = Fake::new();
        let engine = Engine::new(Arc::new(Shared::default()), sink.clone());
        let circle = a_circle();
        let post = post_for(
            &mut circle.lock().unwrap(),
            &fix(1_700_000_001_000),
            &permitted(),
            "Ada",
        )
        .unwrap();
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
        let circle = a_circle();
        let mut guard = circle.lock().unwrap();
        // A timestamp inside the circle's own epoch: the ratchet refuses a post from
        // before it was created, which is correct and is checked elsewhere.
        let now = 1_700_000_001_000;
        assert!(
            post_for(&mut guard, &fix(now), &permitted(), "Ada").is_some(),
            "a usable position should produce a post"
        );
        let zero = Fix { lat: 0.0, lon: 0.0, acc: 0.0, ts: now + 1000, battery: 0.0 };
        // The core refuses a null-island position outright, so nothing is queued rather
        // than a marker appearing in the Gulf of Guinea.
        assert!(post_for(&mut guard, &zero, &permitted(), "Ada").is_none());
    }

    /// Runs a future to completion without a runtime.
    ///
    /// A test-only executor rather than tokio: the engine's own tests should not need an
    /// async runtime to check that a queue drains.
    fn block_on<F: std::future::Future>(mut future: F) -> F::Output {
        use std::task::{Context, Poll, Waker};
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        // SAFETY: nothing is shared across threads here; the future is polled to
        // completion on this one and then dropped.
        let mut future = unsafe { std::pin::Pin::new_unchecked(&mut future) };
        loop {
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}
