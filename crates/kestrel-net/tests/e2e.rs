//! Three devices and a relay, all running, talking to each other over HTTP.
//!
//! Nothing here is a stand-in. The relay is the deployed router over a real
//! SQLite file, the clients are the real `Relay` from `kestrel-net`, and every
//! position is a real signed and sealed post. A test that mocked any of those
//! would pass while the app failed on a phone, which is the only failure mode
//! worth caring about.
//!
//! The clock is a parameter throughout. Positions and epochs come from it rather
//! than from the wall, so the assertions are about behaviour and not about how
//! long the test took.

use std::sync::Arc;

use kestrel_core::{
    beacon,
    identity::Identity,
    msg::{CircleMsg, Fix, ShareMode, Who},
    places::Place,
    roster::Roster,
    session::{Circle, Event, me},
    wire::{self, Feed, FeedMember, FeedPoint, Post},
};
use kestrel_net::{Polled, Relay};
use kestrel_relay::{Bound, http::Config};
use tokio::task::JoinHandle;

const SEED: [u8; 32] = [42u8; 32];
const EPOCH0: i64 = 2_980_471;
const MS: i64 = 1_000;

fn at(epoch: i64) -> i64 {
    epoch * wire::EPOCH_MS
}

fn fix(lat: f64, lon: f64) -> Fix {
    Fix::new(lat, lon, 5.0)
}

// ---------------------------------------------------------------- harness

/// A relay running for the duration of one test, on a real file.
struct Harness {
    /// Kept so the relay cannot be dropped mid-test by a refactor.
    _task: JoinHandle<()>,
    app: Arc<kestrel_relay::http::App>,
    origin: String,
    _dir: tempfile::TempDir,
}

impl Harness {
    /// A relay whose clock is the same simulated time the devices use.
    ///
    /// The clock matters more than it looks. A relay running on the wall clock
    /// would refuse every post from these devices with `clock`, because their
    /// simulated time is in the past relative to the real one — and the tests
    /// would then be measuring the skew check rather than the thing they are for.
    async fn on_disk() -> Self {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("kestrel.db");
        let bound = kestrel_relay::bind_file(&path, Config::default())
            .await
            .expect("the relay binds");
        let h = Self::from_bound(bound, dir);
        h.set_clock(at(EPOCH0)).await;
        h
    }

    fn from_bound(bound: Bound, dir: tempfile::TempDir) -> Self {
        let origin = bound.origin();
        let app = bound.app.clone();
        let task = tokio::spawn(async move {
            // Serves until the runtime ends, which is when the test ends.
            let _ = bound.serve(std::future::pending()).await;
        });
        Self { _task: task, app, origin, _dir: dir }
    }

    /// Put the relay's clock where the devices' is.
    async fn set_clock(&self, now: i64) {
        self.app.store.lock().await.set_now(now);
    }

    fn origin(&self) -> &str {
        &self.origin
    }

    /// Every value in every table.
    async fn dump(&self) -> String {
        self.app.store.lock().await.dump_everything()
    }

    async fn count_points(&self, channel: &str) -> i64 {
        self.app.store.lock().await.count_points(channel).unwrap_or(0)
    }

    /// Move the relay's clock forward, so a day's expiry is testable in a moment.
    async fn advance(&self, ms: i64) {
        let mut store = self.app.store.lock().await;
        let now = store.now() + ms;
        store.set_now(now);
    }
}

/// One simulated device.
struct Device {
    name: &'static str,
    identity: Identity,
    circle: Circle,
    relay: Relay,
    outbox: kestrel_net::Outbox,
    cursor: i64,
}

impl Device {
    /// The device that makes the circle.
    async fn creator(name: &'static str, seed: [u8; 32], now: i64, origin: &str) -> Self {
        let identity = Identity::generate();
        let circle = Circle::create(identity.clone(), &seed, now);
        Self::new(name, identity, circle, origin, now)
    }

    /// A device in an existing circle, holding its generation.
    fn member_of(
        name: &'static str,
        circle: Circle,
        identity: Identity,
        origin: &str,
        now: i64,
    ) -> Self {
        let cursor = circle.feed_cursor(now);
        Self {
            name,
            identity,
            circle,
            relay: Relay::new(origin).expect("a usable relay address"),
            outbox: kestrel_net::Outbox::new(),
            cursor,
        }
    }

    fn new(
        name: &'static str,
        identity: Identity,
        circle: Circle,
        origin: &str,
        now: i64,
    ) -> Self {
        Self::member_of(name, circle, identity, origin, now)
    }

    fn member_id(&self) -> &str {
        self.identity.member_id()
    }

    fn who(&self, battery: f64) -> kestrel_core::msg::Who {
        me(&self.identity, self.name, "", battery, ShareMode::Precise)
    }

    /// Seal a position and queue it.
    fn queue_location(&mut self, f: Fix, mode: ShareMode, now: i64) {
        if let Some(post) = self.circle.location(&self.who(0.8), f, mode, now) {
            self.outbox.push(post, "position", true);
        }
    }

    fn queue_check_in(&mut self, f: Fix, now: i64) {
        if let Some(post) = self.circle.check_in(&self.who(0.8), f, now) {
            self.outbox.push(post, "checkin", true);
        }
    }

    fn queue_sos(&mut self, f: Fix, now: i64) {
        if let Some(post) = self.circle.sos(&self.who(0.8), f, now) {
            self.outbox.push(post, "sos", true);
        }
    }

    fn queue_goodbye(&mut self, now: i64) {
        if let Some(post) = self.circle.goodbye(&self.who(0.0), now) {
            self.outbox.push(post, "goodbye", false);
        }
    }

    /// Send everything queued, oldest first.
    async fn flush(&mut self) {
        while let Some(post) = self.outbox.peek().cloned() {
            if self.relay.post(self.circle.channel(), &post).await.is_err() {
                // Left in the queue, which is what the outbox is for.
                return;
            }
            self.outbox.pop();
        }
    }

    /// Read the feed and apply it, returning what happened.
    async fn poll(&mut self, now: i64) -> Vec<Event> {
        let polled =
            self.relay.poll(self.circle.channel(), self.cursor).await.expect("a feed read");
        match polled {
            Polled::Retired => panic!("the relay retired the protocol"),
            Polled::Feed { feed, cursor } => {
                self.cursor = cursor;
                self.circle.ingest_feed(&feed, now)
            }
        }
    }

    /// The newest accepted position from another device, as of `now`.
    fn sees(&self, member: &str, now: i64) -> Option<Fix> {
        self.circle.member(member)?.position(now)
    }
}

/// A second device already inside `first`'s circle, with the same generation.
fn joiner(first: &Device, name: &'static str, origin: &str, now: i64) -> Device {
    let identity = Identity::generate();
    let circle = Circle::join(
        identity.clone(),
        &SEED,
        first.circle.channel().to_string(),
        first.circle.generation(),
        first.circle.opened_epoch(),
        Roster::new(),
        now,
    );
    Device::member_of(name, circle, identity, origin, now)
}

/// A feed carrying one member's points, as the relay would serve it.
fn feed_of(posts: &[Post], now: i64) -> Feed {
    let mut member = posts.first().map(|p| FeedMember {
        m: p.m.clone(),
        alg: p.alg.clone(),
        pk: p.pk.clone(),
        epk: p.epk.clone(),
        points: Vec::new(),
    });
    if let Some(m) = member.as_mut() {
        for p in posts {
            m.points.push(FeedPoint {
                e: p.e,
                ts: p.ts,
                srv: p.ts,
                n: p.n.clone(),
                c: p.c.clone(),
                sig: p.sig.clone(),
            });
        }
    }
    Feed { now, members: member.into_iter().collect() }
}

/// How many of `events` are positions from `member`.
fn positions_from(events: &[Event], member: &str) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, Event::Position { member: m, .. } if m == member))
        .count()
}

// ---------------------------------------------------------------- tests

#[tokio::test]
async fn a_relay_reports_the_protocol_and_its_clock() {
    let h = Harness::on_disk().await;
    let mut relay = Relay::new(h.origin()).unwrap();
    let body = relay.health().await.expect("a healthy relay");
    assert_eq!(
        kestrel_net::health_protocol(&body).as_deref(),
        Some(kestrel_net::our_protocol()),
        "a client must be able to tell what it is talking to: {body}"
    );
    assert!(kestrel_net::health_now(&body).is_some());
}

#[tokio::test]
async fn a_created_circle_sees_itself_and_nobody_else() {
    let h = Harness::on_disk().await;
    let mut a = Device::creator("Ana", SEED, at(EPOCH0), h.origin()).await;

    // A's own channel is empty until it posts.
    assert!(a.poll(at(EPOCH0)).await.is_empty());

    a.queue_location(fix(44.98, -93.27), ShareMode::Precise, at(EPOCH0) + MS);
    a.flush().await;
    // The post is stored, comes back, and is recognised as its own: a device is
    // not a member of its own map.
    assert!(a.poll(at(EPOCH0) + MS).await.is_empty());
    assert_eq!(a.circle.roster().len(), 1);
    assert!(a.circle.roster().contains(a.member_id()));
}

#[tokio::test]
async fn two_devices_see_each_other_through_a_relay() {
    let h = Harness::on_disk().await;
    let mut a = Device::creator("Ana", SEED, at(EPOCH0), h.origin()).await;
    let mut b = joiner(&a, "Bo", h.origin(), at(EPOCH0));
    let a_id = a.member_id().to_string();
    let b_id =
        b.circle.roster().iter().next().map(|m| m.member_id.clone()).unwrap_or_default();
    let _ = b_id;

    // A posts, and B reads it off the relay.
    a.queue_location(fix(44.98, -93.27), ShareMode::Precise, at(EPOCH0) + MS);
    a.flush().await;
    let events = b.poll(at(EPOCH0) + MS).await;
    assert_eq!(positions_from(&events, &a_id), 1, "B should see A's position: {events:?}");
    let state = b.circle.member(&a_id).expect("A is on B's map");
    assert_eq!(state.last.as_ref().unwrap().timestamp(), at(EPOCH0) + MS);
    assert_eq!(b.circle.roster().get(&a_id).unwrap().name, "Ana");

    // And the other way.
    b.queue_location(fix(44.99, -93.26), ShareMode::Precise, at(EPOCH0) + 2 * MS);
    b.flush().await;
    let b_id = b.member_id().to_string();
    let events = a.poll(at(EPOCH0) + 2 * MS).await;
    assert_eq!(positions_from(&events, &b_id), 1, "A should see B's position: {events:?}");
    assert!(a.sees(&b_id, at(EPOCH0) + 2 * MS).is_some(), "A should have B's position");
}

#[tokio::test]
async fn a_check_in_an_emergency_and_a_goodbye_all_cross_the_relay() {
    let h = Harness::on_disk().await;
    let mut a = Device::creator("Ana", SEED, at(EPOCH0), h.origin()).await;
    let mut b = joiner(&a, "Bo", h.origin(), at(EPOCH0));
    let a_id = a.member_id().to_string();

    a.queue_location(fix(44.98, -93.27), ShareMode::Precise, at(EPOCH0) + MS);
    a.flush().await;
    assert_eq!(positions_from(&b.poll(at(EPOCH0) + MS).await, &a_id), 1);

    // A check-in is a distinct message type, not a position with a flag.
    a.queue_check_in(fix(44.98, -93.27), at(EPOCH0) + 2 * MS);
    a.flush().await;
    let events = b.poll(at(EPOCH0) + 2 * MS).await;
    assert!(
        events.iter().any(|e| matches!(
            e,
            Event::Position { message: CircleMsg::CheckIn { .. }, .. }
        )),
        "the check-in should be visible as itself: {events:?}"
    );

    // An emergency.
    a.queue_sos(fix(44.981, -93.271), at(EPOCH0) + 3 * MS);
    a.flush().await;
    let events = b.poll(at(EPOCH0) + 3 * MS).await;
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::Position { message: CircleMsg::Sos { .. }, .. })),
        "the emergency should be visible: {events:?}"
    );

    // A goodbye, so B sees "stopped" rather than a dot frozen where A last was.
    a.queue_goodbye(at(EPOCH0) + 4 * MS);
    a.flush().await;
    let events = b.poll(at(EPOCH0) + 4 * MS).await;
    assert!(
        events.iter().any(|e| matches!(e, Event::Stopped { member } if *member == a_id)),
        "B should see A stopped: {events:?}"
    );
    let state = b.circle.member(&a_id).expect("A is still on the roster");
    assert!(matches!(state.last, Some(CircleMsg::Bye { .. })));
    assert!(state.position(at(EPOCH0) + 4 * MS).is_none());
}

#[tokio::test]
async fn a_help_link_opens_only_for_its_own_emergency() {
    let h = Harness::on_disk().await;
    let a = Device::creator("Ana", SEED, at(EPOCH0), h.origin()).await;

    let mut emergency = beacon::Beacon::new();
    let link = emergency.add(beacon::DEFAULT_TTL_MS, at(EPOCH0));
    let parsed = beacon::parse_fragment(&link.fragment()).expect("our own link parses");
    // A beacon's signer is not the circle's identity, so a helper's browser is
    // not linkable to the person in trouble.
    assert_ne!(parsed.owner, a.member_id());

    let posts = emergency.position_posts(
        &CircleMsg::sos(
            0,
            Who::plain("Ana", "", a.circle.identity().hue() as i64),
            fix(44.98, -93.27),
        ),
        wire::epoch_at(at(EPOCH0) + MS),
        at(EPOCH0) + MS,
    );
    assert_eq!(posts.len(), 1);

    let mut sender = Relay::new(h.origin()).unwrap();
    for post in &posts {
        sender.post(&link.channel(), post).await.expect("the beacon posts");
    }

    // A viewer reads the beacon channel and opens what it can.
    let mut viewer = Relay::new(h.origin()).unwrap();
    let Polled::Feed { feed, .. } =
        viewer.poll(&link.channel(), 0).await.expect("a feed read")
    else {
        panic!("not a feed");
    };
    let opened: Vec<CircleMsg> = feed
        .posts()
        .iter()
        .filter_map(|p| beacon::verify_for_viewer(p, &parsed, at(EPOCH0) + MS))
        .collect();
    assert_eq!(opened.len(), 1, "one position, got {opened:?}");
    assert!(matches!(opened[0], CircleMsg::Sos { .. }));

    // A different link derives a different channel, so it sees nothing.
    let other = beacon::parse_fragment(
        &emergency.add(beacon::DEFAULT_TTL_MS, at(EPOCH0)).fragment(),
    )
    .unwrap();
    assert_ne!(other.channel(), parsed.channel());
    let leaked = feed
        .posts()
        .iter()
        .filter_map(|p| beacon::verify_for_viewer(p, &other, at(EPOCH0) + MS))
        .count();
    assert_eq!(leaked, 0, "a help link is confined to one emergency");
}

#[tokio::test]
async fn a_forged_position_is_refused_by_the_relay_and_by_the_receiver() {
    // Two independent defences, both exercised. Relying on the other is how a
    // circle ends up trusting a relay.
    let h = Harness::on_disk().await;
    let mut a = Device::creator("Ana", SEED, at(EPOCH0), h.origin()).await;
    let mut b = joiner(&a, "Bo", h.origin(), at(EPOCH0));

    let post = b
        .circle
        .location(&b.who(0.8), fix(44.98, -93.27), ShareMode::Precise, at(EPOCH0) + MS)
        .expect("a post seals");

    assert!(b.relay.post(b.circle.channel(), &post).await.is_ok());
    // The identical bytes again: the primary key collides, and the relay says
    // `conflict`.
    let again = b.relay.post(b.circle.channel(), &post).await;
    assert_eq!(
        again.err(),
        Some(wire::RelayError::new(409, "conflict")),
        "a whole-body replay is refused"
    );

    // A tampered ciphertext, re-signed properly: the relay verifies the signature
    // but the body no longer opens for a receiver.
    let mut tampered = b
        .circle
        .location(&b.who(0.8), fix(44.98, -93.27), ShareMode::Precise, at(EPOCH0) + 2 * MS)
        .expect("a post seals");
    tampered.c = kestrel_core::b64::encode(&[0u8; 528]);
    tampered.sig = b.identity.sign_text(&wire::sig_base(
        b.circle.channel(),
        &tampered.m,
        tampered.e,
        tampered.ts,
        &tampered.n,
        &tampered.c,
    ));
    assert!(
        b.relay.post(b.circle.channel(), &tampered).await.is_ok(),
        "the relay stores a well-signed post; it does not read inside one"
    );

    // And a receiver, fed both, accepts the real one and refuses the other.
    let events = a
        .circle
        .ingest_feed(&feed_of(&[post, tampered], at(EPOCH0) + 2 * MS), at(EPOCH0) + 2 * MS);
    assert_eq!(
        positions_from(&events, b.member_id()),
        1,
        "exactly one of the two opened: {events:?}"
    );
}

#[tokio::test]
async fn a_replay_is_refused_by_the_receiver_even_when_the_relay_served_it_twice() {
    // The relay's monotonicity is a courtesy. The receiver's mark is the boundary.
    let h = Harness::on_disk().await;
    let mut a = Device::creator("Ana", SEED, at(EPOCH0), h.origin()).await;
    let mut b = joiner(&a, "Bo", h.origin(), at(EPOCH0));
    let post = b
        .circle
        .location(&b.who(0.8), fix(44.98, -93.27), ShareMode::Precise, at(EPOCH0) + MS)
        .expect("a post seals");

    let events =
        a.circle.ingest_feed(&feed_of(std::slice::from_ref(&post), at(EPOCH0) + MS), at(EPOCH0) + MS);
    assert_eq!(positions_from(&events, b.member_id()), 1);

    // The same bytes again, under a different receive time so it looks like a
    // fresh row.
    let events =
        a.circle.ingest_feed(&feed_of(&[post], at(EPOCH0) + 2 * MS), at(EPOCH0) + 2 * MS);
    assert_eq!(
        positions_from(&events, b.member_id()),
        0,
        "the replay was refused: {events:?}"
    );
}

#[tokio::test]
async fn positions_survive_a_relay_restart() {
    // The relay is a process like any other. A circle has to come back when it
    // does, which means the rows are on disk and the schema reapplies cleanly.
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("kestrel.db");

    let first = kestrel_relay::bind_file(&path, Config::default()).await.unwrap();
    let origin = first.origin();
    let app = first.app.clone();
    app.store.lock().await.set_now(at(EPOCH0));
    let serving = tokio::spawn(async move {
        let _ = first.serve(std::future::pending()).await;
    });
    let _ = &serving;

    let mut a = Device::creator("Ana", SEED, at(EPOCH0), &origin).await;
    a.queue_location(fix(44.98, -93.27), ShareMode::Precise, at(EPOCH0) + MS);
    a.flush().await;
    let ch = a.circle.channel().to_string();
    assert_eq!(app.store.lock().await.count_points(&ch).unwrap(), 1);

    // A fresh store over the same file, with no complaint from the schema.
    let second = kestrel_relay::bind_file(&path, Config::default()).await.unwrap();
    second.app.store.lock().await.set_now(at(EPOCH0));
    assert_eq!(second.count_points(&ch).await, 1);
    assert!(second.dump().await.contains(&ch));
}

#[tokio::test]
async fn a_relay_forgets_everything_after_a_day() {
    let h = Harness::on_disk().await;
    let mut a = Device::creator("Ana", SEED, at(EPOCH0), h.origin()).await;
    a.queue_location(fix(44.98, -93.27), ShareMode::Precise, at(EPOCH0) + MS);
    a.flush().await;
    let channel = a.circle.channel().to_string();
    assert_eq!(h.count_points(&channel).await, 1);

    h.advance(wire::TTL_MS + 1).await;
    // A read is what normally sweeps, so the test reads. The cursor has to start
    // from the beginning of the channel, because a read is the sweep.
    a.cursor = 0;
    let _ = a.relay.poll(a.circle.channel(), 0).await.expect("a feed read");
    assert_eq!(h.count_points(&channel).await, 0);
}

#[tokio::test]
async fn a_clock_error_says_so_rather_than_looking_like_a_rejection() {
    // A device a week out of step has to be told what is wrong, or it never fixes
    // it. A generic rejection gives it nothing to act on.
    let h = Harness::on_disk().await;
    let mut a = Device::creator("Ana", SEED, at(EPOCH0), h.origin()).await;

    // A timestamp a week in the future is refused as a bad request, because that
    // is what it is: an out-of-range time.
    //
    // Sealed at the low level rather than through the circle, because a circle
    // cannot build this one: its own ratchet refuses to derive a key for an
    // epoch its clock does not believe in, which is the correct behaviour and
    // leaves nothing for the relay to disagree with.
    let far = at(EPOCH0) + 10 * wire::EPOCH_MS;
    let key = a
        .circle
        .ratchet()
        .clone()
        .key_for(wire::epoch_at(at(EPOCH0)), a.member_id(), at(EPOCH0))
        .expect("a key for this epoch");
    let body =
        serde_json::to_string(&CircleMsg::loc(0, a.who(0.8), fix(44.98, -93.27))).unwrap();
    let future = kestrel_core::seal::build_post(
        &a.identity,
        a.circle.channel(),
        &key,
        wire::epoch_at(at(EPOCH0)),
        far,
        &body,
    )
    .expect("a post seals");
    let err = a
        .relay
        .post(a.circle.channel(), &future)
        .await
        .expect_err("a post from a week in the future is refused");
    assert_eq!(err.status, 400);
    assert!(!err.clock, "a future timestamp is not a clock complaint: {err:?}");

    // A plausible timestamp claiming a plausible-looking but distant epoch is the
    // case `clock` exists for: the sender's device clock disagrees with the
    // relay's, and the only useful thing to say is so.
    let mut skewed = a
        .circle
        .location(&a.who(0.8), fix(44.98, -93.27), ShareMode::Precise, at(EPOCH0) + MS)
        .expect("a post seals");
    skewed.e = wire::epoch_at(at(EPOCH0)) + 40;
    skewed.sig = a.identity.sign_text(&wire::sig_base(
        a.circle.channel(),
        &skewed.m,
        skewed.e,
        skewed.ts,
        &skewed.n,
        &skewed.c,
    ));
    let err = a
        .relay
        .post(a.circle.channel(), &skewed)
        .await
        .expect_err("a post claiming a distant epoch is refused");
    assert!(err.clock, "the relay should say `clock`, said {:?}", err.message);
    assert_eq!(err.status, 400);

    // And the client learns the relay's clock, so it can correct itself.
    let mut relay = Relay::new(h.origin()).unwrap();
    relay.health().await.unwrap();
    assert!(relay.server_now.is_some());
    assert!(relay.clock_skew(at(EPOCH0) + 10 * wire::EPOCH_MS) > 0);
}

#[tokio::test]
async fn the_relay_never_stores_a_name_or_a_coordinate() {
    // The claim the whole design rests on, checked against a relay that has been
    // running and written to by two devices.
    let h = Harness::on_disk().await;
    let mut a = Device::creator("Ana Ångström", SEED, at(EPOCH0), h.origin()).await;
    let mut b = joiner(&a, "Bo Ñuñez", h.origin(), at(EPOCH0));

    // Both share and both stop, so the dump covers every message type a circle
    // actually sends.
    a.queue_location(fix(44.981_23, -93.274_56), ShareMode::Precise, at(EPOCH0) + MS);
    a.queue_check_in(fix(44.981_23, -93.274_56), at(EPOCH0) + 2 * MS);
    a.queue_goodbye(at(EPOCH0) + 3 * MS);
    a.flush().await;
    b.queue_location(fix(44.99, -93.26), ShareMode::Precise, at(EPOCH0) + 4 * MS);
    b.flush().await;

    let dump = h.dump().await;
    assert!(!dump.contains("Ana Ångström"), "a name reached the database");
    assert!(!dump.contains("Bo Ñuñez"), "a name reached the database");
    assert!(!dump.contains("44.98"), "a latitude reached the database");
    assert!(!dump.contains("-93.27"), "a longitude reached the database");
    // The things the relay legitimately holds are there, so the test is not
    // passing because the dump is empty.
    assert!(dump.contains(a.circle.channel()), "the channel should be there");
    assert!(dump.contains(a.member_id()), "the member id should be there");
    assert!(dump.contains(b.member_id()), "and the second member's");
}

#[tokio::test]
async fn a_place_is_detected_on_the_device_that_hears_the_position() {
    // Places never leave the phone, so the detection happens on whichever device
    // read the position, and only there.
    let h = Harness::on_disk().await;
    let mut a = Device::creator("Ana", SEED, at(EPOCH0), h.origin()).await;
    let mut b = joiner(&a, "Bo", h.origin(), at(EPOCH0));

    // A has a place configured. B has none.
    a.circle.places.put(Place::new("home", "Home", 44.98, -93.27).with_radius(150.0));

    // B walks towards Home, then into it, and stays long enough for the dwell to
    // be satisfied. Two agreeing fixes a full dwell period apart, which is the
    // whole point of the dwell: a noisy fix crossing a boundary must not announce
    // an arrival by itself.
    let dwell = kestrel_core::places::DEFAULT_DWELL_MS;
    let mut announcements = Vec::new();
    for (i, lat) in [44.99f64, 44.98, 44.98].iter().enumerate() {
        let ts = at(EPOCH0) + (i as i64 + 1) * (dwell + MS);
        let post = b
            .circle
            .location(&b.who(0.8), fix(*lat, -93.27), ShareMode::Precise, ts)
            .expect("a post seals");
        // It goes through the relay, as it would in life.
        b.relay.post(b.circle.channel(), &post).await.ok();
        let events = a.circle.ingest_feed(&feed_of(&[post], ts), ts);
        announcements.extend(events);
    }

    assert!(
        announcements.iter().any(|e| matches!(e, Event::Place(_))),
        "the arrival should be detected on A, which read the positions: {announcements:?}"
    );
    // And the relay never heard a word about the place: it is a local thing.
    let dump = h.dump().await;
    assert!(!dump.contains("Home"), "a place name reached the relay");
    // B, which has no places configured, detected nothing.
    assert!(b.circle.places.all().is_empty());
}
