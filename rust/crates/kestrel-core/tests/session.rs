//! The client state machine, driven the way a circle actually uses it.
//!
//! Each test builds a real circle with a real keypair, seals real posts, and
//! reads them through the same `ingest` path a phone uses. Nothing is stubbed,
//! because the interesting failures are all in the interaction between the
//! cryptography and the ordering, and a stubbed key is exactly where that
//! interaction would be hidden.

use kestrel_core::{
    identity::Identity,
    kdf, msg,
    roster::Roster,
    session::{Circle, Event, Reject, me},
    wire::{self, Post},
};

// -------------------------------------------------------------- helpers

/// A fixed generation seed, so every device in a test derives the same channel.
fn seed() -> [u8; 32] {
    [7u8; 32]
}

fn channel_of(seed: &[u8; 32]) -> String {
    kdf::channel_id(&kdf::anchor(seed))
}

const EPOCH: i64 = wire::EPOCH_MS;

fn at(epoch: i64) -> i64 {
    epoch * EPOCH
}

/// A circle and its identity, plus a second device in the same circle.
struct Two {
    a_identity: Identity,
    a: Circle,
    b_identity: Identity,
    b: Circle,
}

fn a_pair(now: i64) -> Two {
    let a_identity = Identity::generate();
    let a = Circle::create(a_identity.clone(), &seed(), now);
    let b_identity = Identity::generate();
    // B joins the circle that A created, by being handed the same seed and
    // channel. The join handshake that would normally deliver them is covered
    // separately; what matters here is the state afterwards.
    let b = Circle::join(
        b_identity.clone(),
        &seed(),
        channel_of(&seed()),
        0,
        wire::epoch_at(now),
        Roster::new(),
        now,
    );
    Two { a_identity, a, b_identity, b }
}

fn fix() -> msg::Fix {
    msg::Fix::new(44.98, -93.27, 5.0)
}

/// Seal a post for an identity that is not a member of `circle`.
///
/// Needed for the negative tests: a stranger's post is built the same way as a
/// member's, on the same channel and under the same content key, so the only
/// thing that can refuse it is the check under test.
fn seal_as(identity: &Identity, circle: &Circle, body: &msg::CircleMsg, ts: i64) -> Post {
    let mut body = body.clone();
    match &mut body {
        msg::CircleMsg::Loc { ts: t, .. }
        | msg::CircleMsg::CheckIn { ts: t, .. }
        | msg::CircleMsg::Sos { ts: t, .. }
        | msg::CircleMsg::Bye { ts: t, .. }
        | msg::CircleMsg::ReKey { ts: t, .. } => *t = ts,
    }
    let json = serde_json::to_string(&body).unwrap();
    let key = kestrel_core::seal::ContentKey::new(kdf::msg_key(
        &kdf::chain0(&seed()),
        identity.member_id(),
    ));
    kestrel_core::seal::build_post(
        identity,
        circle.channel(),
        &key,
        wire::epoch_at(ts),
        ts,
        &json,
    )
    .expect("a post seals")
}

/// A stranger's position post on a circle's channel.
fn stranger_post(identity: &Identity, circle: &Circle, name: &str, ts: i64) -> Post {
    seal_as(
        identity,
        circle,
        &msg::CircleMsg::loc(
            0,
            me(identity, name, "", 0.5, msg::ShareMode::Precise),
            fix(),
        ),
        ts,
    )
}

// -------------------------------------------------------------- sending

#[test]
fn a_new_circle_derives_its_channel_from_its_seed() {
    let id = Identity::generate();
    let c = Circle::create(id.clone(), &seed(), at(2980471));
    assert_eq!(c.channel(), channel_of(&seed()));
    assert_eq!(c.generation(), 0);
    assert_eq!(c.opened_epoch(), 2980471);
    // This device is in its own roster: a re-key's roster hash is computed over a
    // view that includes it, and a device that had forgotten itself would compute
    // a different hash from everybody else.
    assert!(c.roster().contains(id.member_id()));
}

#[test]
fn a_sealed_post_verifies_and_opens() {
    let mut t = a_pair(at(2980471));
    let post =
        t.b.location(
            &me(&t.b_identity, "Bo", "", 0.8, msg::ShareMode::Precise),
            fix(),
            msg::ShareMode::Precise,
            at(2980471) + 1_000,
        )
        .expect("a post seals");

    let events =
        t.a.ingest_feed(&feed_of(&post), at(2980471) + 1_000)
            .into_iter()
            .filter(|e| matches!(e, Event::Position { .. }))
            .collect::<Vec<_>>();
    assert_eq!(events.len(), 1, "one position, got {events:?}");

    let state = t.a.member(t.b_identity.member_id()).expect("a member");
    assert_eq!(state.last.as_ref().unwrap().timestamp(), at(2980471) + 1_000);
    assert_eq!(state.trail.len(), 1);
    assert_eq!(t.a.roster().get(t.b_identity.member_id()).unwrap().name, "Bo");
}

#[test]
fn a_post_built_for_another_channel_does_not_open() {
    // The signature covers the channel, so a post lifted from one circle into
    // another fails here rather than being decrypted under a mismatched key.
    let mut t = a_pair(at(2980471));
    let other = Identity::generate();
    let mut other_circle = Circle::create(other.clone(), &[9u8; 32], at(2980471));
    let post = other_circle
        .location(
            &me(&other, "X", "", 0.5, msg::ShareMode::Precise),
            fix(),
            msg::ShareMode::Precise,
            at(2980471) + 1,
        )
        .unwrap();

    let before = t.a.roster().clone();
    assert_eq!(t.a.ingest(&post, &before, at(2980471) + 1), Err(Reject::BadSignature));
}

#[test]
fn our_own_post_coming_back_is_ignored() {
    let mut t = a_pair(at(2980471));
    let post =
        t.a.location(
            &me(&t.a_identity, "Ana", "", 0.9, msg::ShareMode::Precise),
            fix(),
            msg::ShareMode::Precise,
            at(2980471) + 1,
        )
        .unwrap();
    let before = t.a.roster().clone();
    assert_eq!(t.a.ingest(&post, &before, at(2980471) + 1), Err(Reject::OwnPost));
}

// -------------------------------------------------------------- replay

#[test]
fn the_exact_same_post_twice_is_refused_the_second_time() {
    // A whole-body replay. The signature and the ciphertext are the originals and
    // both verify, so what refuses it is the monotonicity mark.
    let mut t = a_pair(at(2980471));
    let ts = at(2980471) + 1_000;
    let post =
        t.b.location(
            &me(&t.b_identity, "Bo", "", 0.8, msg::ShareMode::Precise),
            fix(),
            msg::ShareMode::Precise,
            ts,
        )
        .unwrap();

    let before = t.a.roster().clone();
    assert!(t.a.ingest(&post, &before, ts).is_ok());
    assert_eq!(t.a.ingest(&post, &before, ts), Err(Reject::Replay));
}

#[test]
fn a_post_with_an_older_timestamp_is_refused() {
    // Hand-made, because the sender's own guard never emits a stale timestamp.
    // The receiver has to hold the line against a sender that tries to, since
    // nothing else in the protocol stops one.
    let mut t = a_pair(at(2980471));
    let first = seal_as(
        &t.b_identity,
        &t.a,
        &msg::CircleMsg::loc(
            0,
            me(&t.b_identity, "Bo", "", 0.8, msg::ShareMode::Precise),
            fix(),
        ),
        at(2980471) + 2_000,
    );
    let older = seal_as(
        &t.b_identity,
        &t.a,
        &msg::CircleMsg::loc(
            0,
            me(&t.b_identity, "Bo", "", 0.8, msg::ShareMode::Precise),
            fix(),
        ),
        at(2980471) + 1_000,
    );

    let before = t.a.roster().clone();
    assert!(t.a.ingest(&first, &before, at(2980471) + 2_000).is_ok());
    assert_eq!(t.a.ingest(&older, &before, at(2980471) + 2_000), Err(Reject::Replay));
}

#[test]
fn a_post_in_the_same_millisecond_is_refused() {
    // Two posts with an identical timestamp, hand-made. A hostile or buggy sender
    // can produce them even though the real one cannot: the `<=` in the mark is
    // what makes the second a replay rather than a tie, and without it two posts
    // in one millisecond would both be drawn.
    let mut t = a_pair(at(2980471));
    let ts = at(2980471) + 5_000;
    let body = msg::CircleMsg::loc(
        0,
        me(&t.b_identity, "B", "", 0.8, msg::ShareMode::Precise),
        fix(),
    );
    let a = seal_as(&t.b_identity, &t.a, &body, ts);
    let b = seal_as(&t.b_identity, &t.a, &body, ts);

    let before = t.a.roster().clone();
    assert!(t.a.ingest(&a, &before, ts).is_ok());
    assert_eq!(t.a.ingest(&b, &before, ts), Err(Reject::Replay));
}

#[test]
fn the_send_timestamp_strictly_increases() {
    // Two posts in the same millisecond must not share a timestamp, or the
    // receiver refuses the second as a replay.
    let mut t = a_pair(at(2980471));
    let now = at(2980471) + 1_000;
    let one =
        t.a.location(
            &me(&t.a_identity, "A", "", 0.5, msg::ShareMode::Precise),
            fix(),
            msg::ShareMode::Precise,
            now,
        )
        .unwrap();
    let two =
        t.a.location(
            &me(&t.a_identity, "A", "", 0.5, msg::ShareMode::Precise),
            fix(),
            msg::ShareMode::Precise,
            now,
        )
        .unwrap();
    assert!(two.ts > one.ts, "{} then {}", one.ts, two.ts);
    // And a third, so it is a real monotonic sequence rather than a one-off.
    let three =
        t.a.location(
            &me(&t.a_identity, "A", "", 0.5, msg::ShareMode::Precise),
            fix(),
            msg::ShareMode::Precise,
            now,
        )
        .unwrap();
    assert!(three.ts > two.ts);
}

#[test]
fn a_send_timestamp_never_goes_backwards_with_a_wrong_clock() {
    let mut t = a_pair(at(2980471));
    let now = at(2980471) + 1_000;
    let one =
        t.a.location(
            &me(&t.a_identity, "A", "", 0.5, msg::ShareMode::Precise),
            fix(),
            msg::ShareMode::Precise,
            now,
        )
        .unwrap();
    // The device's clock jumps backwards by five seconds.
    let two =
        t.a.location(
            &me(&t.a_identity, "A", "", 0.5, msg::ShareMode::Precise),
            fix(),
            msg::ShareMode::Precise,
            now - 5_000,
        )
        .unwrap();
    assert!(two.ts > one.ts, "{} then {}", one.ts, two.ts);
}

#[test]
fn a_replay_does_not_stop_a_newer_post() {
    let mut t = a_pair(at(2980471));
    let first =
        t.b.location(
            &me(&t.b_identity, "B", "", 0.8, msg::ShareMode::Precise),
            fix(),
            msg::ShareMode::Precise,
            at(2980471) + 1,
        )
        .unwrap();
    let newer =
        t.b.location(
            &me(&t.b_identity, "B", "", 0.8, msg::ShareMode::Precise),
            fix(),
            msg::ShareMode::Precise,
            at(2980471) + 2,
        )
        .unwrap();
    let before = t.a.roster().clone();
    assert!(t.a.ingest(&first, &before, at(2980471) + 1).is_ok());
    assert_eq!(t.a.ingest(&first, &before, at(2980471) + 1), Err(Reject::Replay));
    assert!(t.a.ingest(&newer, &before, at(2980471) + 2).is_ok());
}

// -------------------------------------------------------------- the roster

#[test]
fn a_new_member_is_admitted_and_announced() {
    let mut t = a_pair(at(2980471));
    let before = t.a.roster().clone();
    let post =
        t.b.location(
            &me(&t.b_identity, "Bo", "", 0.8, msg::ShareMode::Precise),
            fix(),
            msg::ShareMode::Precise,
            at(2980471) + 1,
        )
        .unwrap();
    let events = t.a.ingest(&post, &before, at(2980471) + 1).unwrap();
    assert!(
        events.iter().any(
            |e| matches!(e, Event::Joined { member } if member == t.b_identity.member_id())
        ),
        "got {events:?}"
    );
    assert!(t.a.roster().contains(t.b_identity.member_id()));
}

#[test]
fn a_key_change_is_refused_and_reported() {
    // A member id commits to both public keys, so a device cannot present a
    // different keypair under an id it already holds. The point is dropped and the
    // user is told, rather than the roster being quietly rewritten.
    let mut t = a_pair(at(2980471));
    let before = t.a.roster().clone();
    let good =
        t.b.location(
            &me(&t.b_identity, "Bo", "", 0.8, msg::ShareMode::Precise),
            fix(),
            msg::ShareMode::Precise,
            at(2980471) + 1,
        )
        .unwrap();
    assert!(t.a.ingest(&good, &before, at(2980471) + 1).is_ok());

    // The same member id, a different keypair, correctly signed by that keypair.
    let impostor = Identity::generate();
    let mut forged = stranger_post(&impostor, &t.a, "Not Bo", at(2980471) + 2);
    forged.m = t.b_identity.member_id().to_string();
    // Re-signed by the impostor over the claimed id, so the only thing that can
    // refuse it is the pinned key.
    forged.sig = impostor.sign_text(&wire::sig_base(
        t.a.channel(),
        &forged.m,
        forged.e,
        forged.ts,
        &forged.n,
        &forged.c,
    ));

    let before = t.a.roster().clone();
    assert_eq!(t.a.ingest(&forged, &before, at(2980471) + 2), Err(Reject::KeyChanged));
    // And the roster still holds the original keys.
    assert_eq!(
        t.a.roster().get(t.b_identity.member_id()).unwrap().pk,
        t.b_identity.pk_b64()
    );
}

#[test]
fn a_key_change_in_a_feed_is_reported_as_an_event() {
    let mut t = a_pair(at(2980471));
    let good =
        t.b.location(
            &me(&t.b_identity, "Bo", "", 0.8, msg::ShareMode::Precise),
            fix(),
            msg::ShareMode::Precise,
            at(2980471) + 1,
        )
        .unwrap();
    t.a.ingest_feed(&feed_of(&good), at(2980471) + 1);

    let impostor = Identity::generate();
    let mut forged = stranger_post(&impostor, &t.a, "Not Bo", at(2980471) + 2);
    forged.m = t.b_identity.member_id().to_string();
    forged.sig = impostor.sign_text(&wire::sig_base(
        t.a.channel(),
        &forged.m,
        forged.e,
        forged.ts,
        &forged.n,
        &forged.c,
    ));

    let events = t.a.ingest_feed(&feed_of(&forged), at(2980471) + 2);
    assert!(
        events.iter().any(|e| matches!(e, Event::KeyChanged { member } if member == t.b_identity.member_id())),
        "the user has to be told: {events:?}"
    );
}

#[test]
fn a_full_circle_admits_nobody_else() {
    // Sixteen on the relay, and this device holds fifteen others.
    let mut t = a_pair(at(2980471));
    let cap = kestrel_core::roster::LOCAL_CAP;
    for i in 0..(cap - 1) {
        let id = Identity::generate();
        let p = stranger_post(&id, &t.a, &format!("M{i}"), at(2980471) + i as i64 + 1);
        t.a.ingest_feed(&feed_of(&p), at(2980471) + i as i64 + 1);
    }
    assert_eq!(t.a.roster().len(), cap);

    let outsider = Identity::generate();
    let p = stranger_post(&outsider, &t.a, "Outsider", at(2980471) + 100);
    let before = t.a.roster().clone();
    assert!(matches!(
        t.a.ingest(&p, &before, at(2980471) + 100),
        Err(Reject::NotAdmissible(_))
    ),);
}

#[test]
fn a_post_admitting_its_own_author_does_not_authorise_itself() {
    // The order that matters: a re-key from a member who is not yet pinned is
    // refused, even though ingesting it is what would have pinned them. Judged
    // against the roster as it was *before* this pass, which is why `ingest` takes
    // it as a parameter.
    let mut t = a_pair(at(2980471));
    let stranger = Identity::generate();
    // A re-key from someone the circle has never seen, correctly signed and
    // correctly encrypted for this circle. The only thing that can refuse it is
    // the prior-pin check.
    let rekey_post = seal_as(
        &stranger,
        &t.a,
        &msg::CircleMsg::ReKey {
            v: msg::VERSION,
            ts: 0,
            g: 1,
            e0: 2980472,
            me: 2980472,
            to: t.a_identity.member_id().to_string(),
            eph: String::new(),
            w: String::new(),
            rm: vec![],
            rh: String::new(),
        },
        at(2980471) + 1,
    );

    // Not in the roster as it was before this pass.
    let before = t.a.roster().clone();
    assert!(!before.contains(stranger.member_id()));

    // Ingesting it admits the stranger, because a position from a stranger is
    // exactly what the roster is for. But the *control* message is judged against
    // the snapshot, so admitting the author does not authorise the re-key.
    let events = t.a.ingest(&rekey_post, &before, at(2980471) + 1);
    assert!(t.a.roster().contains(stranger.member_id()), "the stranger was admitted");
    assert_eq!(events, Err(Reject::StrangerControl), "but their re-key was still refused");
    // And the circle is on its original generation.
    assert_eq!(t.a.generation(), 0);
}

// -------------------------------------------------------------- the roster view

#[test]
fn the_roster_view_excludes_the_rotator_and_includes_self() {
    let mut t = a_pair(at(2980471));
    let before = t.a.roster().clone();
    let p =
        t.b.location(
            &me(&t.b_identity, "Bo", "", 0.8, msg::ShareMode::Precise),
            fix(),
            msg::ShareMode::Precise,
            at(2980471) + 1,
        )
        .unwrap();
    t.a.ingest(&p, &before, at(2980471) + 1).unwrap();

    // A re-key from A: the roster afterwards is everyone except A, plus A itself,
    // which is what every other device will converge on.
    let view = t.a.roster().roster_view(t.a_identity.member_id(), t.a_identity.member_id());
    assert!(view.contains(&t.a_identity.member_id().to_string()));
    assert!(view.contains(&t.b_identity.member_id().to_string()));
    assert_eq!(view.len(), 2, "no duplicates: {view:?}");
}

#[test]
fn the_next_roster_matches_what_a_rekey_would_expect() {
    let mut t = a_pair(at(2980471));
    let before = t.a.roster().clone();
    let p =
        t.b.location(
            &me(&t.b_identity, "Bo", "", 0.8, msg::ShareMode::Precise),
            fix(),
            msg::ShareMode::Precise,
            at(2980471) + 1,
        )
        .unwrap();
    t.a.ingest(&p, &before, at(2980471) + 1).unwrap();

    let removed = t.b_identity.member_id().to_string();
    let next = t.a.next_roster(None, std::slice::from_ref(&removed));
    assert!(!next.contains(&removed));
    assert!(next.contains(&t.a_identity.member_id().to_string()));
    // The hash a re-key carries, so every recipient can check they agree.
    let hash = kdf::roster_hash(&next);
    assert!(!hash.is_empty());
}

// -------------------------------------------------------------- goodbye

#[test]
fn a_goodbye_shows_as_stopped_rather_than_a_frozen_dot() {
    let mut t = a_pair(at(2980471));
    let pos =
        t.b.location(
            &me(&t.b_identity, "Bo", "", 0.8, msg::ShareMode::Precise),
            fix(),
            msg::ShareMode::Precise,
            at(2980471) + 1,
        )
        .unwrap();
    t.a.ingest_feed(&feed_of(&pos), at(2980471) + 1);

    let bye =
        t.b.goodbye(
            &me(&t.b_identity, "Bo", "", 0.0, msg::ShareMode::Precise),
            at(2980471) + 2,
        )
        .unwrap();
    let events = t.a.ingest_feed(&feed_of(&bye), at(2980471) + 2);
    assert!(
        events.iter().any(
            |e| matches!(e, Event::Stopped { member } if member == t.b_identity.member_id())
        ),
        "got {events:?}"
    );
    // And the state is a goodbye, so nothing draws a position.
    let state = t.a.member(t.b_identity.member_id()).unwrap();
    assert!(matches!(state.last, Some(msg::CircleMsg::Bye { .. })));
    assert!(state.position(at(2980471) + 2).is_none());
}

// -------------------------------------------------------------- coarse mode

#[test]
fn coarse_mode_rounds_before_encryption() {
    // The ciphertext is the coarse position. Rounding afterwards would leave the
    // exact one inside the sealed body.
    let mut t = a_pair(at(2980471));
    let precise = msg::Fix::new(44.981_23, -93.274_56, 5.0);
    let coarse_post =
        t.b.location(
            &me(&t.b_identity, "Bo", "", 0.8, msg::ShareMode::Coarse),
            precise,
            msg::ShareMode::Coarse,
            at(2980471) + 1,
        )
        .unwrap();
    let events = t.a.ingest_feed(&feed_of(&coarse_post), at(2980471) + 1);
    let position = events
        .iter()
        .find_map(|e| match e {
            Event::Position { message, .. } => message.fix(),
            _ => None,
        })
        .expect("a position");
    assert!((position.lat - precise.lat).abs() > 0.000_5, "not rounded: {position:?}");
    assert!(position.acc >= 1000.0, "accuracy must not claim better than it has");
}

// -------------------------------------------------------------- staleness

#[test]
fn a_member_goes_stale_after_three_minutes() {
    let mut t = a_pair(at(2980471));
    let pos =
        t.b.location(
            &me(&t.b_identity, "Bo", "", 0.8, msg::ShareMode::Precise),
            fix(),
            msg::ShareMode::Precise,
            at(2980471) + 1,
        )
        .unwrap();
    t.a.ingest_feed(&feed_of(&pos), at(2980471) + 1);
    let id = t.b_identity.member_id().to_string();
    assert!(t.a.member(&id).unwrap().is_live(at(2980471) + 1));
    assert!(t.a.member(&id).unwrap().is_live(at(2980471) + 1 + 3 * 60 * 1000));
    assert!(!t.a.member(&id).unwrap().is_live(at(2980471) + 1 + 3 * 60 * 1000 + 1));
    assert!(t.a.member(&id).unwrap().position(at(2980471) + 1).is_some());
    assert!(
        t.a.member(&id).unwrap().position(at(2980471) + 1 + 3 * 60 * 1000 + 1).is_none()
    );
}

#[test]
fn a_trail_is_bounded() {
    let mut t = a_pair(at(2980471));
    for i in 0..(wire::TRAIL_CAP as i64 + 5) {
        let ts = at(2980471) + i * 1_000;
        let p =
            t.b.location(
                &me(&t.b_identity, "Bo", "", 0.8, msg::ShareMode::Precise),
                fix(),
                msg::ShareMode::Precise,
                ts,
            )
            .unwrap();
        t.a.ingest(&p, &t.a.roster().clone(), ts).expect("a fresh position is accepted");
    }
    let state = t.a.member(t.b_identity.member_id()).unwrap();
    assert_eq!(state.trail.len(), wire::TRAIL_CAP);
    // The newest are the ones kept.
    assert_eq!(
        state.trail.last().unwrap().timestamp(),
        at(2980471) + (wire::TRAIL_CAP as i64 + 4) * 1_000
    );
}

// -------------------------------------------------------------- places

#[test]
fn arriving_at_a_place_is_announced() {
    let mut t = a_pair(at(2980471));
    t.a.places.put(
        kestrel_core::places::Place::new("home", "Home", 44.98, -93.27).with_radius(150.0),
    );

    // B starts outside, so the first inside fix is a crossing rather than a
    // first observation.
    let outside = msg::Fix::new(44.99, -93.27, 5.0);
    let far = at(2980471) + 1;
    let first = b_post(&mut t, &outside, far);
    t.a.ingest_feed(&feed_of(&first), far);

    let near = at(2980471) + 2;
    let crossing = b_post(&mut t, &fix(), near);
    t.a.ingest_feed(&feed_of(&crossing), near);

    // A full dwell period later, with a second agreeing fix, it concludes.
    let later = near + 60_000;
    let post = b_post(&mut t, &fix(), later);
    let events = t.a.ingest_feed(&feed_of(&post), later);
    assert!(
        events.iter().any(|e| matches!(e, Event::Place(_))),
        "an arrival should be announced, got {events:?}"
    );
}

fn b_post(t: &mut Two, f: &msg::Fix, ts: i64) -> Post {
    t.b.location(
        &me(&t.b_identity, "Bo", "", 0.8, msg::ShareMode::Precise),
        *f,
        msg::ShareMode::Precise,
        ts,
    )
    .expect("a post seals")
}

/// A one-member feed, as the relay would serve it.
fn feed_of(post: &Post) -> wire::Feed {
    wire::Feed {
        now: post.ts,
        members: vec![wire::FeedMember {
            m: post.m.clone(),
            alg: post.alg.clone(),
            pk: post.pk.clone(),
            epk: post.epk.clone(),
            points: vec![wire::FeedPoint {
                e: post.e,
                ts: post.ts,
                srv: post.ts,
                n: post.n.clone(),
                c: post.c.clone(),
                sig: post.sig.clone(),
            }],
        }],
    }
}
