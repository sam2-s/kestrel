//! The join handshake, driven the way a phone drives it.
//!
//! The pieces are tested separately elsewhere; what is checked here is the
//! *ordering* between them, which is where a handshake that looks correct in
//! each part still fails: a welcome posted before its records, a re-key on the
//! wrong channel, a roster hash computed over a roster that does not know the
//! newcomer yet. Nothing here is stubbed — every post is sealed, read back off
//! a feed, and opened by the other side through the same path an app uses.

use kestrel_core::{
    b64,
    identity::{self, Identity},
    invite::{self, Invite, ParsedInvite, parse_fragment, screen_join_request},
    kdf,
    membership::{self, PendingJoin},
    msg::{self, InviteMsg},
    rekey,
    roster::{LOCAL_CAP, Roster},
    seal,
    session::{Circle, Event, me},
    wire::{self, Alg, Post},
};

const EPOCH: i64 = wire::EPOCH_MS;

/// The epoch every timestamp in this file lives in.
const EPOCH_AT: i64 = 2_980_471;

fn at(epoch: i64) -> i64 {
    epoch * EPOCH
}

/// A fixed envelope of entropy, so a test's generations are reproducible.
fn entropy() -> [u8; rekey::FRESH_ENTROPY_LEN] {
    [0x5a; rekey::FRESH_ENTROPY_LEN]
}

/// Assert a post's signature covers `channel`.
///
/// The only way to tell which channel a post was sealed for: the channel is
/// mixed into the signed bytes, so a post that verifies on one does not on
/// another.
fn signed_for(post: &Post, channel: &str, why: &str) {
    let signed = wire::sig_base(channel, &post.m, post.e, post.ts, &post.n, &post.c);
    let pk = post.pk_bytes().expect("a post carries a signing key");
    let alg = Alg::from_pk(&pk).expect("a key length the protocol knows");
    let sig = b64::decode(&post.sig).expect("a signature that decodes");
    assert!(
        identity::verify_sig(alg, &pk, &sig, signed.as_bytes()),
        "{why}: the signature does not cover {channel}"
    );
}

/// Open everything on a rendezvous channel.
///
/// Sealed, then timestamp-checked, then parsed: a record that a receiver could
/// not actually parse is not a record, which is the class of bug this is here
/// to catch.
fn read_rendezvous(
    posts: &[Post],
    link: &ParsedInvite,
    now: i64,
) -> Vec<(Post, InviteMsg)> {
    let channel = link.channel();
    let key = link.key();
    let mut out = Vec::new();
    for post in posts {
        let Some(opened) = seal::verify_and_open(post, &channel, &key, now) else {
            continue;
        };
        assert!(
            msg::inner_timestamp_matches(&opened.body, post.ts),
            "the header's timestamp and the body's have to be the same number, \
             or every receiver refuses the message as tampered"
        );
        let Some(body) = msg::parse_invite(&opened.body) else {
            continue;
        };
        out.push((post.clone(), body));
    }
    out
}

/// A location post, sealed and ready to hand to the other side.
fn a_location(circle: &mut Circle, name: &str, now: i64) -> Post {
    let who = me(circle.identity(), name, "", 0.8, msg::ShareMode::Precise);
    circle
        .location(&who, msg::Fix::new(44.98, -93.27, 5.0), msg::ShareMode::Precise, now)
        .expect("a member of a circle can seal a position")
}

/// The founding pair: `a` created the circle and `b` joined it, with `b`'s
/// roster built the way a real join builds one, from the inviter's record.
///
/// Handing `Circle::join` an empty roster looks equivalent and is not: the
/// roster is also the *founding* roster, and a device whose founding roster is
/// empty refuses every later re-key as coming from a stranger.
fn a_founding_pair(now: i64) -> (Circle, Identity, Circle, Identity) {
    let a_identity = Identity::generate();
    let seed = [7u8; 32];
    let a = Circle::create(a_identity.clone(), &seed, now);

    let b_identity = Identity::generate();
    let mut roster = Roster::new();
    roster
        .admit(
            a_identity.member_id(),
            &a_identity.pk_b64(),
            &a_identity.epk_b64(),
            now,
            LOCAL_CAP,
        )
        .expect("the inviter fits");
    let b = Circle::join(
        b_identity.clone(),
        &seed,
        kdf::channel_id(&kdf::anchor(&seed)),
        0,
        wire::epoch_at(now),
        roster,
        now,
    );
    (a, a_identity, b, b_identity)
}

/// An invitation minted by `inviter`, and a stranger asking to join it.
///
/// The link has to be minted by the very identity that will later sign the
/// welcome: the commitment in the fragment is what the joining device checks the
/// welcome against, so a link from one device and a circle from another is a
/// handshake that fails at the door every time.
struct Request {
    invite: Invite,
    requester: PendingJoin,
    post: Post,
    body: InviteMsg,
}

fn a_request(inviter: &Identity, now: i64) -> Request {
    let invite = Invite::mint(inviter, now, invite::DEFAULT_TTL_MS);
    let parsed = parse_fragment(&invite.fragment()).expect("our own fragment parses");
    let requester = PendingJoin::new(&parsed, now);
    let body = InviteMsg::Join {
        v: msg::VERSION,
        ts: now,
        pk: requester.identity.pk_b64(),
        epk: requester.identity.epk_b64(),
        name: "Bo".into(),
    };
    let json = serde_json::to_string(&body).unwrap();
    let post = seal::build_post(
        &requester.identity,
        &requester.channel,
        &requester.key,
        wire::epoch_at(now),
        now,
        &json,
    )
    .expect("a join request seals");
    Request { invite, requester, post, body }
}

/// Read the invitation back through the fragment a joiner would have scanned.
fn parsed_link(req: &Request) -> ParsedInvite {
    parse_fragment(&req.invite.fragment()).expect("the fragment parses")
}

/// Admit `req` into `circle`, which must own the invitation.
fn admit(circle: &mut Circle, req: &Request, now: i64) -> membership::Admission {
    membership::admit(circle, &req.invite, (&req.post, &req.body), now, &entropy())
        .expect("the request is admissible")
}

// ------------------------------------------------------------- the link

#[test]
fn an_invitation_round_trips_through_a_real_fragment() {
    let now = at(EPOCH_AT);
    let inviter = Identity::generate();
    let req = a_request(&inviter, now);
    let link = parsed_link(&req);
    assert_eq!(link.channel(), req.invite.channel());
    // The link the joiner holds and the invitation the inviter kept are the same
    // rendezvous, or the two sides are reading different doors.
    assert_eq!(
        req.requester.channel,
        link.channel(),
        "the joiner must be posting where the inviter is listening"
    );
}

#[test]
fn a_join_request_is_screened_into_a_safety_number() {
    let now = at(EPOCH_AT);
    let inviter = Identity::generate();
    let req = a_request(&inviter, now);
    let shown =
        screen_join_request(&req.invite, &req.post, &req.body, now, false, false, true)
            .expect("a genuine request is shown to the inviter");

    let invite::Screen::ShowSafetyNumber { member_id, safety_number } = shown;
    assert_eq!(member_id, req.requester.identity.member_id());
    // The number the inviter reads out loud is derived from the keys the *post*
    // was signed with, which is the device that is actually asking.
    let expected = identity::safety_number_for(
        &req.post.pk_bytes().unwrap(),
        &req.post.epk_bytes().unwrap(),
    );
    assert_eq!(safety_number, expected);
}

#[test]
fn a_screening_refuses_a_request_the_circle_has_no_room_for() {
    let now = at(EPOCH_AT);
    let inviter = Identity::generate();
    let req = a_request(&inviter, now);
    let err =
        screen_join_request(&req.invite, &req.post, &req.body, now, false, false, false)
            .expect_err("a full circle says so rather than queueing");
    assert_eq!(err, invite::ScreenError::NoRoom);
}

// ------------------------------------------------------------- the admission

#[test]
fn an_admission_moves_onto_a_channel_nobody_was_on_before() {
    let now = at(EPOCH_AT);
    let (mut circle, inviter, _, _) = a_founding_pair(now);
    let old_channel = circle.channel().to_string();
    let req = a_request(&inviter, now);

    let admission = admit(&mut circle, &req, now);

    // A joiner is admitted into a generation that did not exist a moment ago, so
    // there is no backlog on it for them to decrypt and no way to work the
    // circle's history out from ciphertext they were not there for.
    assert_eq!(admission.generation, 1);
    assert_ne!(admission.channel, old_channel);
    assert_eq!(circle.channel(), admission.channel, "the rotator moves too");
    assert_eq!(circle.generation(), 1);

    // The re-key went to the channel that is ending, because that is the one the
    // members already in are reading. On the rendezvous it would be invisible.
    assert!(!admission.rekeys.is_empty(), "a re-key is how the circle learns");
    for post in &admission.rekeys {
        signed_for(post, &old_channel, "a re-key posted anywhere else is unreadable");
    }
    // And the rest went to the rendezvous, where the joiner is listening.
    let rendezvous = req.invite.channel();
    for post in &admission.rendezvous {
        signed_for(post, &rendezvous, "the handshake belongs on the rendezvous channel");
    }
}

#[test]
fn the_ack_goes_out_first_and_the_welcome_last() {
    // The plan exists to be followed in order. The ack claims the inviter's slot
    // on a channel whose member cap is what the welcome depends on, and the
    // welcome is the commit point, so it goes last.
    let now = at(EPOCH_AT);
    let (mut circle, inviter, _, _) = a_founding_pair(now);
    let req = a_request(&inviter, now);
    let admission = admit(&mut circle, &req, now);

    let link = parsed_link(&req);
    let bodies: Vec<InviteMsg> = read_rendezvous(&admission.rendezvous, &link, now)
        .into_iter()
        .map(|(_, b)| b)
        .collect();
    assert!(
        matches!(bodies.first(), Some(InviteMsg::Ack { .. })),
        "ack first, got {bodies:?}"
    );
    assert!(
        matches!(bodies.last(), Some(InviteMsg::Welcome { .. })),
        "welcome last, got {bodies:?}"
    );
    let records = bodies.iter().filter(|b| matches!(b, InviteMsg::Member { .. })).count();
    assert_eq!(records, 1, "one record per member other than the joiner");
}

#[test]
fn a_welcome_names_the_records_that_follow_it() {
    let now = at(EPOCH_AT);
    let (mut circle, inviter, _, _) = a_founding_pair(now);
    let req = a_request(&inviter, now);
    let admission = admit(&mut circle, &req, now);

    let link = parsed_link(&req);
    let arrived = read_rendezvous(&admission.rendezvous, &link, now);
    let (_, welcome) = arrived
        .iter()
        .find(|(_, b)| matches!(b, InviteMsg::Welcome { .. }))
        .expect("a welcome is posted");
    let InviteMsg::Welcome { n, .. } = welcome else { unreachable!() };
    let records =
        arrived.iter().filter(|(_, b)| matches!(b, InviteMsg::Member { .. })).count();
    assert_eq!(*n as usize, records, "the count has to match what followed");

    // And each record opens for the joiner, naming a member they will have to
    // recognise on the new channel.
    let welcome_seen = kestrel_core::membership::VerifiedWelcome {
        generation: 1,
        opening_epoch: wire::epoch_at(now),
        record_count: *n,
        seed: [0u8; 32],
        from: welcome_post_member(&arrived),
    };
    let mut opened = 0;
    for (post, body) in &arrived {
        if matches!(body, InviteMsg::Member { .. })
            && membership::open_member_record(
                &req.requester.identity,
                &welcome_seen.from,
                post,
                body,
                &welcome_seen,
                &link,
            )
            .is_some()
        {
            opened += 1;
        }
    }
    assert_eq!(opened, *n as usize, "every record opens");
}

/// The member id of whoever posted the welcome, which is the only inviter a
/// record may be believed from.
fn welcome_post_member(arrived: &[(Post, InviteMsg)]) -> String {
    arrived
        .iter()
        .find(|(_, b)| matches!(b, InviteMsg::Welcome { .. }))
        .map(|(p, _)| p.m.clone())
        .expect("a welcome is posted")
}

// ------------------------------------------------------------- the joiner

#[test]
fn a_joiner_lands_on_the_same_channel_as_the_rest_of_the_circle() {
    let now = at(EPOCH_AT);
    let (mut circle, inviter, _, _) = a_founding_pair(now);
    let req = a_request(&inviter, now);
    let admission = admit(&mut circle, &req, now);

    let link = parsed_link(&req);
    let arrived = read_rendezvous(&admission.rendezvous, &link, now);
    let joined = membership::finish_join(&req.requester, &link, &arrived, now, now)
        .expect("the handshake completes");

    assert_eq!(joined.channel(), admission.channel, "one circle, one channel");
    assert_eq!(joined.generation(), 1);
    assert!(
        joined.roster().contains(circle.identity().member_id()),
        "the joiner recognises the inviter"
    );
    assert!(joined.roster().contains(joined.identity().member_id()), "and itself");
}

#[test]
fn two_devices_exchange_a_position_after_joining() {
    let now = at(EPOCH_AT);
    let (mut circle, inviter, _, _) = a_founding_pair(now);
    let req = a_request(&inviter, now);
    let admission = admit(&mut circle, &req, now);

    let link = parsed_link(&req);
    let arrived = read_rendezvous(&admission.rendezvous, &link, now);
    let mut joiner =
        membership::finish_join(&req.requester, &link, &arrived, now, now).expect("joins");

    // The joiner speaks first: they have just joined a generation with no
    // backlog, so the inviter admitting them is exactly what happens when this
    // position lands.
    let pos = a_location(&mut joiner, "Bo", now + 1);
    let events = circle
        .ingest(&pos, &circle.roster().clone(), now + 1)
        .expect("the joiner's position is accepted on the new channel");
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::Joined { member } if member == joiner.identity().member_id())),
        "{events:?}"
    );

    // And back the other way.
    let reply = a_location(&mut circle, "Ana", now + 2);
    let events = joiner
        .ingest(&reply, &joiner.roster().clone(), now + 2)
        .expect("the inviter's position opens for the joiner");
    assert!(events.iter().any(|e| matches!(e, Event::Position { .. })));
}

// ------------------------------------------------------------- a third device

/// The circle with two in it: the founder, and someone who joined for real.
///
/// Both circles come back, because the point of a third admission is what the
/// *other* member does, and a hand-built stand-in cannot answer that: its
/// generation, its channel, and its founding roster all have to be the ones a
/// real join leaves behind.
fn a_circle_of_two(now: i64) -> (Circle, Identity, Circle) {
    let (mut a, a_identity, _, _) = a_founding_pair(now);
    let req = a_request(&a_identity, now);
    let admission = admit(&mut a, &req, now);
    let link = parsed_link(&req);
    let arrived = read_rendezvous(&admission.rendezvous, &link, now);
    let mut bo =
        membership::finish_join(&req.requester, &link, &arrived, now, now).expect("joins");
    let pos = a_location(&mut bo, "Bo", now + 1);
    a.ingest(&pos, &a.roster().clone(), now + 1).expect("Bo's first position admits them");
    (a, a_identity, bo)
}

#[test]
fn a_second_admission_takes_the_whole_circle_with_it() {
    // The case a single join cannot reach: a member who is not the rotator has
    // to be moved to the new generation too, and the roster hash has to be the
    // one that includes the newcomer before they have posted anywhere.
    let now = at(EPOCH_AT);
    let (mut ana, ana_identity, mut bo) = a_circle_of_two(now);
    let old_channel = ana.channel().to_string();

    let req = a_request(&ana_identity, now + 5);
    let admission = admit(&mut ana, &req, now + 5);
    assert_eq!(admission.rekeys.len(), 2, "a wrap for Bo and one for Cass");

    // The re-key is readable where the circle is: on the channel that is
    // ending, not on the one nobody has joined yet.
    for post in &admission.rekeys {
        signed_for(post, &old_channel, "a re-key has to be readable where the circle is");
    }

    // Bo, still reading the old channel, follows it. Cass's wrap is on the same
    // bytes and is not for him; that it is skipped rather than fatal is the
    // behaviour under test.
    let roster_before = bo.roster().clone();
    let mut moved = 0;
    for post in &admission.rekeys {
        for event in bo.ingest(post, &roster_before, now + 5).into_iter().flatten() {
            moved += usize::from(matches!(event, Event::Rekeyed { .. }));
        }
    }
    assert_eq!(moved, 1, "the member who was in the circle moves exactly once");
    assert_eq!(bo.channel(), admission.channel, "Bo is on the new channel");
    assert_eq!(bo.generation(), 2);

    let link = parsed_link(&req);
    let arrived = read_rendezvous(&admission.rendezvous, &link, now + 5);
    let mut cass_circle =
        membership::finish_join(&req.requester, &link, &arrived, now + 5, now + 5)
            .expect("joins");
    assert_eq!(cass_circle.channel(), admission.channel);
    assert_eq!(cass_circle.generation(), 2);

    // The founder sees the newcomer on the new channel, and the newcomer sees
    // the member who was already there.
    let pos = a_location(&mut cass_circle, "Cass", now + 6);
    ana.ingest(&pos, &ana.roster().clone(), now + 6)
        .expect("the founder sees the newcomer on the channel they both moved to");
    let reply = a_location(&mut ana, "Ana", now + 7);
    bo.ingest(&reply, &bo.roster().clone(), now + 7)
        .expect("the member who followed the re-key sees the founder too");
    cass_circle
        .ingest(
            &a_location(&mut ana, "Ana", now + 8),
            &cass_circle.roster().clone(),
            now + 8,
        )
        .expect("and so does the newcomer");
}

#[test]
fn a_member_follows_the_rekey_to_the_new_generation() {
    // Just the rotator and one other member: the smallest circle in which a
    // re-key has somebody to move who is not the one who sent it.
    let now = at(EPOCH_AT);
    // A circle of two, so there is somebody besides the rotator to move.
    let (mut ana, ana_identity, mut bo) = a_circle_of_two(now);
    let old_generation = ana.generation();

    let req = a_request(&ana_identity, now + 5);
    let admission = admit(&mut ana, &req, now + 5);
    assert_eq!(admission.rekeys.len(), 2, "one wrap each for the two members already in");

    let roster_before = bo.roster().clone();
    let mut moved = false;
    for post in &admission.rekeys {
        for event in bo.ingest(post, &roster_before, now + 5).into_iter().flatten() {
            moved |= matches!(event, Event::Rekeyed { .. });
        }
    }
    assert!(moved, "Bo moved with the circle");
    assert_eq!(bo.channel(), admission.channel, "and now reads the new channel");
    assert_eq!(bo.generation(), old_generation + 1);
    assert_eq!(ana.generation(), bo.generation(), "the rotator moved too");

    // And Bo can still talk to Ana on the channel they both landed on.
    let reply = a_location(&mut ana, "Ana", now + 6);
    bo.ingest(&reply, &bo.roster().clone(), now + 6)
        .expect("Ana's position opens for the member who followed the re-key");
}

// ------------------------------------------------------------- refusals

#[test]
fn a_welcome_from_the_wrong_device_is_ignored() {
    // The whole point of the commitment: someone who saw the link must not be
    // able to hand the joining device a circle of their choosing.
    let now = at(EPOCH_AT);
    let (mut circle, inviter, _, _) = a_founding_pair(now);
    let req = a_request(&inviter, now);
    let admission = admit(&mut circle, &req, now);

    let stranger = Identity::generate();
    let link = parsed_link(&req);
    let genuine = read_rendezvous(&admission.rendezvous, &link, now);
    let forged: Vec<(Post, InviteMsg)> = genuine
        .iter()
        .map(|(_, body)| {
            let json = serde_json::to_string(body).unwrap();
            let post = seal::build_post(
                &stranger,
                &link.channel(),
                &link.key(),
                wire::epoch_at(now),
                now,
                &json,
            )
            .unwrap();
            (post, body.clone())
        })
        .collect();

    let err = match membership::finish_join(&req.requester, &link, &forged, now, now) {
        Ok(_) => panic!("a welcome from anyone but the inviter is refused"),
        Err(e) => e,
    };
    assert_eq!(err, membership::JoinError::Waiting, "it is not even a welcome to consider");
}

#[test]
fn records_that_have_not_arrived_are_waited_for_rather_than_skipped() {
    // A partial join is worse than no join: a circle missing one of its own
    // members cannot attribute a re-key later.
    // A circle with two in it, so the welcome names two records and dropping one
    // leaves a delivery that is genuinely short.
    let now = at(EPOCH_AT);
    let (mut circle, inviter, _) = a_circle_of_two(now);
    let req = a_request(&inviter, now);
    let admission = admit(&mut circle, &req, now);

    let link = parsed_link(&req);
    let all = read_rendezvous(&admission.rendezvous, &link, now);
    let mut kept_a_record = false;
    let short: Vec<(Post, InviteMsg)> = all
        .iter()
        .filter(|(_, b)| {
            if !matches!(b, InviteMsg::Member { .. }) {
                return true;
            }
            if kept_a_record {
                return false;
            }
            kept_a_record = true;
            true
        })
        .cloned()
        .collect();
    let records =
        short.iter().filter(|(_, b)| matches!(b, InviteMsg::Member { .. })).count();
    assert_eq!(records, 1, "one record was dropped");

    let err = match membership::finish_join(&req.requester, &link, &short, now, now) {
        Ok(_) => panic!("a short delivery is a refusal"),
        Err(e) => e,
    };
    assert_eq!(err, membership::JoinError::Waiting, "still inside the grace period");

    // After the grace period it is a refusal with a reason.
    let later = now + membership::WELCOME_GRACE_MS + 1;
    let err = match membership::finish_join(&req.requester, &link, &short, later, now) {
        Ok(_) => panic!("and stays a refusal"),
        Err(e) => e,
    };
    assert_eq!(err, membership::JoinError::Incomplete { have: 1, need: 2 });
}

#[test]
fn an_expired_invitation_is_refused_before_anything_is_sent() {
    let now = at(EPOCH_AT);
    let (mut circle, inviter, _, _) = a_founding_pair(now);
    let req = a_request(&inviter, now);
    let late = now + invite::DEFAULT_TTL_MS + 1;
    let err = membership::admit(
        &mut circle,
        &req.invite,
        (&req.post, &req.body),
        late,
        &entropy(),
    )
    .expect_err("an expired link does not open");
    assert_eq!(err, membership::AdmitError::Expired);
    assert_eq!(circle.generation(), 0, "and the circle did not move");
}

#[test]
fn a_request_that_is_not_a_request_is_refused() {
    let now = at(EPOCH_AT);
    let (mut circle, inviter, _, _) = a_founding_pair(now);
    let req = a_request(&inviter, now);
    // An ack where a join request should be — the same channel, a different
    // message. Screening refuses it and admitting must too.
    let ack = InviteMsg::Ack { v: msg::VERSION, ts: now, to: "someone".into() };
    let err =
        membership::admit(&mut circle, &req.invite, (&req.post, &ack), now, &entropy())
            .expect_err("an ack is not a join request");
    assert_eq!(err, membership::AdmitError::NotARequest);
    assert_eq!(circle.generation(), 0);
}
