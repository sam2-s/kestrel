//! The join handshake, as the app drives it.
//!
//! The core has every cryptographic step and tests each of them. What is here is
//! the *ordering between them across two devices*, which is where a handshake
//! that is correct in every part still fails: a request posted to the circle's
//! channel instead of the rendezvous, an invitation re-minted while somebody is
//! still scanning the old code, a welcome folded into a circle that was never
//! told the roster it belongs to.
//!
//! One rendezvous at a time. The app holds one circle, so it is either waiting
//! for somebody to ask it in, or asking to be let in, and a second link would be
//! a state machine nobody can see the state of.
//!
//! Nothing here talks to the network. [`receive`] and [`accept`] take posts and
//! return [`Received`] — what should go where — so a test can drive a whole
//! handshake between two in-memory devices with no relay, no clock and no phone.

use kestrel_core::{
    invite::{self, Invite, ParsedInvite, Screen as InviteScreen},
    membership::{self, AdmitError, JoinError, PendingJoin},
    msg::{self, InviteMsg},
    rekey,
    roster::LOCAL_CAP,
    seal,
    wire::Post,
};

use crate::{engine::Engine, state::Shared, store};

/// What this device is doing on a rendezvous channel.
#[derive(Default)]
pub enum Handshake {
    /// Nothing. The state on the welcome screen and after every handshake ends.
    #[default]
    None,
    /// A link was minted here, and requests arrive on the rendezvous it names.
    ///
    /// Boxed like [`Handshake::Joining`], so that `None` — the state on the
    /// welcome screen and after every handshake — stays a thing that costs
    /// nothing to hold.
    Inviter(Box<Inviting>),
    /// A link came from somewhere else and this device is waiting for a welcome.
    Joining(Box<Joining>),
}

impl Handshake {
    /// Whether a rendezvous channel should be polled at all.
    ///
    /// Asked from the share loop on every pass, so it is a match and not a
    /// chain of fields that could drift apart.
    pub fn is_active(&self) -> bool {
        !matches!(self, Handshake::None)
    }
}

/// The inviter's half: the live link, and anyone asking to use it.
pub struct Inviting {
    pub invite: Invite,
    /// A request that has been screened and is waiting for a person to decide.
    ///
    /// One at a time. A queue of pending requests would be a list of people
    /// the inviter has to compare numbers for while the first one is still
    /// standing there, and the relay would hold the rest anyway.
    pub request: Option<Incoming>,
}

/// A join request that passed screening, waiting for a human decision.
#[derive(Debug, Clone, PartialEq)]
pub struct Incoming {
    pub post: Post,
    pub body: InviteMsg,
    pub member_id: String,
    pub name: String,
    pub safety_number: String,
}

/// The joiner's half: everything known before a welcome arrives.
pub struct Joining {
    pub invite: ParsedInvite,
    pub pending: PendingJoin,
    /// Every message that arrived on the rendezvous and opened with its key.
    ///
    /// Kept whole rather than folded as it comes, because
    /// [`membership::finish_join`] has to see the welcome and every record
    /// together: which post is the welcome is not knowable before its
    /// commitment has been checked.
    pub arrived: Vec<(Post, InviteMsg)>,
    /// When the first welcome was seen, which is when the records' grace
    /// period starts. Not when the poll happened to arrive.
    pub welcome_seen_at: Option<i64>,
}

/// What a handshake step changed, as data.
///
/// Returned rather than applied so a test can assert on where every post is
/// going without a relay, and so the caller — the share loop, or a screen —
/// decides what a failure means. Everything the engine has to do is in here:
/// which channels to read, and what to put on them.
#[derive(Debug, Default, PartialEq)]
pub struct Received {
    /// Re-keys, for the circle's own channel.
    pub to_circle: Vec<Post>,
    /// The ack, the records and the welcome, for the rendezvous.
    pub to_rendezvous: Vec<Post>,
    /// The rendezvous to read, or the empty string to stop reading one.
    ///
    /// `None` leaves it alone, which is the case where a handshake has just
    /// ended and its welcome is still on its way out: the channel has to stay
    /// attached until the queue drains, and the share loop is what knows when
    /// that is.
    pub rendezvous_channel: Option<String>,
    /// The circle channel the engine should serve now, if the join completed.
    pub attached: Option<String>,
    /// A request reached the review screen.
    pub surfaced: bool,
    /// A join completed and this device is now in a circle.
    pub completed: bool,
    /// Something worth telling the user.
    pub error: Option<String>,
}

/// Hand a [`Received`] to the engine.
///
/// Both channels are attached before anything is queued on them: attaching
/// resets the queue, so a post pushed first would be dropped by the very call
/// meant to send it.
pub fn apply(engine: &Engine, received: &Received) {
    if let Some(channel) = &received.rendezvous_channel {
        engine.attach_rendezvous(channel);
    }
    if let Some(channel) = &received.attached {
        engine.attach(channel);
    }
    for post in &received.to_circle {
        engine.push(post.clone(), "rekey", false);
    }
    for post in &received.to_rendezvous {
        engine.push_rendezvous(post.clone(), "handshake", false);
    }
}

/// Whether a handshake is in progress.
pub fn active(shared: &Shared) -> bool {
    shared.state.lock().map(|s| s.handshake.is_active()).unwrap_or(false)
}

/// Mint an invitation, or hand back the one that is still alive.
///
/// A fresh link on every tap would kill the code somebody is halfway through
/// scanning, so an unexpired one is returned as it is.
pub fn begin_invite(shared: &Shared, now: i64) -> Result<(String, Received), String> {
    if let Ok(state) = shared.state.lock()
        && let Handshake::Inviter(inv) = &state.handshake
        && !inv.invite.is_expired(now)
    {
        let channel = inv.invite.channel();
        return Ok((
            inv.invite.fragment(),
            Received { rendezvous_channel: Some(channel), ..Received::default() },
        ));
    }

    let invite = {
        let circles =
            shared.circles.lock().map_err(|_| "The circle is busy.".to_string())?;
        let circle = circles.first().ok_or("Create a circle first.")?;
        crate::logic::mint_invite(circle, now)
    };

    let channel = invite.channel();
    let fragment = invite.fragment();
    if let Ok(mut state) = shared.state.lock() {
        state.handshake = Handshake::Inviter(Box::new(Inviting {
            invite: invite.clone(),
            request: None,
        }));
    }
    // Not fatal if this fails: the link works for this run either way, and the
    // code on screen is still the code to send. What is lost is only that the
    // next launch mints a new one.
    let _ = store::save_invite(&invite);
    Ok((fragment, Received { rendezvous_channel: Some(channel), ..Received::default() }))
}

/// Put the stored invitation back, so yesterday's code still answers.
///
/// `None` when there is nothing to put back, which is the usual case.
pub fn restore(shared: &Shared, now: i64) -> Option<Received> {
    let invite = store::load_invite(now)?;
    let mut changed = false;
    if let Ok(mut state) = shared.state.lock()
        && matches!(state.handshake, Handshake::None)
    {
        state.handshake = Handshake::Inviter(Box::new(Inviting {
            invite: invite.clone(),
            request: None,
        }));
        changed = true;
    }
    // The rendezvous is attached even if the state already held one: the link
    // being restored is the one the user has already shown somebody.
    let _ = changed;
    Some(Received { rendezvous_channel: Some(invite.channel()), ..Received::default() })
}

/// Ask to join the circle behind `fragment`, and post the request.
///
/// The identity used for the attempt is generated here and never stored: an
/// abandoned join leaves nothing on the device, which is the point of holding
/// it in memory until a welcome arrives.
pub fn begin_join(
    shared: &Shared,
    fragment: &str,
    name: &str,
    now: i64,
) -> Result<Received, String> {
    let parsed =
        invite::parse_fragment(fragment.trim()).ok_or("That is not an invitation code.")?;
    let pending = PendingJoin::new(&parsed, now);
    let post = pending.request(name, now).ok_or("The join request could not be built.")?;
    let channel = pending.channel.clone();

    if let Ok(mut state) = shared.state.lock() {
        state.handshake = Handshake::Joining(Box::new(Joining {
            invite: parsed,
            pending,
            arrived: Vec::new(),
            welcome_seen_at: None,
        }));
    }
    Ok(Received {
        rendezvous_channel: Some(channel),
        to_rendezvous: vec![post],
        ..Received::default()
    })
}

/// Walk away from a handshake in progress.
///
/// Drops whatever is queued for it. A cancelled join's request is not a message
/// anybody should still be trying to deliver.
pub fn cancel(shared: &Shared) -> Received {
    if let Ok(mut state) = shared.state.lock() {
        state.handshake = Handshake::None;
        state.pending_name = None;
    }
    Received { rendezvous_channel: Some(String::new()), ..Received::default() }
}

/// Fold newly arrived rendezvous posts into whichever side is waiting.
///
/// Posts are opened with the key this handshake holds, so a post from a
/// different link — or from the circle's own channel, relayed here by mistake —
/// opens for nothing and is dropped without a word.
pub fn receive(shared: &Shared, posts: &[Post], now: i64) -> Received {
    let mut out = Received::default();
    if posts.is_empty() {
        return out;
    }
    let Ok(mut guard) = shared.state.lock() else {
        return out;
    };
    // Taken out so `guard` stays usable for the screen it is about to change.
    // A `Circle` is not the only thing that must not be borrowed twice.
    let mut handshake = std::mem::take(&mut guard.handshake);

    let mut surfaced: Option<(String, String)> = None;
    let mut joined: Option<String> = None;
    let mut failed: Option<String> = None;

    match &mut handshake {
        Handshake::None => {}
        Handshake::Inviter(inv) => {
            let channel = inv.invite.channel();
            let key = inv.invite.key();
            for post in posts {
                // One decision at a time; the rest are still on the wire and
                // will be read again if the cursor ever comes back, which it
                // will not — so a second request waits for the next invite.
                if inv.request.is_some() {
                    break;
                }
                let Some(body) = opened(post, &channel, &key, now) else {
                    continue;
                };
                let InviteMsg::Join { name, .. } = &body else {
                    // Our own ack, records and welcome, read back off the
                    // rendezvous. Nothing on this side is waiting for them.
                    continue;
                };
                let (already_member, has_room) = shared
                    .with_circle(|c| {
                        (c.roster().contains(&post.m), c.roster().len() < LOCAL_CAP)
                    })
                    .unwrap_or((false, false));
                let name = name.clone();
                match invite::screen_join_request(
                    &inv.invite,
                    post,
                    &body,
                    now,
                    already_member,
                    false,
                    has_room,
                ) {
                    Ok(InviteScreen::ShowSafetyNumber { member_id, safety_number }) => {
                        inv.request = Some(Incoming {
                            post: post.clone(),
                            body,
                            member_id,
                            name: name.clone(),
                            safety_number: safety_number.clone(),
                        });
                        surfaced = Some((safety_number, name));
                    }
                    // A refusal is not worth interrupting anybody: an expired
                    // link, a repeat request, a circle that is full. The person
                    // on the other end is told by not being let in.
                    Err(_) => {}
                }
            }
        }
        Handshake::Joining(join) => {
            let channel = join.invite.channel();
            let key = join.invite.key();
            for post in posts {
                let Some(body) = opened(post, &channel, &key, now) else {
                    continue;
                };
                // Our own request, read back. It says nothing to us.
                if matches!(body, InviteMsg::Join { .. }) {
                    continue;
                }
                if join.arrived.iter().any(|(p, _)| p == post) {
                    continue;
                }
                if matches!(body, InviteMsg::Welcome { .. })
                    && join.welcome_seen_at.is_none()
                {
                    join.welcome_seen_at = Some(now);
                }
                join.arrived.push((post.clone(), body));
            }

            let seen = join.welcome_seen_at.unwrap_or(now);
            match membership::finish_join(
                &join.pending,
                &join.invite,
                &join.arrived,
                now,
                seen,
            ) {
                Ok(circle) => {
                    let channel = circle.channel().to_string();
                    if let Ok(mut circles) = shared.circles.lock() {
                        *circles = vec![circle];
                    }
                    joined = Some(channel);
                }
                // Nothing to say: the records are still arriving, and a notice
                // every two seconds saying "still waiting" is noise.
                Err(JoinError::Waiting) => {}
                Err(e) => failed = Some(join_reason(e).to_string()),
            }
        }
    }

    if joined.is_some() {
        // The link has done its job. Burning it is what stops the code on the
        // other phone from being a second way in.
        handshake = Handshake::None;
    } else if failed.is_some() {
        // A handshake that will never complete is not worth polling for.
        handshake = Handshake::None;
    }
    guard.handshake = handshake;

    if let Some((number, name)) = surfaced {
        guard.pending_name = Some((number, name));
        guard.go(crate::state::Screen::Review);
        out.surfaced = true;
    }
    if let Some(channel) = joined {
        guard.pending_name = None;
        guard.invite = None;
        guard.go(crate::state::Screen::Map);
        out.attached = Some(channel);
        out.completed = true;
    }
    out.error = failed;
    out
}

/// Let the person on the review screen in.
///
/// Everything is produced here and applied by the caller, so a refusal leaves
/// the engine untouched rather than half-way through a rotation.
pub fn accept(shared: &Shared, now: i64) -> Received {
    let mut out = Received::default();
    let Ok(mut guard) = shared.state.lock() else {
        return out;
    };
    let mut handshake = std::mem::take(&mut guard.handshake);
    let Handshake::Inviter(inv) = &mut handshake else {
        guard.handshake = handshake;
        return out;
    };
    let Some(incoming) = inv.request.take() else {
        guard.handshake = handshake;
        return out;
    };
    let invite = inv.invite.clone();
    // Fresh entropy per admission, mixed with the rotator's chain key: neither
    // a relay that sees the mix nor a member holding only the chain key can
    // compute the generation that follows.
    let entropy: [u8; rekey::FRESH_ENTROPY_LEN] = seal::random_bytes();

    let Some(admitted) = shared.with_circle(|circle| {
        membership::admit(circle, &invite, (&incoming.post, &incoming.body), now, &entropy)
    }) else {
        // No circle to add anybody to. Should not happen — the review screen
        // only exists because there is one — and must not be reported as a
        // protocol failure when it does.
        if let Handshake::Inviter(inv) = &mut handshake {
            inv.request = Some(incoming);
        }
        guard.handshake = handshake;
        out.error = Some("There is no circle to add them to.".to_string());
        return out;
    };

    match admitted {
        Ok(admission) => {
            out.to_circle = admission.rekeys;
            out.to_rendezvous = admission.rendezvous;
            // Burned: the code the user showed somebody is now a way in for
            // nobody, because somebody is in.
            handshake = Handshake::None;
            guard.pending_name = None;
            store::clear_invite();
        }
        Err(e) => {
            out.error = Some(admit_reason(e).to_string());
            if matches!(
                e,
                AdmitError::AlreadyMember | AdmitError::NoRoom | AdmitError::Expired
            ) {
                // Nothing to retry, so the screen must not sit there offering
                // an Accept button for a decision that no longer exists.
                if let Handshake::Inviter(inv) = &mut handshake {
                    inv.request = None;
                }
                guard.pending_name = None;
            } else if let Handshake::Inviter(inv) = &mut handshake {
                // A clock that is wrong, or a ratchet that would not give up a
                // chain key: fixable, so the request is kept for another try.
                inv.request = Some(incoming);
            }
        }
    }
    guard.handshake = handshake;
    out
}

/// Turn away the person on the review screen.
pub fn decline(shared: &Shared) {
    let Ok(mut guard) = shared.state.lock() else {
        return;
    };
    if let Handshake::Inviter(inv) = &mut guard.handshake {
        inv.request = None;
    }
    guard.pending_name = None;
    guard.go(crate::state::Screen::Map);
}

/// Open one rendezvous post with this handshake's key.
fn opened(
    post: &Post,
    channel: &str,
    key: &seal::ContentKey,
    now: i64,
) -> Option<InviteMsg> {
    let opened = seal::verify_and_open(post, channel, key, now)?;
    msg::parse_invite(&opened.body)
}

/// What a join refusal means, in words.
fn join_reason(e: JoinError) -> &'static str {
    match e {
        JoinError::Waiting => "",
        JoinError::Incomplete { .. } => {
            "The invitation's records did not all arrive in time. Ask for a new code."
        }
        JoinError::Unusable => "That invitation did not build a circle you can use.",
    }
}

/// What an admission refusal means, in words.
fn admit_reason(e: AdmitError) -> &'static str {
    match e {
        AdmitError::NotARequest => "That was not a join request.",
        AdmitError::Expired => "Your invitation has expired. Mint a new one.",
        AdmitError::AlreadyMember => "They are already in the circle.",
        AdmitError::NoRoom => "The circle is full.",
        AdmitError::Unreadable => "Their keys could not be read.",
        AdmitError::Unwritable => {
            "Your device clock is wrong, so the circle could not be re-keyed."
        }
        AdmitError::TooLarge => "The handshake was too large to send.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use kestrel_core::{identity::Identity, seal::random_bytes, session::Circle, wire};

    const NOW: i64 = 1_700_000_000_000;

    /// A device with a circle of its own, which is what an inviter is.
    fn inviter() -> Arc<Shared> {
        let shared = Arc::new(Shared::default());
        let circle = Circle::create(Identity::generate(), &random_bytes::<32>(), NOW);
        *shared.circles.lock().unwrap() = vec![circle];
        shared
    }

    /// A device with no circle, which is what every joiner is.
    fn joiner() -> Arc<Shared> {
        Arc::new(Shared::default())
    }

    fn circle_channel(shared: &Shared) -> String {
        shared.circles.lock().unwrap()[0].channel().to_string()
    }

    fn screen(shared: &Shared) -> crate::state::Screen {
        shared.state.lock().unwrap().screen
    }

    /// Read rendezvous posts back with the key `code` names.
    fn read(code: &str, posts: &[Post], now: i64) -> Vec<InviteMsg> {
        let parsed = invite::parse_fragment(code).expect("our own code parses");
        let (channel, key) = invite::rendezvous(&parsed);
        posts.iter().filter_map(|p| opened(p, &channel, &key, now)).collect()
    }

    /// The whole handshake, from a link to a second member.
    ///
    /// The review screen's safety number is returned with it: accepting a
    /// request clears that screen, so a test that wants to read it has to read
    /// it while the request is still standing.
    fn a_handshake(
        now: i64,
    ) -> (Arc<Shared>, Arc<Shared>, String, Received, (String, String)) {
        let a = inviter();
        let b = joiner();
        let (code, _) = begin_invite(&a, now).expect("a circle can mint a link");
        let asked = begin_join(&b, &code, "Bo", now + 1).expect("a fragment that parses");
        let request = asked.to_rendezvous[0].clone();
        let surfaced = receive(&a, &[request], now + 2);
        assert!(surfaced.surfaced, "{surfaced:?}");
        let review =
            a.state.lock().unwrap().pending_name.clone().expect("a person to review");
        let admitted = accept(&a, now + 3);
        assert!(admitted.error.is_none(), "{:?}", admitted.error);
        (a, b, code, admitted, review)
    }

    #[test]
    fn there_is_no_invitation_without_a_circle() {
        // A link with no circle behind it is a rendezvous nobody can admit
        // anybody from. Said, rather than a button that does nothing.
        let err = begin_invite(&joiner(), NOW).unwrap_err();
        assert!(err.contains("circle"), "{err}");
    }

    #[test]
    fn an_invitation_is_the_same_code_until_it_is_used_or_expires() {
        // Somebody may be halfway through scanning the code already on screen.
        // Minting again would kill their link while it looks alive to both of them.
        let a = inviter();
        let (first, _) = begin_invite(&a, NOW).unwrap();
        let (again, _) = begin_invite(&a, NOW + 1).unwrap();
        assert_eq!(first, again, "a second tap replaced a live invitation");

        // An expired one is replaced rather than re-shown, because it is dead.
        let (later, _) = begin_invite(&a, NOW + store::INVITE_TTL_MS).unwrap();
        assert_ne!(first, later);
    }

    #[test]
    fn an_invitation_reaches_a_safety_number_and_then_a_member() {
        let (a, b, code, admitted, (number, name)) = a_handshake(NOW);

        // What the inviter was asked to decide: a name, and a number to read
        // aloud and compare with the other phone before letting them in.
        assert_eq!(name, "Bo");
        assert!(!number.is_empty(), "a safety number to read aloud");
        assert_eq!(screen(&a), crate::state::Screen::Review);
        // Accepting clears the review screen — there is nobody left to decide
        // about — so this is the last moment the number exists.
        assert!(a.state.lock().unwrap().pending_name.is_none());

        // What admitting produced, in the order the relay will accept.
        assert!(!admitted.to_circle.is_empty(), "the circle is re-keyed");
        let bodies = read(&code, &admitted.to_rendezvous, NOW + 3);
        assert!(matches!(bodies.first(), Some(InviteMsg::Ack { .. })), "{bodies:?}");
        assert!(matches!(bodies.last(), Some(InviteMsg::Welcome { .. })), "{bodies:?}");
        assert!(
            bodies.iter().any(|b| matches!(b, InviteMsg::Member { .. })),
            "at least the inviter's own record"
        );

        // The link is burnt: the code on the other phone is no longer a way in.
        assert!(!a.state.lock().unwrap().handshake.is_active());

        // And the joiner lands on the same channel as everybody else.
        let landed = receive(&b, &admitted.to_rendezvous, NOW + 4);
        assert!(landed.completed, "{landed:?}");
        assert_eq!(landed.attached.as_deref(), Some(circle_channel(&a).as_str()));
        assert!(b.has_circle(), "the joiner has a circle now");
        assert_eq!(screen(&b), crate::state::Screen::Map);
        assert!(!b.state.lock().unwrap().handshake.is_active());
    }

    #[test]
    fn a_post_that_does_not_open_for_this_link_changes_nothing() {
        // Two invitations are two rendezvous with two keys. A ciphertext that
        // opens for neither must be dropped without a word: interpreting it
        // would mean trusting a stranger's framing.
        let a = inviter();
        let stranger = Identity::generate();
        let other = Invite::mint(&stranger, NOW, store::INVITE_TTL_MS);
        let parsed = invite::parse_fragment(&other.fragment()).unwrap();
        let (channel, key) = invite::rendezvous(&parsed);
        let body = serde_json::to_string(&InviteMsg::Join {
            v: msg::VERSION,
            ts: NOW,
            pk: stranger.pk_b64(),
            epk: stranger.epk_b64(),
            name: "Mallory".into(),
        })
        .unwrap();
        let rogue =
            seal::build_post(&stranger, &channel, &key, wire::epoch_at(NOW), NOW, &body)
                .unwrap();

        let received = receive(&a, &[rogue], NOW);
        assert!(!received.surfaced, "{received:?}");
        assert!(received.error.is_none());
        assert!(a.state.lock().unwrap().pending_name.is_none());
        assert_ne!(screen(&a), crate::state::Screen::Review);
    }

    #[test]
    fn declining_leaves_nobody_waiting() {
        let a = inviter();
        let b = joiner();
        let (code, _) = begin_invite(&a, NOW).unwrap();
        let asked = begin_join(&b, &code, "Bo", NOW + 1).unwrap();
        let surfaced = receive(&a, &asked.to_rendezvous, NOW + 2);
        assert!(surfaced.surfaced);

        decline(&a);
        assert!(a.state.lock().unwrap().pending_name.is_none());
        assert!(a.state.lock().unwrap().handshake.is_active(), "the link still works");
        assert_eq!(screen(&a), crate::state::Screen::Map);
        // And there is nothing left to accept: a second tap admits nobody,
        // rather than quietly retrying a decision the user already made.
        let again = accept(&a, NOW + 3);
        assert!(again.to_circle.is_empty() && again.to_rendezvous.is_empty(), "{again:?}");
        assert!(!again.completed, "{again:?}");
    }

    #[test]
    fn a_welcome_without_its_records_ends_the_handshake() {
        // A short delivery is a refusal, not a partial circle: a circle missing
        // one of its own members cannot attribute a re-key later.
        // The joiner from the handshake itself: its identity is the one the
        // welcome was sealed to, so a freshly generated device would find
        // nothing in these posts at all.
        let (_a, b, code, admitted, _review) = a_handshake(NOW);

        let is_record = |post: &Post| {
            read(&code, std::slice::from_ref(post), NOW + 3)
                .first()
                .is_some_and(|m| matches!(m, InviteMsg::Member { .. }))
        };
        let short: Vec<Post> =
            admitted.to_rendezvous.iter().filter(|p| !is_record(p)).cloned().collect();
        assert!(
            short.len() < admitted.to_rendezvous.len(),
            "a record was dropped for this test to mean anything"
        );

        // Inside the grace period: still waiting, because records are allowed
        // to arrive after the welcome that announces them.
        let early = receive(&b, &short, NOW + 4);
        assert!(!early.completed, "{early:?}");
        assert!(early.error.is_none(), "{early:?}");
        assert!(b.state.lock().unwrap().handshake.is_active());

        // After it: a refusal with a reason, and no handshake left to poll for.
        let late = NOW + 4 + membership::WELCOME_GRACE_MS + 1;
        let late = receive(&b, &short, late);
        assert!(late.error.is_some(), "{late:?}");
        assert!(!b.state.lock().unwrap().handshake.is_active());
        assert!(!b.has_circle());
    }

    #[test]
    fn a_join_carries_no_position_of_its_own() {
        // The request is the first thing this device says to a stranger, and it
        // says it on a channel whose owner has not been proven yet.
        let b = joiner();
        let other = Invite::mint(&Identity::generate(), NOW, store::INVITE_TTL_MS);
        let asked = begin_join(&b, &other.fragment(), "Bo", NOW).unwrap();
        let parsed = invite::parse_fragment(&other.fragment()).unwrap();
        let (channel, key) = invite::rendezvous(&parsed);
        let opened = seal::verify_and_open(&asked.to_rendezvous[0], &channel, &key, NOW)
            .expect("the request opens on its own rendezvous");
        assert!(opened.body.contains(r#""t":"join""#), "{}", opened.body);
        assert!(!opened.body.contains("lat"), "{}", opened.body);
    }

    #[test]
    fn cancelling_a_join_says_so_to_the_engine() {
        let b = joiner();
        let other = Invite::mint(&Identity::generate(), NOW, store::INVITE_TTL_MS);
        let asked = begin_join(&b, &other.fragment(), "Bo", NOW).unwrap();
        assert_eq!(
            asked.rendezvous_channel,
            Some(invite::parse_fragment(&other.fragment()).unwrap().channel())
        );
        // The empty string is the engine's "stop reading this", and it is
        // returned rather than applied so a test can see it was asked for.
        let cancelled = cancel(&b);
        assert_eq!(cancelled.rendezvous_channel, Some(String::new()));
        assert!(!b.state.lock().unwrap().handshake.is_active());
    }
}
