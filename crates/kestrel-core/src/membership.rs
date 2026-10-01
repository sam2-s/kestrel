//! Joining a circle: the handshake, and the ordering that makes it safe.
//!
//! The sequence has three load-bearing parts, and each is a decision about
//! ordering rather than about cryptography:
//!
//! 1. **The inviter claims their own slot first.** Their `ack` is the first post
//!    on the rendezvous channel. The relay caps how many members a channel may
//!    have, and the welcome is the most important post there, so the slot it
//!    needs has to be taken before the channel fills with someone else's.
//! 2. **The re-key happens before the welcome.** The joiner is admitted into a
//!    generation that did not exist a moment ago, so there is no backlog on it
//!    for them to decrypt and no way to work out the circle's history from
//!    ciphertext they were not there for.
//! 3. **The welcome is posted last.** It is the commit point. A member record
//!    without a welcome naming its context is inert; a welcome without its
//!    records is incomplete. Sending the welcome first would mean the joiner
//!    re-opens it on every poll, and the channel filling up would starve a later
//!    complete one.
//!
//! If the welcome cannot be sent, the inviter does not simply give up: they run
//! a *second* re-key that removes the member they just admitted, and destroy the
//! seed they sent. The joiner is then unreachable on that generation by any
//! route, and the failure leaves no half-joined device behind.

use crate::{
    b64,
    identity::Identity,
    kdf,
    msg::{self, InviteMsg, MemberRecord},
    rekey,
    roster::Roster,
    seal::{self, ContentKey},
    wire::{MAX_SKEW_EPOCHS, Post},
};

use super::invite::ParsedInvite;

/// The largest number of member records one welcome can name.
///
/// Sixty-four is well above the member cap, so a legitimate welcome is never
/// rejected for size, and low enough that the count is bounded work.
pub const WELCOME_MAX_RECORDS: i64 = 64;

/// How long the joiner waits for the records named by a welcome before refusing
/// the join rather than completing it partially.
pub const WELCOME_GRACE_MS: i64 = 60_000;

/// How many unopened messages a joiner buffers while waiting.
///
/// Bounded because the channel is capped and a hostile inviter could otherwise
/// fill memory with messages that are never opened.
pub const WELCOME_BUF_CAP: usize = 128;

/// A step in admitting someone, as data.
///
/// The plan is returned rather than executed so the UI can show what is about to
/// happen, and so the undo for each step is written next to the step rather than
/// remembered later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionStep {
    /// Post the inviter's own `ack`, claiming a slot on the rendezvous.
    ClaimSlot,
    /// Re-key the circle, admitting the new member into a fresh generation.
    Rekey,
    /// Post one sealed member record per existing member.
    SendRecords,
    /// Post the welcome, which commits the admission.
    SendWelcome,
    /// Destroy the invitation secret.
    BurnInvite,
}

/// The full admission plan, in order.
pub const ADMISSION_PLAN: [AdmissionStep; 5] = [
    AdmissionStep::ClaimSlot,
    AdmissionStep::Rekey,
    AdmissionStep::SendRecords,
    AdmissionStep::SendWelcome,
    AdmissionStep::BurnInvite,
];

/// Whether an admission can be undone, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Undo {
    /// Nothing to undo; the step never took effect.
    Nothing,
    /// A second re-key that removes the member just admitted. The failed
    /// generation's seed is already destroyed, so the joiner cannot reach it.
    RemoveNewMember,
    /// A second re-key removing the member the first one removed, restoring
    /// them. Used when a removal itself fails to send.
    RestoreRemoved,
}

/// What to undo when a step fails.
pub fn undo_for(step: AdmissionStep, admitted: &str) -> Undo {
    match step {
        AdmissionStep::SendWelcome | AdmissionStep::BurnInvite => Undo::RemoveNewMember,
        AdmissionStep::Rekey => Undo::Nothing,
        _ => {
            let _ = admitted;
            Undo::Nothing
        }
    }
}

/// Whether a step commits something irreversible.
pub fn step_commits(step: AdmissionStep) -> bool {
    matches!(
        step,
        AdmissionStep::Rekey | AdmissionStep::SendWelcome | AdmissionStep::BurnInvite
    )
}

/// A welcome, as a receiver sees it after verifying it.
#[derive(Debug, Clone)]
pub struct VerifiedWelcome {
    pub generation: i64,
    pub opening_epoch: i64,
    /// How many member records the inviter says to expect.
    pub record_count: i64,
    /// The new generation's seed.
    pub seed: [u8; 32],
    /// The inviter's member id, already checked against the link's commitment.
    pub from: String,
}

/// Assemble a welcome from the records that arrived with it.
///
/// Fewer records than the welcome names is a refusal, not a partial join: a
/// circle that cannot see one of its own members is worse than one that was
/// never joined.
pub fn assemble(
    welcome: &VerifiedWelcome,
    records: &[MemberRecord],
    now: i64,
    welcome_verified_at: i64,
) -> Result<Vec<MemberRecord>, AssembleError> {
    if (records.len() as i64) < welcome.record_count {
        if now.saturating_sub(welcome_verified_at) < WELCOME_GRACE_MS {
            return Err(AssembleError::Waiting);
        }
        return Err(AssembleError::Incomplete {
            have: records.len() as i64,
            need: welcome.record_count,
        });
    }
    Ok(records[..welcome.record_count as usize].to_vec())
}

/// Why a welcome could not be assembled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssembleError {
    /// Not enough records yet, but the grace period has not elapsed.
    Waiting,
    /// Not enough records, and the grace period has passed. The join is refused.
    Incomplete { have: i64, need: i64 },
}

/// Build the sealed record for one existing member.
///
/// The record is *not* padded to 512 bytes, unlike every other body. It holds a
/// name, and padding would push a long name past the message ceiling. Instead
/// the name is dropped when the record would not fit, which is a visible but
/// harmless loss: the joiner learns the keypair and can show the name later.
pub fn build_member_record(
    inviter: &Identity,
    member: &crate::roster::Member,
    joiner: &Identity,
    invite_channel: &str,
    generation: i64,
) -> Option<InviteMsg> {
    let record = MemberRecord {
        alg: member.alg.as_str().to_string(),
        pk: member.pk.clone(),
        epk: member.epk.clone(),
        name: member.name.clone(),
    };

    let context = welcome_context_for(inviter.member_id(), joiner.member_id(), generation);
    let build = |rec: &MemberRecord| -> Option<InviteMsg> {
        let body = serde_json::to_string(rec).ok()?;
        let wrap = rekey::wrap_to(
            inviter,
            &joiner.epk_bytes(),
            invite_channel,
            joiner.member_id(),
            &context,
            body.as_bytes(),
        )?;
        Some(InviteMsg::Member { v: msg::VERSION, ts: 0, eph: wrap.eph, w: wrap.w })
    };

    let message = build(&record);
    // The ceiling is on the serialised outer message, since that is what the
    // relay bounds.
    let fits = |m: &InviteMsg| {
        serde_json::to_string(m)
            .map(|s| s.len() <= crate::wire::PAD_LEN - 64)
            .unwrap_or(false)
    };

    match message {
        Some(m) if fits(&m) => Some(m),
        // Retry without the name, which is the only variable-length field.
        _ => {
            let trimmed = MemberRecord { name: String::new(), ..record };
            build(&trimmed).filter(|m| fits(m))
        }
    }
}

/// A stable context for the member records belonging to one welcome.
///
/// Records are sent before the welcome, so the context cannot include the
/// welcome's generation number, which the inviter knows but has not published
/// yet. It is bound to the inviter and the joiner instead, which is what makes a
/// record useless to any other pair.
pub fn welcome_context_for(inviter: &str, joiner: &str, g: i64) -> String {
    format!("{}/record|{}|{}|{}", kdf::PROTO, inviter, joiner, g)
}

/// The joiner's side of the handshake, before any welcome has arrived.
pub struct PendingJoin {
    /// The joiner's own identity, generated for this attempt and held in memory
    /// only. It is never stored before a welcome arrives, so an abandoned
    /// attempt leaves nothing behind.
    pub identity: Identity,
    pub channel: String,
    pub key: ContentKey,
    pub requested_at: i64,
    pub safety_number: String,
}

impl PendingJoin {
    pub fn new(invite: &ParsedInvite, now: i64) -> Self {
        let (channel, key) = super::invite::rendezvous(invite);
        let identity = Identity::generate();
        Self {
            safety_number: identity.safety_number(),
            identity,
            channel,
            key,
            requested_at: now,
        }
    }

    /// The join request to post.
    pub fn request(&self, name: &str, ts: i64) -> Option<Post> {
        let body = InviteMsg::Join {
            v: msg::VERSION,
            ts,
            pk: self.identity.pk_b64(),
            epk: self.identity.epk_b64(),
            name: name.chars().take(msg::MAX_NAME).collect(),
        };
        let json = serde_json::to_string(&body).ok()?;
        seal::build_post(
            &self.identity,
            &self.channel,
            &self.key,
            crate::wire::epoch_at(ts),
            ts,
            &json,
        )
        .ok()
    }
}

/// Verify a welcome using the joining device's own keys.
///
/// This is the real entry point; [`read_welcome`] is the door check and this is
/// the complete one, including opening the wrap to the joiner.
pub fn verify_and_open_welcome(
    joiner: &Identity,
    post: &Post,
    body: &InviteMsg,
    invite: &ParsedInvite,
    now: i64,
) -> Option<VerifiedWelcome> {
    let InviteMsg::Welcome { g, e0, n, eph, w, .. } = body else {
        return None;
    };
    if *g < 0 || *e0 < 0 || *n < 1 || *n > WELCOME_MAX_RECORDS {
        return None;
    }
    if !rekey::e0_is_plausible(post.e, *e0, crate::wire::epoch_at(now)) {
        return None;
    }

    // Who wrote it. The link's commitment decides.
    let pk = post.pk_bytes()?;
    let epk = post.epk_bytes()?;
    if kdf::inviter_commitment(&pk, &epk) != invite.commitment {
        return None;
    }
    if kdf::member_id(&pk, &epk) != post.m {
        return None;
    }

    // Whether it was meant for this device. A welcome sealed to a different
    // joiner is refused *without being counted*, so one inviter admitting three
    // people at once does not consume the buffer three times over.
    let channel = kdf::invite_channel(&invite.secret);
    let context = rekey::welcome_context(&post.m, *g, *e0);
    let seed = rekey::open_seed(joiner, eph, w, &channel, &context)?;

    Some(VerifiedWelcome {
        generation: *g,
        opening_epoch: *e0,
        record_count: *n,
        seed,
        from: post.m.clone(),
    })
}

/// Open a member record that arrived alongside a welcome.
pub fn open_member_record(
    joiner: &Identity,
    inviter: &Identity,
    post: &Post,
    body: &InviteMsg,
    welcome: &VerifiedWelcome,
    invite: &ParsedInvite,
) -> Option<MemberRecord> {
    let InviteMsg::Member { eph, w, .. } = body else {
        return None;
    };
    // A record is only believed from the inviter the link committed to.
    if post.m != welcome.from {
        return None;
    }
    let channel = kdf::invite_channel(&invite.secret);
    let context =
        welcome_context_for(inviter.member_id(), joiner.member_id(), welcome.generation);
    let plain = rekey::open_wrap(joiner, eph, w, &channel, &context)?;
    serde_json::from_slice(&plain).ok()
}

/// The roster a joiner holds after assembling a welcome.
///
/// Their own identity is included, because a device does not otherwise pin
/// itself.
pub fn roster_after_join(
    joiner: &Identity,
    inviter: &Identity,
    records: &[MemberRecord],
    now: i64,
) -> Option<Roster> {
    let mut roster = Roster::new();
    let cap = crate::roster::LOCAL_CAP;
    for r in records {
        let id = kdf::member_id(&b64::decode(&r.pk)?, &b64::decode(&r.epk)?);
        roster.admit(&id, &r.pk, &r.epk, now, cap).map_err(|_| ()).ok()?;
    }
    // The inviter is in the records, but add them explicitly so a welcome that
    // omitted them still leaves a usable circle rather than an empty one.
    roster.admit(inviter.member_id(), &inviter.pk_b64(), &inviter.epk_b64(), now, cap).ok();
    let _ = joiner;
    Some(roster)
}

/// Whether a device may re-key the circle it is in.
///
/// Any member may. There is no administrator: a circle of family has no owner,
/// and a rule that only one device could rotate keys would mean that one device
/// has to be trusted in a way the protocol otherwise avoids.
///
/// The real constraint is generational. A re-key is only honoured from a member
/// of the *founding* roster of the current generation, so a member who has just
/// been added cannot immediately re-key and eject the circle.
pub fn may_rekey(
    sender: &str,
    founding_roster: &[String],
    generation: i64,
    claimed_generation: i64,
) -> bool {
    // Exactly the next generation, so two devices cannot both claim to open the
    // same one.
    claimed_generation == generation + 1 && founding_roster.iter().any(|id| id == sender)
}

/// How long a re-key's roster disagreement is tolerated before it is treated as
/// real.
///
/// A re-key in flight briefly makes everyone's roster differ, so a mismatch is
/// held rather than surfaced. Five minutes is long enough for a phone to wake and
/// poll, and short enough that a genuine split does not go unnoticed.
pub const ROSTER_GRACE_MS: i64 = 5 * 60 * 1000;

/// Whether a roster mismatch has waited long enough to be believed.
pub fn roster_mismatch_is_settled(first_seen: i64, now: i64) -> bool {
    now.saturating_sub(first_seen) >= ROSTER_GRACE_MS
}

/// A re-key a device received, checked but not yet applied.
///
/// Returned rather than applied so the caller controls when the chain advances.
/// Advancing before the backlog is read can drop a key a re-key sitting in the
/// relay still needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRekey {
    pub generation: i64,
    pub opening_epoch: i64,
    pub mix_epoch: i64,
    pub seed: [u8; 32],
    pub removed: Vec<String>,
    pub expected_roster_hash: String,
    pub by: String,
}

/// Check a re-key, without applying it.
#[allow(clippy::too_many_arguments)]
pub fn check_rekey(
    joiner: &Identity,
    post: &Post,
    body: &msg::CircleMsg,
    from_channel: &str,
    current_generation: i64,
    founding_roster: &[String],
    now: i64,
) -> Result<PendingRekey, RekeyError> {
    let msg::CircleMsg::ReKey { g, e0, me, to, rm, rh, .. } = body else {
        return Err(RekeyError::NotARekey);
    };
    if to != joiner.member_id() {
        return Err(RekeyError::NotAddressedToUs);
    }
    if !may_rekey(&post.m, founding_roster, current_generation, *g) {
        return Err(RekeyError::NotFromThisGeneration);
    }
    if !rekey::me_is_plausible(post.e, *me) {
        return Err(RekeyError::ImplausibleMixEpoch);
    }
    if !rekey::e0_is_plausible(post.e, *e0, crate::wire::epoch_at(now)) {
        return Err(RekeyError::ImplausibleOpeningEpoch);
    }
    // The removal list is filtered to well-formed ids before anything hashes it,
    // so a malformed entry cannot influence the roster hash.
    let removed: Vec<String> =
        rm.iter().filter(|id| kdf::is_member_id(id)).cloned().collect();

    let ctx = rekey::context_from_message(body, &post.m).ok_or(RekeyError::NotARekey)?;
    let (eph, w) = match body {
        msg::CircleMsg::ReKey { eph, w, .. } => (eph, w),
        _ => return Err(RekeyError::NotARekey),
    };
    let seed = rekey::open_seed(joiner, eph, w, from_channel, &ctx)
        .ok_or(RekeyError::Undecryptable)?;

    Ok(PendingRekey {
        generation: *g,
        opening_epoch: *e0,
        mix_epoch: *me,
        seed,
        removed,
        expected_roster_hash: rh.clone(),
        by: post.m.clone(),
    })
}

/// Why a re-key was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyError {
    NotARekey,
    NotAddressedToUs,
    /// Not from a member of this generation's founding roster, or claiming a
    /// generation other than the next one.
    NotFromThisGeneration,
    ImplausibleMixEpoch,
    ImplausibleOpeningEpoch,
    Undecryptable,
}

/// The tolerance on a generation number, kept here so a future caller cannot
/// invent a second one.
pub const GENERATION_TOLERANCE: i64 = 0;
const _: () = assert!(GENERATION_TOLERANCE == 0 && MAX_SKEW_EPOCHS == 2);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{invite::Invite, msg::CircleMsg, roster::LOCAL_CAP, wire::EPOCH_MS};
    use std::collections::BTreeSet;

    fn at(e: i64) -> i64 {
        e * EPOCH_MS
    }

    fn now() -> i64 {
        at(2980472)
    }

    /// Mint an invite and return it with the joiner, as a real flow would.
    fn a_handshake() -> (Identity, Invite, PendingJoin, ParsedInvite) {
        let inviter = Identity::generate();
        let invite = Invite::mint(&inviter, now(), 3_600_000);
        let parsed = crate::invite::parse_fragment(&invite.fragment()).unwrap();
        let join = PendingJoin::new(&parsed, now());
        (inviter, invite, join, parsed)
    }

    // --- the request ---

    #[test]
    fn a_join_request_is_sealed_under_the_invite_key() {
        let (inviter, invite, join, _) = a_handshake();
        let post = join.request("Cass", now()).expect("a request builds");
        // The inviter can open it, because the rendezvous key is derived from
        // the secret that the link carries.
        let opened = seal::verify_and_open(&post, &invite.channel(), &invite.key(), now())
            .expect("the inviter opens a join request");
        let body = msg::parse_invite(&opened.body).unwrap();
        let msg::InviteMsg::Join { pk, epk, name, .. } = &body else {
            panic!("not a join request")
        };
        assert_eq!(pk, &join.identity.pk_b64());
        assert_eq!(epk, &join.identity.epk_b64());
        assert_eq!(name, "Cass");
        assert_eq!(post.m, join.identity.member_id());
        let _ = inviter;
    }

    #[test]
    fn a_join_request_cannot_be_read_on_the_circle_channel() {
        let (_, _, join, _) = a_handshake();
        let post = join.request("Cass", now()).unwrap();
        let wrong = seal::ContentKey::new([0u8; 32]);
        assert!(seal::verify_and_open(&post, &join.channel, &wrong, now()).is_none());
    }

    // --- the welcome ---

    /// Build the welcome the inviter would post, and the re-key that creates the
    /// generation it names.
    fn a_welcome(
        inviter: &Identity,
        join: &PendingJoin,
        invite: &ParsedInvite,
        g: i64,
        e0: i64,
        records: i64,
    ) -> (Post, InviteMsg, [u8; 32]) {
        let channel = kdf::invite_channel(&invite.secret);
        let seed = [42u8; 32];
        let context = rekey::welcome_context(inviter.member_id(), g, e0);
        let wrap = rekey::wrap_to(
            inviter,
            &join.identity.epk_bytes(),
            &channel,
            join.identity.member_id(),
            &context,
            &seed,
        )
        .unwrap();
        let body = InviteMsg::Welcome {
            v: msg::VERSION,
            ts: now(),
            g,
            e0,
            n: records,
            eph: wrap.eph,
            w: wrap.w,
        };
        let json = serde_json::to_string(&body).unwrap();
        let post = seal::build_post(
            inviter,
            &channel,
            &seal::ContentKey::new(kdf::invite_key(&invite.secret)),
            crate::wire::epoch_at(now()),
            now(),
            &json,
        )
        .unwrap();
        let parsed = msg::parse_invite(&json).unwrap();
        (post, parsed, seed)
    }

    #[test]
    fn a_welcome_carries_the_new_generation_seed() {
        let (inviter, _, join, invite) = a_handshake();
        let (post, body, seed) = a_welcome(&inviter, &join, &invite, 1, 2980472, 1);
        let welcome = verify_and_open_welcome(&join.identity, &post, &body, &invite, now())
            .expect("a genuine welcome opens");
        assert_eq!(welcome.seed, seed);
        assert_eq!(welcome.generation, 1);
        assert_eq!(welcome.opening_epoch, 2980472);
        assert_eq!(welcome.from, inviter.member_id());
    }

    #[test]
    fn a_welcome_from_the_wrong_inviter_is_refused() {
        // The link carries a commitment to the inviter's keys. A device that
        // stole the link can post a join request, but any welcome it sends
        // fails here, so it cannot hand a circle to a keypair of its choosing.
        let (_, _, join, invite) = a_handshake();
        let attacker = Identity::generate();
        let (post, body, _) = a_welcome(&attacker, &join, &invite, 1, 2980472, 1);
        assert!(
            verify_and_open_welcome(&join.identity, &post, &body, &invite, now()).is_none()
        );
    }

    #[test]
    fn a_welcome_meant_for_another_joiner_is_refused_and_not_counted() {
        // One inviter admitting three people at once sends three welcomes, all
        // on the same rendezvous channel. Each is sealed to one joiner, so the
        // other two must be refused: a welcome the joiner cannot open is
        // addressed to somebody else, and counting it would let one inviter fill
        // a joiner's buffer three times over.
        let (inviter, _, mine, invite) = a_handshake();
        let theirs = PendingJoin::new(&invite, now());
        let (post, body, _) = a_welcome(&inviter, &theirs, &invite, 1, 2980472, 1);
        assert!(
            verify_and_open_welcome(&mine.identity, &post, &body, &invite, now()).is_none(),
            "a welcome sealed to another joiner must not open here"
        );
        // And the one addressed to us still opens, so the refusal is specific.
        let (post, body, seed) = a_welcome(&inviter, &mine, &invite, 1, 2980472, 1);
        assert_eq!(
            verify_and_open_welcome(&mine.identity, &post, &body, &invite, now())
                .map(|w| w.seed),
            Some(seed)
        );
    }

    #[test]
    fn a_welcome_with_an_implausible_opening_epoch_is_refused() {
        // Unbounded `e0` was a remote wipe: a receiver would try to walk its
        // chain to a year from now. The bound is against the message's own epoch,
        // which is what keeps a backlogged welcome valid while still refusing a
        // steered one.
        let (inviter, _, join, invite) = a_handshake();
        let (post, body, _) = a_welcome(&inviter, &join, &invite, 1, 2_980_000, 1);
        assert!(
            verify_and_open_welcome(&join.identity, &post, &body, &invite, now()).is_none()
        );
    }

    #[test]
    fn a_welcome_naming_no_records_is_refused() {
        let (inviter, _, join, invite) = a_handshake();
        for records in [0, -1, WELCOME_MAX_RECORDS + 1] {
            let (post, body, _) = a_welcome(&inviter, &join, &invite, 1, 2980472, records);
            assert!(
                verify_and_open_welcome(&join.identity, &post, &body, &invite, now())
                    .is_none(),
                "a welcome naming {records} records must be refused"
            );
        }
    }

    #[test]
    fn a_welcome_with_a_negative_generation_is_refused() {
        let (inviter, _, join, invite) = a_handshake();
        let (post, body, _) = a_welcome(&inviter, &join, &invite, -1, 2980472, 1);
        assert!(
            verify_and_open_welcome(&join.identity, &post, &body, &invite, now()).is_none()
        );
    }

    #[test]
    fn assembling_waits_then_refuses_rather_than_half_joining() {
        let welcome = VerifiedWelcome {
            generation: 1,
            opening_epoch: 2980472,
            record_count: 3,
            seed: [0u8; 32],
            from: "aa".into(),
        };
        let records = vec![MemberRecord {
            alg: "ed25519".into(),
            pk: "p".into(),
            epk: "e".into(),
            name: "A".into(),
        }];
        // Before the grace period: keep waiting.
        assert_eq!(assemble(&welcome, &records, now(), now()), Err(AssembleError::Waiting));
        assert_eq!(
            assemble(&welcome, &records, now() + WELCOME_GRACE_MS - 1, now()),
            Err(AssembleError::Waiting)
        );
        // After it: refuse, rather than joining a circle that cannot see itself.
        assert_eq!(
            assemble(&welcome, &records, now() + WELCOME_GRACE_MS, now()),
            Err(AssembleError::Incomplete { have: 1, need: 3 })
        );
    }

    #[test]
    fn assembling_succeeds_with_enough_records() {
        let welcome = VerifiedWelcome {
            generation: 1,
            opening_epoch: 2980472,
            record_count: 2,
            seed: [0u8; 32],
            from: "aa".into(),
        };
        let records: Vec<MemberRecord> = (0..3)
            .map(|i| MemberRecord {
                alg: "ed25519".into(),
                pk: format!("p{i}"),
                epk: format!("e{i}"),
                name: "A".into(),
            })
            .collect();
        let got = assemble(&welcome, &records, now(), now()).unwrap();
        assert_eq!(got.len(), 2, "only as many as the welcome named");
    }

    // --- records ---

    #[test]
    fn a_member_record_round_trips_to_a_joinable_roster() {
        let (inviter, _, join, invite) = a_handshake();
        let mut roster = Roster::new();
        roster
            .admit(
                inviter.member_id(),
                &inviter.pk_b64(),
                &inviter.epk_b64(),
                now(),
                LOCAL_CAP,
            )
            .unwrap();
        roster.set_name(inviter.member_id(), "Ana");

        let member = roster.get(inviter.member_id()).unwrap().clone();
        let record_msg =
            build_member_record(&inviter, &member, &join.identity, &invite.channel(), 1)
                .expect("a record builds");

        // Post it the way the inviter would, then open it as the joiner.
        let channel = kdf::invite_channel(&invite.secret);
        let json = serde_json::to_string(&record_msg).unwrap();
        let post = seal::build_post(
            &inviter,
            &channel,
            &seal::ContentKey::new(kdf::invite_key(&invite.secret)),
            crate::wire::epoch_at(now()),
            now(),
            &json,
        )
        .unwrap();

        let welcome = VerifiedWelcome {
            generation: 1,
            opening_epoch: 2980472,
            record_count: 1,
            seed: [0u8; 32],
            from: inviter.member_id().to_string(),
        };
        let record = open_member_record(
            &join.identity,
            &inviter,
            &post,
            &record_msg,
            &welcome,
            &invite,
        )
        .expect("the joiner opens a record addressed to them");
        assert_eq!(record.pk, inviter.pk_b64());
        assert_eq!(record.name, "Ana");

        let joined = roster_after_join(&join.identity, &inviter, &[record], now()).unwrap();
        assert!(joined.contains(inviter.member_id()));
    }

    #[test]
    fn a_record_from_someone_other_than_the_inviter_is_refused() {
        let (inviter, _, join, invite) = a_handshake();
        let mut roster = Roster::new();
        roster
            .admit(
                inviter.member_id(),
                &inviter.pk_b64(),
                &inviter.epk_b64(),
                now(),
                LOCAL_CAP,
            )
            .unwrap();
        let member = roster.get(inviter.member_id()).unwrap().clone();
        let record_msg =
            build_member_record(&inviter, &member, &join.identity, &invite.channel(), 1)
                .unwrap();

        let welcome = VerifiedWelcome {
            generation: 1,
            opening_epoch: 2980472,
            record_count: 1,
            seed: [0u8; 32],
            // Naming someone else: the record must not be believed.
            from: "00000000000000000000000000000000".into(),
        };
        assert!(
            open_member_record(
                &join.identity,
                &inviter,
                &post_for(&inviter, &invite, &record_msg),
                &record_msg,
                &welcome,
                &invite
            )
            .is_none()
        );
    }

    fn post_for(inviter: &Identity, invite: &ParsedInvite, body: &InviteMsg) -> Post {
        let channel = kdf::invite_channel(&invite.secret);
        let json = serde_json::to_string(body).unwrap();
        seal::build_post(
            inviter,
            &channel,
            &seal::ContentKey::new(kdf::invite_key(&invite.secret)),
            crate::wire::epoch_at(now()),
            now(),
            &json,
        )
        .unwrap()
    }

    #[test]
    fn a_long_name_is_dropped_rather_than_overflowing_the_ceiling() {
        let (inviter, _, join, invite) = a_handshake();
        let mut roster = Roster::new();
        roster
            .admit(
                inviter.member_id(),
                &inviter.pk_b64(),
                &inviter.epk_b64(),
                now(),
                LOCAL_CAP,
            )
            .unwrap();
        roster.set_name(inviter.member_id(), &"n".repeat(200));
        let member = roster.get(inviter.member_id()).unwrap().clone();
        let m =
            build_member_record(&inviter, &member, &join.identity, &invite.channel(), 1)
                .expect("the record still builds without the name");
        let json = serde_json::to_string(&m).unwrap();
        assert!(
            json.len() <= crate::wire::PAD_LEN,
            "the outer message must fit the plaintext ceiling, got {}",
            json.len()
        );
    }

    // --- the re-key, from the receiver's side ---

    /// The arguments a re-key needs, as a struct, so the call sites read as prose
    /// rather than as a list of positions.
    struct RekeySpec<'a> {
        g: i64,
        e0: i64,
        me: i64,
        removed: Vec<String>,
        rh: &'a str,
    }

    impl Default for RekeySpec<'_> {
        fn default() -> Self {
            Self { g: 1, e0: 2980472, me: 2980472, removed: vec![], rh: "hash" }
        }
    }

    /// Build a re-key the way the inviter would, for one recipient.
    fn a_rekey(
        inviter: &Identity,
        recipient: &Identity,
        from_channel: &str,
        spec: RekeySpec<'_>,
    ) -> (Post, CircleMsg) {
        let RekeySpec { g, e0, me, removed, rh } = spec;
        let mut rm = removed.clone();
        rm.sort();
        let ns = [7u8; 32];
        let body = rekey::build_rekey(
            inviter,
            &recipient.epk_bytes(),
            recipient.member_id(),
            from_channel,
            "irrelevant",
            g,
            e0,
            me,
            now(),
            rh,
            &rm,
            &ns,
            &ns,
        )
        .unwrap();
        let key = ContentKey::new(kdf::msg_key(&kdf::chain0(&ns), inviter.member_id()));
        let json = serde_json::to_string(&body).unwrap();
        let post = seal::build_post(
            inviter,
            from_channel,
            &key,
            crate::wire::epoch_at(now()),
            now(),
            &json,
        )
        .unwrap();
        let parsed = msg::parse_circle(&json).unwrap();
        (post, parsed)
    }

    #[test]
    fn a_rekey_addressed_to_us_is_accepted() {
        let inviter = Identity::generate();
        let me = Identity::generate();
        let channel = "f1c695a80bae6baf8bb34828bc177bc9";
        let (post, body) = a_rekey(&inviter, &me, channel, RekeySpec::default());
        let founding = vec![inviter.member_id().to_string()];
        let pending = check_rekey(&me, &post, &body, channel, 0, &founding, now())
            .expect("a re-key from a founding member is accepted");
        assert_eq!(pending.generation, 1);
        assert_eq!(pending.by, inviter.member_id());
        assert!(pending.removed.is_empty());
    }

    #[test]
    fn a_rekey_from_a_stranger_is_refused() {
        let inviter = Identity::generate();
        let me = Identity::generate();
        let stranger = Identity::generate();
        let channel = "f1c695a80bae6baf8bb34828bc177bc9";
        let (post, body) = a_rekey(&stranger, &me, channel, RekeySpec::default());
        let founding = vec![inviter.member_id().to_string()];
        assert_eq!(
            check_rekey(&me, &post, &body, channel, 0, &founding, now()),
            Err(RekeyError::NotFromThisGeneration)
        );
    }

    #[test]
    fn a_rekey_addressed_to_someone_else_is_refused() {
        let inviter = Identity::generate();
        let me = Identity::generate();
        let other = Identity::generate();
        let channel = "f1c695a80bae6baf8bb34828bc177bc9";
        let (post, body) = a_rekey(&inviter, &other, channel, RekeySpec::default());
        let founding = vec![inviter.member_id().to_string()];
        assert_eq!(
            check_rekey(&me, &post, &body, channel, 0, &founding, now()),
            Err(RekeyError::NotAddressedToUs)
        );
    }

    #[test]
    fn a_rekey_claiming_the_wrong_generation_is_refused() {
        // Two devices must not both be able to claim to open the same
        // generation, so the claim must be exactly the next one.
        let inviter = Identity::generate();
        let me = Identity::generate();
        let channel = "f1c695a80bae6baf8bb34828bc177bc9";
        let founding = vec![inviter.member_id().to_string()];
        for g in [0, 2, 5] {
            let (post, body) =
                a_rekey(&inviter, &me, channel, RekeySpec { g, ..Default::default() });
            assert_eq!(
                check_rekey(&me, &post, &body, channel, 0, &founding, now()),
                Err(RekeyError::NotFromThisGeneration),
                "generation {g} must be refused"
            );
        }
        // And the right one, from a later starting point.
        let (post, body) =
            a_rekey(&inviter, &me, channel, RekeySpec { g: 4, ..Default::default() });
        assert!(check_rekey(&me, &post, &body, channel, 3, &founding, now()).is_ok());
    }

    #[test]
    fn a_rekey_with_a_future_mix_epoch_is_refused() {
        let inviter = Identity::generate();
        let me = Identity::generate();
        let channel = "f1c695a80bae6baf8bb34828bc177bc9";
        let founding = vec![inviter.member_id().to_string()];
        // The mix epoch names an epoch whose chain key must already exist, so it
        // cannot be ahead of the message that carries it. The post's own epoch
        // here is 2980472, so anything later is refused.
        let (post, body) = a_rekey(
            &inviter,
            &me,
            channel,
            RekeySpec { me: 2_980_490, ..Default::default() },
        );
        assert_eq!(post.e, 2980472);
        assert_eq!(
            check_rekey(&me, &post, &body, channel, 0, &founding, now()),
            Err(RekeyError::ImplausibleMixEpoch)
        );
        // And the same mix epoch is accepted when it is the message's own.
        let (post, body) = a_rekey(&inviter, &me, channel, RekeySpec::default());
        assert!(check_rekey(&me, &post, &body, channel, 0, &founding, now()).is_ok());
    }

    #[test]
    fn a_rekey_with_a_steered_opening_epoch_is_refused() {
        let inviter = Identity::generate();
        let me = Identity::generate();
        let channel = "f1c695a80bae6baf8bb34828bc177bc9";
        let founding = vec![inviter.member_id().to_string()];
        let (post, body) = a_rekey(
            &inviter,
            &me,
            channel,
            RekeySpec { e0: 2_980_000, ..Default::default() },
        );
        assert_eq!(
            check_rekey(&me, &post, &body, channel, 0, &founding, now()),
            Err(RekeyError::ImplausibleOpeningEpoch)
        );
    }

    #[test]
    fn a_removal_is_carried_and_its_list_is_filtered() {
        let inviter = Identity::generate();
        let me = Identity::generate();
        let channel = "f1c695a80bae6baf8bb34828bc177bc9";
        let founding = vec![inviter.member_id().to_string()];
        // A malformed id must not reach the roster hash.
        let (post, body) = a_rekey(
            &inviter,
            &me,
            channel,
            RekeySpec { removed: vec!["not-a-member-id".into()], ..Default::default() },
        );
        let pending = check_rekey(&me, &post, &body, channel, 0, &founding, now()).unwrap();
        assert!(pending.removed.is_empty(), "a malformed id is dropped");
    }

    // --- authority ---

    #[test]
    fn any_founding_member_may_rekey() {
        // No administrator: a circle of family has no owner.
        let ids: Vec<String> =
            (0..3).map(|_| Identity::generate().member_id().to_string()).collect();
        for id in &ids {
            assert!(may_rekey(id, &ids, 0, 1));
        }
    }

    #[test]
    fn a_member_added_this_generation_may_not_rekey_yet() {
        let ids: Vec<String> =
            (0..2).map(|_| Identity::generate().member_id().to_string()).collect();
        let newcomer = Identity::generate().member_id().to_string();
        assert!(!may_rekey(&newcomer, &ids, 0, 1));
    }

    // --- the plan ---

    #[test]
    fn the_admission_plan_is_claim_then_rekey_then_records_then_welcome_then_burn() {
        assert_eq!(
            ADMISSION_PLAN,
            [
                AdmissionStep::ClaimSlot,
                AdmissionStep::Rekey,
                AdmissionStep::SendRecords,
                AdmissionStep::SendWelcome,
                AdmissionStep::BurnInvite,
            ]
        );
    }

    #[test]
    fn a_failed_welcome_is_undone_by_removing_the_admitted_member() {
        // The failed attempt's seed is destroyed, so the joiner cannot follow
        // the circle to its next channel by any route.
        assert_eq!(undo_for(AdmissionStep::SendWelcome, "x"), Undo::RemoveNewMember);
        assert_eq!(undo_for(AdmissionStep::SendRecords, "x"), Undo::Nothing);
    }

    #[test]
    fn a_roster_mismatch_is_settled_after_the_grace_period() {
        assert!(!roster_mismatch_is_settled(now(), now()));
        assert!(!roster_mismatch_is_settled(now(), now() + ROSTER_GRACE_MS - 1));
        assert!(roster_mismatch_is_settled(now(), now() + ROSTER_GRACE_MS));
    }

    #[test]
    fn the_record_context_binds_both_parties() {
        let a = welcome_context_for("inviter", "joiner", 1);
        let b = welcome_context_for("inviter", "other", 1);
        let c = welcome_context_for("other", "joiner", 1);
        assert_ne!(a, b);
        assert_ne!(a, c);
        // And it names the protocol, so it cannot collide with a re-key context.
        assert!(a.starts_with("starling/v2/"));
    }

    #[test]
    fn a_set_of_founding_members_is_ordered_independently() {
        // The roster hash must not depend on the order members were admitted.
        let a = Identity::generate().member_id().to_string();
        let b = Identity::generate().member_id().to_string();
        let mut one = BTreeSet::new();
        one.insert(a.clone());
        one.insert(b.clone());
        let mut two = BTreeSet::new();
        two.insert(b);
        two.insert(a);
        let v1: Vec<&String> = one.iter().collect();
        let v2: Vec<&String> = two.iter().collect();
        assert_eq!(
            kdf::roster_hash(&v1.into_iter().cloned().collect::<Vec<_>>()),
            kdf::roster_hash(&v2.into_iter().cloned().collect::<Vec<_>>())
        );
    }
}
