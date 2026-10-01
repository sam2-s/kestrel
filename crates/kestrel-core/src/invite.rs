//! Invitations: minting one, and accepting one.
//!
//! An invitation is a fragment, never a URL that gets fetched. The secret
//! travels after the `#`, so it is not in any request, log, or referrer, and the
//! page it lands on cannot learn it.
//!
//! What makes a stolen link inert is the commitment beside the secret. The link
//! carries a hash of the inviter's own public keys, so a device that holds one
//! can only ever *ask*. It cannot present itself as the inviter, and a welcome
//! is believed only when the signing key matches that commitment. A stolen link
//! is therefore good for one join request against one inviter, and nothing more
//! — and even that request is refused until the real inviter comes back and
//! accepts a safety number they were not expecting.

use crate::{b64, identity::Identity, kdf, seal::random_bytes, wire::INVITE_TTL_MS};

/// Length of the invitation secret, and of the secret encoded in a fragment.
pub const SECRET_LEN: usize = 32;

/// Length of the inviter's commitment.
pub const COMMITMENT_LEN: usize = 16;

/// An invitation this device minted.
#[derive(Clone)]
pub struct Invite {
    /// The rendezvous secret. The circle key is not derived from this, so a
    /// leaked invitation does not expose the circle.
    secret: [u8; SECRET_LEN],
    /// The inviter's member id, so a device holding several circles answers a
    /// link only from the circle that issued it.
    by: String,
    commitment: [u8; COMMITMENT_LEN],
    created_at: i64,
    expires_at: i64,
}

impl Invite {
    /// Mint an invitation.
    ///
    /// One live invitation at a time: minting a new one replaces the old, so a
    /// link shared earlier stops working rather than lingering as a second way
    /// in.
    pub fn mint(identity: &Identity, now: i64, ttl_ms: i64) -> Self {
        let secret = random_bytes::<SECRET_LEN>();
        let commitment =
            kdf::inviter_commitment(&identity.pk_bytes(), &identity.epk_bytes());
        Self {
            secret,
            by: identity.member_id().to_string(),
            commitment,
            created_at: now,
            expires_at: now + ttl_ms.max(0),
        }
    }

    pub fn secret(&self) -> &[u8; SECRET_LEN] {
        &self.secret
    }

    pub fn inviter(&self) -> &str {
        &self.by
    }

    pub fn created_at(&self) -> i64 {
        self.created_at
    }

    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// The rendezvous channel this invitation meets on.
    ///
    /// Derived from the secret, so two invitations never share a channel and the
    /// relay cannot tell a rendezvous from a circle.
    pub fn channel(&self) -> String {
        kdf::invite_channel(&self.secret)
    }

    /// The key that seals the handshake on the rendezvous channel.
    pub fn key(&self) -> crate::seal::ContentKey {
        crate::seal::ContentKey::new(kdf::invite_key(&self.secret))
    }

    /// The fragment to share: `#j=` then the secret, a dot, and the commitment.
    ///
    /// Exactly 43 characters, a dot, then 22. A fragment of any other shape is
    /// refused rather than half-accepted, because accepting a near-miss would
    /// leave an older bearer-token invitation working.
    pub fn fragment(&self) -> String {
        format!("#j={}.{}", b64::encode(&self.secret), b64::encode(&self.commitment))
    }

    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.expires_at
    }

    /// Whether a post's sender is the inviter this invitation was minted by.
    ///
    /// Checked on the door, when a message is buffered, not only when it is
    /// opened. A welcome sealed to a different joiner must not even occupy
    /// buffer space, and this is the only way to know before opening it.
    pub fn is_from_inviter(&self, post_member: &str) -> bool {
        post_member == self.by
    }

    /// The commitment, for verifying a welcome's sender.
    pub fn commitment_bytes(&self) -> &[u8; COMMITMENT_LEN] {
        &self.commitment
    }

    /// Whether a member id and its keys satisfy this invitation's commitment.
    ///
    /// The check that makes the link inert. The member id already commits to
    /// both keys, so requiring the id to hash to the commitment pins the signing
    /// key that a welcome must carry.
    pub fn commitment_matches(&self, member_id: &str, pk: &[u8], epk: &[u8]) -> bool {
        kdf::member_id(pk, epk) == member_id
            && kdf::inviter_commitment(pk, epk) == self.commitment
    }
}

/// A parsed invitation, held by the joining device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedInvite {
    pub secret: [u8; SECRET_LEN],
    pub commitment: [u8; COMMITMENT_LEN],
}

impl ParsedInvite {
    /// The rendezvous channel this link names, derived from its secret.
    pub fn channel(&self) -> String {
        kdf::invite_channel(&self.secret)
    }

    /// The key that seals the handshake on the rendezvous channel.
    pub fn key(&self) -> crate::seal::ContentKey {
        crate::seal::ContentKey::new(kdf::invite_key(&self.secret))
    }
}

/// Parse an invitation fragment.
///
/// Accepts the fragment with or without the `#j=` prefix, so a code copied out of
/// a message works as well as a link. Anything that is not exactly 43 characters
/// and a dot and 22 characters is refused outright.
pub fn parse_fragment(fragment: &str) -> Option<ParsedInvite> {
    let body = fragment.trim().trim_start_matches('#').trim_start_matches("j=");

    let (secret_s, commit_s) = body.split_once('.')?;
    if secret_s.len() != 43 || commit_s.len() != 22 {
        return None;
    }
    if !b64::looks_like_key(secret_s) || !b64::looks_like_key(commit_s) {
        return None;
    }

    let secret: [u8; SECRET_LEN] = b64::decode_exact(secret_s)?;
    let commitment: [u8; COMMITMENT_LEN] = b64::decode_exact(commit_s)?;
    Some(ParsedInvite { secret, commitment })
}

/// A parsed invitation's rendezvous channel and key.
pub fn rendezvous(parsed: &ParsedInvite) -> (String, crate::seal::ContentKey) {
    (
        kdf::invite_channel(&parsed.secret),
        crate::seal::ContentKey::new(kdf::invite_key(&parsed.secret)),
    )
}

/// Default lifetime for an invitation.
pub const DEFAULT_TTL_MS: i64 = INVITE_TTL_MS;

/// Why a join request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenError {
    /// The invitation has expired.
    Expired,
    /// The message was not a join request.
    NotARequest,
    /// The presented keys do not match the ones the message was signed with.
    KeysMismatch,
    /// The keys are not decodable, or the agreement key is not a curve point.
    BadKeys,
    /// The requester is already a member.
    AlreadyMember,
    /// The requester has already asked, and is waiting to be let in.
    AlreadyPending,
    /// The circle has no room.
    NoRoom,
}

/// The outcome of screening a join request, as data.
///
/// A joiner waiting to be let in is a person, not a packet, so this ends in a
/// safety number the inviter reads. Returning a value rather than a bool keeps
/// the screens and the reasons in one place, which is where a subtle mistake
/// would otherwise hide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screen {
    /// Show this safety number and let the inviter decide.
    ShowSafetyNumber { member_id: String, safety_number: String },
}

/// Screen a join request, before any human sees it.
///
/// Every check is cheap and mechanical; none of them is the trust decision. The
/// trust decision is the inviter comparing a safety number in person.
pub fn screen_join_request(
    invite: &Invite,
    post: &crate::wire::Post,
    body: &crate::msg::InviteMsg,
    now: i64,
    already_member: bool,
    already_pending: bool,
    has_room: bool,
) -> Result<Screen, ScreenError> {
    if invite.is_expired(now) {
        return Err(ScreenError::Expired);
    }

    // The sender is deliberately *not* checked against the inviter here. A join
    // request comes from a stranger by definition; that is the whole point of
    // the screen. Requiring the inviter here would reject every real request.
    // What must hold instead is that the requester is not already inside, which
    // is checked below.
    let crate::msg::InviteMsg::Join { pk, epk, .. } = body else {
        return Err(ScreenError::NotARequest);
    };

    // The keys in the body must be the keys the post was signed with. A
    // request that advertises one keypair and signs with another is showing the
    // inviter a safety number for a device that is not the one asking.
    let posted_pk = post.pk_bytes().ok_or(ScreenError::BadKeys)?;
    let posted_epk = post.epk_bytes().ok_or(ScreenError::BadKeys)?;
    if !crate::roster::same_key(pk, &b64::encode(&posted_pk))
        || !crate::roster::same_key(epk, &b64::encode(&posted_epk))
    {
        return Err(ScreenError::KeysMismatch);
    }

    if !crate::identity::valid_ecdh_key(&posted_epk) {
        return Err(ScreenError::BadKeys);
    }
    if already_member {
        return Err(ScreenError::AlreadyMember);
    }
    if already_pending {
        return Err(ScreenError::AlreadyPending);
    }
    if !has_room {
        return Err(ScreenError::NoRoom);
    }

    Ok(Screen::ShowSafetyNumber {
        member_id: post.m.clone(),
        safety_number: crate::identity::safety_number_for(&posted_pk, &posted_epk),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{msg, seal, wire};

    fn an_invite(identity: &Identity) -> Invite {
        Invite::mint(identity, 1_000_000, DEFAULT_TTL_MS)
    }

    #[test]
    fn a_fragment_is_exactly_the_documented_shape() {
        let inviter = Identity::generate();
        let invite = an_invite(&inviter);
        let f = invite.fragment();
        assert!(f.starts_with("#j="));
        let body = &f[3..];
        let (secret, commit) = body.split_once('.').unwrap();
        assert_eq!(secret.len(), 43, "32 bytes is 43 base64url characters");
        assert_eq!(commit.len(), 22, "16 bytes is 22 base64url characters");
    }

    #[test]
    fn a_fragment_round_trips() {
        let inviter = Identity::generate();
        let invite = an_invite(&inviter);
        let parsed = parse_fragment(&invite.fragment()).expect("our own fragment parses");
        assert_eq!(parsed.secret, *invite.secret());
        assert_eq!(parsed.commitment, *invite.commitment_bytes());
    }

    #[test]
    fn a_fragment_parses_with_or_without_its_prefix() {
        let inviter = Identity::generate();
        let invite = an_invite(&inviter);
        let f = invite.fragment();
        let parsed = parse_fragment(&f).unwrap();
        // The same code pasted into a message, without the marker.
        assert_eq!(parse_fragment(&f[3..]), Some(parsed));
        assert_eq!(parse_fragment(f.trim()), Some(parse_fragment(&f).unwrap()));
    }

    #[test]
    fn a_malformed_fragment_is_refused_rather_than_half_accepted() {
        // A near-miss that is leniently accepted would keep an older
        // bearer-token invitation working.
        let inviter = Identity::generate();
        let good = an_invite(&inviter).fragment();
        let body = &good[3..];
        let (secret, commit) = body.split_once('.').unwrap();

        assert!(parse_fragment("").is_none());
        assert!(parse_fragment("#j=").is_none());
        assert!(parse_fragment(&format!("#j={secret}")).is_none(), "no commitment");
        assert!(parse_fragment(&format!("#j={secret}.{commit}extra")).is_none());
        assert!(
            parse_fragment(&format!("#j={}.{commit}", &secret[..42])).is_none(),
            "short secret"
        );
        assert!(parse_fragment(&format!("#j={secret}x.{commit}")).is_none(), "long secret");
        assert!(
            parse_fragment(&format!("#j={secret}.{}", &commit[..21])).is_none(),
            "short commitment"
        );
        assert!(parse_fragment(&format!("#j={secret}.{commit}=")).is_none(), "padded");
        // A character outside the URL-safe alphabet, in place of one inside it.
        let foreign = format!("{}!{}", &commit[..21], &commit[21..]);
        assert!(parse_fragment(&format!("#j={secret}.{foreign}")).is_none());
        // And the standard base64 alphabet, which is a different scheme.
        let standard = b64::encode(&[0u8; 16]);
        if standard.contains('+') || standard.contains('/') {
            assert!(parse_fragment(&format!("#j={secret}.{standard}")).is_none());
        }
    }

    #[test]
    fn a_secret_of_the_wrong_length_is_refused() {
        let f = format!("#j={}.{}", b64::encode(&[0u8; 31]), b64::encode(&[0u8; 16]));
        assert!(parse_fragment(&f).is_none());
    }

    #[test]
    fn two_invitations_never_share_a_channel() {
        let inviter = Identity::generate();
        let a = an_invite(&inviter);
        let b = an_invite(&inviter);
        assert_ne!(a.channel(), b.channel());
        assert_ne!(a.secret(), b.secret());
    }

    #[test]
    fn a_channel_is_a_thirty_two_character_lowercase_hex_name() {
        let inviter = Identity::generate();
        let invite = an_invite(&inviter);
        let ch = invite.channel();
        assert_eq!(ch.len(), 32);
        assert!(kdf::is_member_id(&ch), "a channel looks like a member id");
    }

    #[test]
    fn an_invitation_expires() {
        let inviter = Identity::generate();
        let invite = Invite::mint(&inviter, 1_000, 3_600_000);
        assert!(!invite.is_expired(1_000));
        assert!(!invite.is_expired(1_000 + 3_599_999));
        assert!(invite.is_expired(1_000 + 3_600_000));
    }

    #[test]
    fn a_zero_lifetime_expires_immediately() {
        let inviter = Identity::generate();
        let invite = Invite::mint(&inviter, 1_000, 0);
        assert!(invite.is_expired(1_000));
    }

    #[test]
    fn only_the_minting_inviter_is_recognised() {
        let inviter = Identity::generate();
        let stranger = Identity::generate();
        let invite = an_invite(&inviter);
        assert!(invite.is_from_inviter(inviter.member_id()));
        assert!(!invite.is_from_inviter(stranger.member_id()));
    }

    #[test]
    fn the_commitment_pins_the_inviter_keys() {
        let inviter = Identity::generate();
        let other = Identity::generate();
        let invite = an_invite(&inviter);
        assert!(invite.commitment_matches(
            inviter.member_id(),
            &inviter.pk_bytes(),
            &inviter.epk_bytes()
        ));
        // A different keypair does not satisfy it, even with a matching id claim.
        assert!(!invite.commitment_matches(
            inviter.member_id(),
            &other.pk_bytes(),
            &other.epk_bytes()
        ));
        assert!(!invite.commitment_matches(
            other.member_id(),
            &other.pk_bytes(),
            &other.epk_bytes()
        ));
    }

    #[test]
    fn a_third_party_who_holds_the_secret_still_cannot_forge_a_welcome() {
        // The whole point of the commitment: possessing the link is not
        // authority. An attacker with the link can send a join request, and
        // every welcome they send fails this check.
        let inviter = Identity::generate();
        let attacker = Identity::generate();
        let invite = an_invite(&inviter);
        assert!(
            !invite.commitment_matches(
                attacker.member_id(),
                &attacker.pk_bytes(),
                &attacker.epk_bytes()
            ),
            "holding the secret must not make a device the inviter"
        );
    }

    #[test]
    fn the_rendezvous_matches_the_fragment() {
        let inviter = Identity::generate();
        let invite = an_invite(&inviter);
        let parsed = parse_fragment(&invite.fragment()).unwrap();
        let (channel, key) = rendezvous(&parsed);
        assert_eq!(channel, invite.channel());
        // The same key both sides derive.
        assert_eq!(*key.as_bytes(), *invite.key().as_bytes());
    }

    // --- screening a join request ---

    /// Build a real join request from a real joiner, sealed under the invite
    /// key and signed by the joiner.
    fn a_join_request(
        joiner: &Identity,
        invite: &Invite,
        ts: i64,
    ) -> (wire::Post, msg::InviteMsg) {
        let body = msg::InviteMsg::Join {
            v: msg::VERSION,
            ts,
            pk: joiner.pk_b64(),
            epk: joiner.epk_b64(),
            name: "Cass".to_string(),
        };
        let json = serde_json::to_string(&body).unwrap();
        let epoch = wire::epoch_at(ts);
        let post =
            seal::build_post(joiner, &invite.channel(), &invite.key(), epoch, ts, &json)
                .expect("a join request builds");
        let back = seal::verify_and_open(&post, &invite.channel(), &invite.key(), ts)
            .expect("and opens again");
        let parsed = msg::parse_invite(&back.body).expect("and parses");
        (post, parsed)
    }

    #[test]
    fn a_valid_request_shows_a_safety_number() {
        let inviter = Identity::generate();
        let joiner = Identity::generate();
        let invite = an_invite(&inviter);
        let now = 1_000_100;
        let (post, body) = a_join_request(&joiner, &invite, now);

        let screen = screen_join_request(&invite, &post, &body, now, false, false, true)
            .expect("a valid request is shown to the inviter");
        match screen {
            Screen::ShowSafetyNumber { member_id, safety_number } => {
                assert_eq!(member_id, joiner.member_id());
                assert_eq!(safety_number, joiner.safety_number());
            }
        }
    }

    #[test]
    fn an_expired_invitation_screens_nothing() {
        let inviter = Identity::generate();
        let joiner = Identity::generate();
        let invite = Invite::mint(&inviter, 0, 1_000);
        let (post, body) = a_join_request(&joiner, &invite, 10);
        assert_eq!(
            screen_join_request(&invite, &post, &body, 5_000, false, false, true),
            Err(ScreenError::Expired)
        );
    }

    #[test]
    fn a_request_from_a_stranger_is_the_normal_case() {
        // The requester is by definition not the inviter, so screening must not
        // require it. This is the test that would fail if someone "hardened" the
        // screen by adding that check.
        let inviter = Identity::generate();
        let joiner = Identity::generate();
        let invite = an_invite(&inviter);
        let (post, body) = a_join_request(&joiner, &invite, 1_100);
        assert_ne!(post.m, inviter.member_id());
        assert!(
            screen_join_request(&invite, &post, &body, 1_100, false, false, true).is_ok()
        );
    }

    #[test]
    fn the_inviter_check_belongs_to_the_welcome_not_the_request() {
        // The inviter identity is verified when a welcome arrives at the
        // joiner, against the commitment in the link. A request carries no such
        // claim, so there is nothing to check.
        let inviter = Identity::generate();
        let joiner = Identity::generate();
        let invite = an_invite(&inviter);
        assert!(invite.is_from_inviter(inviter.member_id()));
        assert!(!invite.is_from_inviter(joiner.member_id()));
    }

    #[test]
    fn a_request_advertising_one_keypair_and_signing_with_another_is_refused() {
        // Otherwise the inviter is shown a safety number for a device that is
        // not the one asking, which is the whole point of showing it.
        let inviter = Identity::generate();
        let joiner = Identity::generate();
        let other = Identity::generate();
        let invite = an_invite(&inviter);
        let (post, _) = a_join_request(&joiner, &invite, 1_100);

        let body = msg::InviteMsg::Join {
            v: msg::VERSION,
            ts: 1_100,
            pk: other.pk_b64(),
            epk: other.epk_b64(),
            name: "Cass".to_string(),
        };
        assert_eq!(
            screen_join_request(&invite, &post, &body, 1_100, false, false, true),
            Err(ScreenError::KeysMismatch)
        );
    }

    #[test]
    fn a_message_that_is_not_a_join_request_is_refused() {
        let inviter = Identity::generate();
        let joiner = Identity::generate();
        let invite = an_invite(&inviter);
        let (post, _) = a_join_request(&joiner, &invite, 1_100);
        let other = msg::InviteMsg::Ack { v: msg::VERSION, ts: 1_100, to: "x".into() };
        assert_eq!(
            screen_join_request(&invite, &post, &other, 1_100, false, false, true),
            Err(ScreenError::NotARequest)
        );
    }

    #[test]
    fn a_second_request_from_the_same_joiner_is_not_shown_twice() {
        let inviter = Identity::generate();
        let joiner = Identity::generate();
        let invite = an_invite(&inviter);
        let (post, body) = a_join_request(&joiner, &invite, 1_100);
        assert_eq!(
            screen_join_request(&invite, &post, &body, 1_100, false, true, true),
            Err(ScreenError::AlreadyPending)
        );
    }

    #[test]
    fn an_existing_member_asking_again_is_refused() {
        let inviter = Identity::generate();
        let joiner = Identity::generate();
        let invite = an_invite(&inviter);
        let (post, body) = a_join_request(&joiner, &invite, 1_100);
        assert_eq!(
            screen_join_request(&invite, &post, &body, 1_100, true, false, true),
            Err(ScreenError::AlreadyMember)
        );
    }

    #[test]
    fn a_full_circle_admits_nobody() {
        let inviter = Identity::generate();
        let joiner = Identity::generate();
        let invite = an_invite(&inviter);
        let (post, body) = a_join_request(&joiner, &invite, 1_100);
        assert_eq!(
            screen_join_request(&invite, &post, &body, 1_100, false, false, false),
            Err(ScreenError::NoRoom)
        );
    }

    #[test]
    fn the_default_lifetime_is_one_hour() {
        assert_eq!(DEFAULT_TTL_MS, 3_600_000);
    }
}
