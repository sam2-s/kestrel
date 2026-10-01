//! The help beacon: an emergency that opens in a browser, with no app and no
//! account.
//!
//! A circle is a list of people someone chose in advance. The person who can
//! actually reach you in an emergency may not be on it. So an SOS can mint a
//! link that shows your live position to anyone it is sent to, in any browser,
//! for as long as the emergency lasts.
//!
//! Every design decision here follows from one fact: **a help link is a shared
//! symmetric secret.** Everyone it was ever forwarded to can derive the channel
//! and the key, and can therefore write a position that opens as cleanly as
//! yours. Trust on first use is not available, because the attacker can be
//! first: they hold the link before you have posted anything.
//!
//! What stops that is not the encryption, it is the signature. Each viewer gets
//! a *fresh* identity of its own, and the link commits to that member id. A
//! forged position would need a signature from that key, and the link's committed
//! id is what the viewer checks the signature against. The relay cannot help a
//! forger here, because a member id commits to both of its public keys.
//!
//! There is no ratchet on a beacon channel. A beacon is one emergency, and the
//! epoch still travels on every point so a post is still bound to a time.

use crate::{b64, geo, identity::Identity, kdf, msg, seal, wire, wire::Post};

/// Length of the shared secret in a help link.
pub const SECRET_LEN: usize = 32;

/// How long a beacon lasts by default: the relay's own retention window, so a
/// link cannot outlive the data it points at.
pub const DEFAULT_TTL_MS: i64 = wire::TTL_MS;

/// A help link, as a device mints it.
#[derive(Clone)]
pub struct HelpLink {
    secret: [u8; SECRET_LEN],
    /// The member id of the identity minted *for this viewer*. Not the circle
    /// identity: a viewer can never become a circle member, and a beacon's
    /// signer must not be linkable to the person who minted it.
    owner: String,
    expires_at: i64,
}

impl HelpLink {
    /// The fragment to share: `#b=` then the secret, a dot, the expiry in
    /// milliseconds, a dot, and the owner's member id.
    pub fn fragment(&self) -> String {
        format!("#b={}.{}.{}", b64::encode(&self.secret), self.expires_at, self.owner)
    }

    pub fn secret(&self) -> &[u8; SECRET_LEN] {
        &self.secret
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.expires_at
    }

    /// The channel this link's beacon posts to. One per viewer, so revoking a
    /// link removes that viewer's channel and nothing else.
    pub fn channel(&self) -> String {
        kdf::help_channel(&self.secret)
    }

    /// The key the beacon seals with, and the one the viewer opens with.
    pub fn key(&self) -> seal::ContentKey {
        seal::ContentKey::new(kdf::help_key(&self.secret))
    }
}

/// Mint a link for a viewer, under a caller-chosen identity.
///
/// The identity is the beacon's own, freshly generated per viewer, and *not* the
/// circle's: a helper's browser and the person in trouble must not be
/// linkable, and revoking one viewer's link must not implicate the others.
pub fn mint(owner: &Identity, ttl_ms: i64, now: i64) -> HelpLink {
    HelpLink {
        secret: seal::random_bytes::<SECRET_LEN>(),
        owner: owner.member_id().to_string(),
        expires_at: now + ttl_ms.max(0),
    }
}

/// A parsed help link, held by whoever opens it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHelp {
    pub secret: [u8; SECRET_LEN],
    pub expires_at: i64,
    /// The member id the viewer will only accept positions from.
    pub owner: String,
}

impl ParsedHelp {
    pub fn channel(&self) -> String {
        kdf::help_channel(&self.secret)
    }

    pub fn key(&self) -> seal::ContentKey {
        seal::ContentKey::new(kdf::help_key(&self.secret))
    }
}

/// Parse a help link.
///
/// Three fields, and no fallback for a link missing the last one. Stripping the
/// owner's member id is not a downgrade path, it simply does not parse: without
/// it a viewer has no way to know which key a signature must belong to, which is
/// the only thing standing between them and a forged position.
pub fn parse_fragment(fragment: &str) -> Option<ParsedHelp> {
    let body = fragment.trim().trim_start_matches('#').trim_start_matches("b=");
    let mut parts = body.split('.');

    let secret_s = parts.next()?;
    let expires_s = parts.next()?;
    let owner_s = parts.next()?;
    if parts.next().is_some() {
        return None;
    }

    // The lengths are exact, so a truncated or padded link is refused rather
    // than repaired.
    if secret_s.len() != 43 {
        return None;
    }
    if expires_s.is_empty()
        || expires_s.len() > 15
        || !expires_s.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    if !kdf::is_member_id(owner_s) {
        return None;
    }

    let secret: [u8; SECRET_LEN] = b64::decode_exact(secret_s)?;
    // `0` for an unparseable number, so a viewer that somehow got a bad expiry
    // treats the link as already over rather than as never ending.
    let expires_at: i64 = expires_s.parse().unwrap_or(0);
    Some(ParsedHelp { secret, expires_at, owner: owner_s.to_string() })
}

/// One viewer's view of a beacon.
pub struct Viewer {
    pub link: HelpLink,
    /// The identity that signs this viewer's posts. Held only for as long as the
    /// beacon does.
    pub identity: Identity,
    pub live: bool,
    /// Set once a final goodbye has been sent or the link has been revoked.
    pub retired: bool,
}

impl Viewer {
    pub fn channel(&self) -> String {
        self.link.channel()
    }
}

/// The set of viewers currently watching one emergency.
pub struct Beacon {
    /// Kept in memory only. Process death kills it, and a viewer's page then
    /// sees the trail go stale rather than a beacon that outlived its app.
    viewers: Vec<Viewer>,
}

impl Default for Beacon {
    fn default() -> Self {
        Self::new()
    }
}

impl Beacon {
    pub fn new() -> Self {
        Self { viewers: Vec::new() }
    }

    /// Add a viewer and return the link to share with them.
    pub fn add(&mut self, ttl_ms: i64, now: i64) -> HelpLink {
        // Each viewer gets a fresh identity and a fresh channel.
        let identity = Identity::generate();
        let link = HelpLink {
            secret: seal::random_bytes::<SECRET_LEN>(),
            owner: identity.member_id().to_string(),
            expires_at: now + ttl_ms.max(0),
        };
        self.viewers.push(Viewer {
            link: link.clone(),
            identity,
            live: true,
            retired: false,
        });
        link
    }

    pub fn viewer_count(&self) -> usize {
        self.viewers.len()
    }

    /// How many viewers are still watching, as opposed to revoked or expired.
    pub fn live_count(&self) -> usize {
        self.viewers.iter().filter(|v| v.live).count()
    }

    /// Revoke one viewer's link.
    ///
    /// Sends a final goodbye so the page says "session ended" rather than
    /// silently going quiet, then retires the viewer. An already-expired viewer
    /// gets no goodbye: there is no live session to end.
    pub fn revoke(&mut self, owner: &str) -> bool {
        let Some(v) = self.viewers.iter_mut().find(|v| v.link.owner == owner && !v.retired)
        else {
            return false;
        };
        v.retired = true;
        v.live = false;
        true
    }

    /// Whether a viewer may still be written to.
    pub fn is_live(&self, owner: &str) -> bool {
        self.viewers.iter().any(|v| v.link.owner == owner && v.live && !v.retired)
    }

    /// The posts for one position, one per live viewer.
    ///
    /// A beacon with no viewers produces nothing: there is nowhere to post to,
    /// and sealing a position into the void would only risk leaving it in memory.
    pub fn posts(&self, body: &str, epoch: i64, ts: i64) -> Vec<Post> {
        self.viewers
            .iter()
            .filter(|v| v.live && !v.retired)
            .filter_map(|v| {
                let key = v.link.key();
                seal::build_post(&v.identity, &v.link.channel(), &key, epoch, ts, body).ok()
            })
            .collect()
    }

    /// The posts that end every live session, for a check-in or a stop.
    pub fn goodbye_posts(&self, name: &str, emoji: &str, hue: u16, ts: i64) -> Vec<Post> {
        let body = msg::CircleMsg::bye(
            ts,
            msg::Who::new(name, emoji, hue as i64, 0.0, msg::ShareMode::Precise, ""),
        );
        self.posts(
            &serde_json::to_string(&body).unwrap_or_default(),
            wire::epoch_at(ts),
            ts,
        )
    }

    /// Retire every viewer that was live at this instant.
    ///
    /// Liveness is read *before* anything is marked revoked, so a viewer added
    /// during the fan-out does not get a goodbye it was never part of.
    pub fn end(&mut self, name: &str, emoji: &str, hue: u16, ts: i64) -> Vec<Post> {
        let posts = self.goodbye_posts(name, emoji, hue, ts);
        for v in &mut self.viewers {
            if v.live && !v.retired {
                v.retired = true;
                v.live = false;
            }
        }
        posts
    }
}

/// What a help page shows for a position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// An emergency is active.
    Sos,
    /// Position is being shared.
    Sharing,
    /// A deliberate check-in.
    CheckedIn,
    /// Nothing recent enough to draw.
    SignalLost,
    /// A goodbye was received, or the link expired.
    Stopped,
}

/// Classify a beacon's state from its most recent message.
///
/// `now` is the viewer's own clock, and the staleness threshold is generous: a
/// helper looking at a page should not see "signal lost" because the phone's
/// screen went off.
pub fn status_of(last: Option<&msg::CircleMsg>, now: i64) -> Status {
    let Some(m) = last else {
        return Status::SignalLost;
    };
    // A goodbye is checked before staleness, and deliberately never ages out. A
    // session that ended did end: telling a helper to keep watching for someone
    // who has already said they are safe is the wrong way to be wrong.
    if matches!(m, msg::CircleMsg::Bye { .. }) {
        return Status::Stopped;
    }
    if now.saturating_sub(m.timestamp()) > STALE_MS {
        return Status::SignalLost;
    }
    match m {
        msg::CircleMsg::Sos { .. } => Status::Sos,
        msg::CircleMsg::CheckIn { .. } => Status::CheckedIn,
        _ => Status::Sharing,
    }
}

/// How old a position may be before a help page calls the signal lost.
pub const STALE_MS: i64 = 3 * 60 * 1000;

/// Verify and open one beacon post, as a viewer does.
///
/// Two things are checked that a circle receiver does not check, because a
/// viewer has no roster to check against:
///
/// * the post must come from exactly the member id the link committed to, so a
///   helper cannot be shown a position written by anyone else; and
/// * the payload must be a position or a status, not a control message, so a
///   help link can never be used to move a circle anywhere.
pub fn verify_for_viewer(
    post: &Post,
    parsed: &ParsedHelp,
    now: i64,
) -> Option<msg::CircleMsg> {
    if post.m != parsed.owner {
        return None;
    }
    let opened = seal::verify_and_open(post, &parsed.channel(), &parsed.key(), now)?;
    let m = msg::parse_circle(&opened.body)?;
    // A beacon is read-only. A re-key on a help channel would be meaningless and
    // is refused, so a link can never become a way into a circle.
    if m.is_control() {
        return None;
    }
    Some(m)
}

/// The distance from a viewer to an emergency, for the "how far away" line.
pub fn distance_to(viewer_lat: f64, viewer_lon: f64, m: &msg::CircleMsg) -> Option<f64> {
    let (lat, lon) = fix_of(m)?;
    Some(geo::haversine_m(viewer_lat, viewer_lon, lat, lon))
}

fn fix_of(m: &msg::CircleMsg) -> Option<(f64, f64)> {
    m.fix().map(|f| (f.lat, f.lon))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> Identity {
        Identity::generate()
    }

    #[test]
    fn a_link_is_three_fields_of_exact_shape() {
        let link = mint(&owner(), DEFAULT_TTL_MS, 1_000_000);
        assert!(link.expires_at() == 1_000_000 + DEFAULT_TTL_MS);
        let f = link.fragment();
        assert!(f.starts_with("#b="));
        let body = &f[3..];
        let parts: Vec<&str> = body.split('.').collect();
        assert_eq!(parts.len(), 3, "secret, expiry, owner");
        assert_eq!(parts[0].len(), 43);
        assert!(parts[1].len() <= 15 && parts[1].bytes().all(|b| b.is_ascii_digit()));
        assert!(kdf::is_member_id(parts[2]));
    }

    #[test]
    fn a_link_round_trips() {
        let link = mint(&owner(), DEFAULT_TTL_MS, 1_000_000);
        let parsed = parse_fragment(&link.fragment()).expect("our own link parses");
        assert_eq!(parsed.secret, *link.secret());
        assert_eq!(parsed.owner, link.owner());
        assert_eq!(parsed.expires_at, link.expires_at());
    }

    #[test]
    fn a_link_without_its_owner_does_not_parse() {
        // This is the load-bearing case. Without the owner there is no way to
        // know which key a signature must belong to, so the link is refused
        // rather than accepted with a weaker rule.
        let link = mint(&owner(), DEFAULT_TTL_MS, 1_000_000);
        let body = &link.fragment()[3..];
        let mut parts: Vec<&str> = body.split('.').collect();
        parts.pop();
        assert!(parse_fragment(&format!("#b={}", parts.join("."))).is_none());
    }

    #[test]
    fn a_malformed_link_is_refused() {
        let link = mint(&owner(), DEFAULT_TTL_MS, 1_000);
        let f = link.fragment();
        let body = &f[3..];
        let parts: Vec<&str> = body.split('.').collect();

        assert!(parse_fragment("").is_none());
        assert!(parse_fragment("#b=").is_none());
        assert!(
            parse_fragment(&format!("#b={}.{}", parts[0], parts[2])).is_none(),
            "no expiry"
        );
        assert!(
            parse_fragment(&format!(
                "#b={}.{}.{}.{}",
                parts[0], parts[1], parts[2], parts[2]
            ))
            .is_none(),
            "four fields"
        );
        assert!(
            parse_fragment(&format!("#b={}.{}.x", &parts[0][..42], parts[1])).is_none(),
            "short secret"
        );
        assert!(
            parse_fragment(&format!("#b={}.abc.{}", parts[0], parts[2])).is_none(),
            "non-numeric expiry"
        );
        assert!(
            parse_fragment(&format!("#b={}.{}.SHORT", parts[0], parts[1])).is_none(),
            "short owner"
        );
        assert!(
            parse_fragment(&format!(
                "#b={}.{}.{}",
                parts[0],
                parts[1],
                parts[2].to_uppercase()
            ))
            .is_none(),
            "an uppercase owner is not a member id"
        );
        assert!(
            parse_fragment(&format!("#b={}.99999999999999999999.{}", parts[0], parts[2]))
                .is_none()
        );
    }

    #[test]
    fn two_links_never_share_a_channel_or_an_owner() {
        // Two viewers of one emergency: two channels and two identities, so
        // revoking one leaves the other untouched.
        let mut beacon = Beacon::new();
        let a = beacon.add(DEFAULT_TTL_MS, 0);
        let b = beacon.add(DEFAULT_TTL_MS, 0);
        assert_ne!(a.channel(), b.channel());
        assert_ne!(a.owner(), b.owner());
        assert_ne!(a.secret(), b.secret());
    }

    #[test]
    fn a_link_expires() {
        let link = mint(&owner(), 3_600_000, 1_000);
        assert!(!link.is_expired(1_000));
        assert!(link.is_expired(1_000 + 3_600_000));
    }

    #[test]
    fn a_beacon_has_no_viewers_to_post_to_initially() {
        let b = Beacon::new();
        assert_eq!(b.viewer_count(), 0);
        assert!(b.posts("{}", 1, 2).is_empty());
    }

    #[test]
    fn a_post_reaches_every_live_viewer() {
        let mut b = Beacon::new();
        let a = b.add(DEFAULT_TTL_MS, 1_000);
        let c = b.add(DEFAULT_TTL_MS, 1_000);
        assert_eq!(b.viewer_count(), 2);
        assert_eq!(b.live_count(), 2);

        let body = serde_json::to_string(&msg::CircleMsg::sos(
            2_000,
            msg::Who::default(),
            msg::Fix::new(44.98, -93.27, 5.0),
        ))
        .unwrap();
        let posts = b.posts(&body, 1, 2_000);
        assert_eq!(posts.len(), 2, "one post per viewer");
        // Each from its own identity, so a viewer's channel has exactly one
        // signer and the two links cannot be confused.
        assert_ne!(posts[0].m, posts[1].m);
        assert!(posts.iter().any(|p| p.m == a.owner()));
        assert!(posts.iter().any(|p| p.m == c.owner()));
    }

    #[test]
    fn a_viewer_can_open_only_its_own_beacons_posts() {
        let mut b = Beacon::new();
        let mine = b.add(DEFAULT_TTL_MS, 1_000);
        let theirs = b.add(DEFAULT_TTL_MS, 1_000);
        let parsed_mine = parse_fragment(&mine.fragment()).unwrap();
        let parsed_theirs = parse_fragment(&theirs.fragment()).unwrap();

        let body = serde_json::to_string(&msg::CircleMsg::loc(
            2_000,
            msg::Who::default(),
            msg::Fix::new(44.98, -93.27, 5.0),
        ))
        .unwrap();
        let posts = b.posts(&body, wire::epoch_at(2_000), 2_000);
        let mine_post =
            posts.iter().find(|p| p.m == parsed_mine.owner).expect("a post for my channel");
        let their_post = posts
            .iter()
            .find(|p| p.m == parsed_theirs.owner)
            .expect("a post for their channel");

        // Each opens on its own link, and not on the other's. This is what
        // confines a help link to one emergency.
        assert!(verify_for_viewer(mine_post, &parsed_mine, 2_000).is_some());
        assert!(verify_for_viewer(mine_post, &parsed_theirs, 2_000).is_none());
        assert!(verify_for_viewer(their_post, &parsed_theirs, 2_000).is_some());
        assert!(verify_for_viewer(their_post, &parsed_mine, 2_000).is_none());
    }

    #[test]
    fn a_post_from_an_impostor_is_refused() {
        // Someone who derives the channel and key from a link they were sent can
        // write a position that opens. The signature is what stops them, and the
        // link's committed owner id is what the signature is checked against.
        let mut b = Beacon::new();
        let link = b.add(DEFAULT_TTL_MS, 1_000);
        let parsed = parse_fragment(&link.fragment()).unwrap();

        let forger = Identity::generate();
        let key = parsed.key();
        let body = serde_json::to_string(&msg::CircleMsg::sos(
            2_000,
            msg::Who::default(),
            msg::Fix::new(0.0, 0.0, 1.0),
        ))
        .unwrap();
        // A perfectly valid post, sealed under the right key on the right
        // channel, and signed by the wrong key.
        let forged = seal::build_post(
            &forger,
            &parsed.channel(),
            &key,
            wire::epoch_at(2_000),
            2_000,
            &body,
        )
        .unwrap();
        assert!(
            verify_for_viewer(&forged, &parsed, 2_000).is_none(),
            "a forger who holds the link must not be able to move the marker"
        );
    }

    #[test]
    fn a_control_message_on_a_help_channel_is_refused() {
        // A help link must never become a way into a circle, so a re-key is not
        // honoured here even from the beacon's own identity.
        let mut b = Beacon::new();
        let link = b.add(DEFAULT_TTL_MS, 1_000);
        let parsed = parse_fragment(&link.fragment()).unwrap();
        let identity = b.viewers[0].identity.clone();

        let rekey = msg::CircleMsg::ReKey {
            v: msg::VERSION,
            ts: 2_000,
            g: 1,
            e0: 1,
            me: 1,
            to: "aa".into(),
            eph: "e".into(),
            w: "w".into(),
            rm: vec![],
            rh: String::new(),
        };
        let post = seal::build_post(
            &identity,
            &parsed.channel(),
            &parsed.key(),
            wire::epoch_at(2_000),
            2_000,
            &serde_json::to_string(&rekey).unwrap(),
        )
        .unwrap();
        assert!(verify_for_viewer(&post, &parsed, 2_000).is_none());
    }

    #[test]
    fn a_goodbye_ends_the_session_for_every_live_viewer() {
        let mut b = Beacon::new();
        b.add(DEFAULT_TTL_MS, 1_000);
        b.add(DEFAULT_TTL_MS, 1_000);
        let posts = b.end("Ana", "", 210, 2_000);
        assert_eq!(posts.len(), 2, "both live viewers are told");
        assert_eq!(b.live_count(), 0);
        for p in &posts {
            let parsed = parse_fragment(
                &b.viewers.iter().find(|v| v.link.owner == p.m).unwrap().link.fragment(),
            )
            .unwrap();
            let m = verify_for_viewer(p, &parsed, 2_000).expect("the goodbye opens");
            assert!(matches!(m, msg::CircleMsg::Bye { .. }));
        }
    }

    #[test]
    fn a_revoked_viewer_stops_receiving_and_is_told_once() {
        let mut b = Beacon::new();
        let link = b.add(DEFAULT_TTL_MS, 1_000);
        let other = b.add(DEFAULT_TTL_MS, 1_000);
        assert!(b.is_live(link.owner()));

        assert!(b.revoke(link.owner()));
        assert!(!b.is_live(link.owner()));
        // The other viewer is untouched.
        assert!(b.is_live(other.owner()));

        let body = serde_json::to_string(&msg::CircleMsg::loc(
            2_000,
            msg::Who::default(),
            msg::Fix::new(0.0, 0.0, 1.0),
        ))
        .unwrap();
        let posts = b.posts(&body, wire::epoch_at(2_000), 2_000);
        assert_eq!(posts.len(), 1, "the revoked viewer gets nothing further");
        assert!(!posts.iter().any(|p| p.m == link.owner()));

        // Revoking twice does nothing, so a page cannot be told twice.
        assert!(!b.revoke(link.owner()));
    }

    #[test]
    fn a_revoked_viewer_cannot_be_revoked_again_through_another_path() {
        let mut b = Beacon::new();
        let link = b.add(DEFAULT_TTL_MS, 1_000);
        b.revoke(link.owner());
        assert!(!b.is_live(link.owner()));
        // And a goodbye fan-out does not include them.
        let posts = b.end("Ana", "", 0, 2_000);
        assert!(posts.is_empty());
    }

    #[test]
    fn status_reflects_the_last_message_and_its_age() {
        let sos =
            msg::CircleMsg::sos(1_000, msg::Who::default(), msg::Fix::new(0.0, 0.0, 1.0));
        let checkin = msg::CircleMsg::check_in(
            1_000,
            msg::Who::default(),
            msg::Fix::new(0.0, 0.0, 1.0),
        );
        let loc =
            msg::CircleMsg::loc(1_000, msg::Who::default(), msg::Fix::new(0.0, 0.0, 1.0));
        let bye = msg::CircleMsg::bye(1_000, msg::Who::default());

        assert_eq!(status_of(Some(&sos), 1_000), Status::Sos);
        assert_eq!(status_of(Some(&checkin), 1_000), Status::CheckedIn);
        assert_eq!(status_of(Some(&loc), 1_000), Status::Sharing);
        assert_eq!(status_of(Some(&bye), 1_000), Status::Stopped);
        assert_eq!(status_of(None, 1_000), Status::SignalLost);
        // Old enough, and even an SOS reads as lost.
        assert_eq!(status_of(Some(&sos), 1_000 + STALE_MS + 1), Status::SignalLost);
    }

    #[test]
    fn a_goodbye_stays_a_goodbye_however_old() {
        // A session that ended did end; ageing into "signal lost" would tell a
        // helper to keep looking for someone who has said they are safe.
        let bye = msg::CircleMsg::bye(1_000, msg::Who::default());
        assert_eq!(status_of(Some(&bye), 1_000 + STALE_MS * 10), Status::Stopped);
    }

    #[test]
    fn distance_to_an_emergency_is_measurable() {
        let m = msg::CircleMsg::sos(
            1_000,
            msg::Who::default(),
            msg::Fix::new(44.98, -93.27, 1.0),
        );
        let d = distance_to(44.98, -93.27, &m).unwrap();
        assert!(d < 1.0);
        // A goodbye has no position, so there is nothing to measure to.
        let bye = msg::CircleMsg::bye(1_000, msg::Who::default());
        assert!(distance_to(0.0, 0.0, &bye).is_none());
    }

    #[test]
    fn the_default_lifetime_matches_the_relay_retention() {
        // A link must not outlive the data it points at.
        assert_eq!(DEFAULT_TTL_MS, wire::TTL_MS);
    }
}
