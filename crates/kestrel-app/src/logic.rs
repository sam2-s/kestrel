//! The app's own logic, as opposed to the map's geometry and the platform's edges.
//!
//! Everything here is testable on a laptop with no phone and no network, which is the
//! point. The interesting failures in this app are decisions — should this be posted,
//! is this position good enough to send, is this invitation still alive — and those are
//! exactly the things that are painful to reproduce on a device.
//!
//! The parts that cannot be tested without a phone are confined to [`crate::platform`]
//! and [`crate::android`], and everything below reaches them through the [`Platform`]
//! trait.

use kestrel_core::{
    identity::{Identity, StoredIdentity},
    invite::{self, Invite},
    msg::{self, ShareMode},
    seal::random_bytes,
    session::{Circle, me},
    wire,
};

use crate::{
    platform::Platform,
    state::Fix,
    state::now_ms,
    store::{self, INVITE_TTL_MS},
};

/// How a position gets chosen for sending.
///
/// The answer depends on what the circle wants and on what permission this device
/// actually has, and those are different questions: a circle asked for coarse sharing is
/// not a reason to keep a precise fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Post {
    /// Send this.
    Send,
    /// Do not send: nothing has changed enough to be worth the bytes.
    Skip,
    /// Send this, and there is a reason worth telling the user about.
    ///
    /// Carries the reason rather than a bare true, because the cases that force a post
    /// are the ones a person would want to be told happened.
    Force(&'static str),
}

/// When a new position is worth posting.
///
/// The rule is about change, not time. A share every fifteen seconds of a person
/// standing still says one thing: that the app is running. It does not say where
/// anyone is, and it hands the relay a trail of identical coordinates that outlive the
/// moment by the full twenty-four hours the relay keeps them.
pub fn worth_posting(
    last: Option<&Fix>,
    now: Fix,
    coarse: bool,
    moved_m: f64,
    _min_interval_ms: i64,
) -> Post {
    if !now.is_usable() {
        // Not an error. The platform reports this before it has a location and between
        // fixes, and posting a null island marker is worse than posting nothing.
        return Post::Skip;
    }
    let Some(last) = last else {
        // Nothing sent yet, so the first position is the one the circle is waiting for.
        return Post::Force("first position");
    };
    if now.ts <= last.ts {
        // A fix older than one already sent. Sending it would rewind every marker on
        // every other phone in the circle.
        return Post::Skip;
    }
    let moved = kestrel_core::geo::haversine_m(last.lat, last.lon, now.lat, now.lon);
    let quiet_ms = now.ts - last.ts;
    // Coarse sharing has a radius the size of a city block, so a small movement inside
    // it is not a change: rounding it would produce a different coordinate for the same
    // place, which is noise pretending to be detail.
    let threshold = if coarse { 500.0 } else { moved_m.max(10.0) };
    if moved >= threshold {
        return Post::Send;
    }
    // No refresh timer. An earlier version posted "still here" every few minutes, and it
    // was the same coordinate: thirty identical posts an hour, which says "the app is
    // running" and nothing about where anyone is, while giving the relay a trail of
    // identical points to hold for its full twenty-four hours.
    //
    // The map already handles a member who has gone quiet: the marker stays where it
    // was and fades, which is the honest rendering of "we last knew they were here".
    let _ = quiet_ms;
    Post::Skip
}

/// Whether an invitation can still be used.
pub fn invite_live(invite: &Invite, now: i64) -> bool {
    !invite.is_expired(now)
}

/// A short line about an invitation, for the UI.
pub fn invite_status(invite: &Invite, now: i64) -> &'static str {
    if invite.is_expired(now) {
        "Expired"
    } else if invite.expires_at() - now < 5 * 60 * 1000 {
        "Expiring"
    } else {
        "Valid"
    }
}

/// Whether a scanned or typed string is an invitation at all.
///
/// Checked before anything else, so a string that is not one is not half-parsed. A
/// near-miss that gets partway through would be a way to make the app do work for an
/// attacker, and would leave an older bearer-token invitation working.
pub fn is_invite_fragment(text: &str) -> bool {
    invite::parse_fragment(text.trim()).is_some()
}

/// What a join needs to hand to the relay.
pub struct JoinPlan {
    /// The rendezvous channel, derived from the secret so two invitations never meet
    /// in the same place.
    pub channel: String,
    /// The join post, sealed to the rendezvous key.
    pub post: Option<wire::Post>,
    /// Why there is no post, if there is none.
    pub refused: Option<String>,
}

/// Build the first message of a join.
///
/// The seed arrives from the inviter inside the welcome, not before, so this is a
/// request rather than an answer. It carries no location: a join post that included one
/// would publish a position to a channel the inviter has not yet proven they own.
pub fn plan_join(fragment: &str, identity: &Identity, now: i64) -> Option<JoinPlan> {
    let parsed = invite::parse_fragment(fragment.trim())?;
    // The channel and the key both come from the core's own derivation, so there is one
    // implementation of the rendezvous rather than two that have to be kept in step.
    let (channel, key) = invite::rendezvous(&parsed);
    // Epoch 0 on the rendezvous: a join is not part of any circle's ratchet, so there
    // is no chain to advance and nothing to keep.
    let body = serde_json::to_string(&msg::InviteMsg::Join {
        v: 1,
        ts: now,
        pk: identity.pk_b64(),
        epk: identity.epk_b64(),
        name: String::new(),
    })
    .ok()?;
    let post = kestrel_core::seal::build_post(identity, &channel, &key, 0, now, &body).ok();
    let refused =
        post.is_none().then(|| "The join request was too large to send.".to_string());
    Some(JoinPlan { channel, post, refused })
}

/// Whether a circle's own state is worth saving.
///
/// Every circle is worth saving, actually — but the seed is what makes it the same
/// circle, and a circle whose seed is gone is a circle this device cannot rejoin.
pub fn circle_is_persistable(seed: &[u8; 32]) -> bool {
    seed.iter().any(|b| *b != 0)
}

/// Write the seed, encrypted by the app lock if one is set.
///
/// Without a lock this is the raw seed, because on a device with no passcode there is
/// no second key to derive it from and pretending otherwise would only add a layer that
/// protects nothing.
pub fn save_seed(seed: &[u8; 32], passcode: Option<&str>) -> std::io::Result<()> {
    match passcode {
        Some(code) => {
            let lock = store::make_lock(code).map_err(std::io::Error::other)?;
            let bytes = seal_seed(seed, code);
            store::write_private(&store::seed_path(), &bytes)?;
            store::write_private(
                &store::lock_path(),
                &serde_json::to_vec(&lock).unwrap_or_default(),
            )
        }
        None => store::write_private(&store::seed_path(), seed),
    }
}

/// Read the seed back, with the passcode if there is one.
pub fn load_seed(passcode: Option<&str>) -> Option<[u8; 32]> {
    let bytes = store::read(&store::seed_path())?;
    match passcode {
        Some(code) if store::is_locked() => open_seed(&bytes, code),
        // No passcode, or no lock file: the bytes are the seed.
        _ => {
            if bytes.len() != 32 {
                return None;
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            Some(seed)
        }
    }
}

/// Seal the seed under a key derived from the passcode and a fresh salt.
///
/// The salt goes in the clear, at the front. It has to: it is what stops two identical
/// passcodes producing identical ciphertext, which would tell an attacker that two
/// phones had the same passcode.
fn seal_seed(seed: &[u8; 32], passcode: &str) -> Vec<u8> {
    let salt = random_bytes::<16>();
    let key = kestrel_core::seal::ContentKey::new(stretch(passcode, &salt));
    let mut out = Vec::with_capacity(16 + 12 + seed.len() + 16);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&seal_one(key.as_bytes(), seed, &salt));
    out
}

/// Open a sealed seed. A wrong passcode gives wrong bytes, which then fail the
/// round-trip check below and are refused.
fn open_seed(bytes: &[u8], passcode: &str) -> Option<[u8; 32]> {
    if bytes.len() != 16 + 12 + 32 + 16 {
        return None;
    }
    let salt = &bytes[..16];
    let body = &bytes[16..];
    let key = kestrel_core::seal::ContentKey::new(stretch(passcode, salt));
    let plain = open_one(key.as_bytes(), body, salt)?;
    plain.try_into().ok()
}

/// Stretch a passcode into a 32-byte key.
///
/// The same work factor as the lock file's verifier, so opening the seed and unlocking
/// the app cost a person the same wait. A fast unlock and a slow decrypt would make the
/// lock feel free.
fn stretch(passcode: &str, salt: &[u8]) -> [u8; 32] {
    let mut acc = [0u8; 32];
    for round in 0..store::ROUNDS_FOR_CRYPTO {
        let mut input = Vec::with_capacity(salt.len() + passcode.len() + 4);
        input.extend_from_slice(salt);
        input.extend_from_slice(passcode.as_bytes());
        input.extend_from_slice(&round.to_le_bytes());
        let digest = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&input);
            h.finalize().into()
        };
        if round == 0 {
            acc = digest;
        } else {
            for (a, b) in acc.iter_mut().zip(digest.iter()) {
                *a ^= b;
            }
        }
    }
    acc
}

/// Encrypt with an explicit nonce, so a ciphertext is never reused for two plaintexts.
///
/// Written here rather than pulled from the seal module because that one derives its
/// nonce from a timestamp, and a timestamp is not a nonce: two saves of the same seed in
/// the same millisecond would produce the same ciphertext.
fn seal_one(key: &[u8; 32], plain: &[u8], aad: &[u8]) -> Vec<u8> {
    let nonce = random_bytes::<12>();
    let mut out = nonce.to_vec();
    out.extend_from_slice(&aes_gcm(key, &nonce, aad, plain).unwrap_or_default());
    out
}

fn open_one(key: &[u8; 32], body: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    if body.len() < 12 + 16 {
        return None;
    }
    let nonce: [u8; 12] = body[..12].try_into().ok()?;
    aes_gcm_open(key, &nonce, aad, &body[12..])
}

/// AES-256-GCM, from the core crate.
///
/// The core's `seal_padded` is deliberately not used: padding to a fixed size exists so
/// every message on the wire is the same length, and a file in the app's own private
/// directory has no observer whose eye length would catch it. Padding here would also
/// mean the decrypted bytes came back space-filled, which is a confusing thing to have
/// to strip before using as a key.
fn aes_gcm(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plain: &[u8]) -> Option<Vec<u8>> {
    kestrel_core::seal::seal(key, nonce, plain, aad)
}

fn aes_gcm_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ct: &[u8],
) -> Option<Vec<u8>> {
    kestrel_core::seal::open(key, nonce, ct, aad)
}

/// The share cadence: at most one post per this many milliseconds.
pub const MIN_INTERVAL_MS: i64 = 15_000;

/// Whether to share coarsely, given what was granted.
///
/// The permission decides it, not a setting. A user on an approximate grant who is
/// offered a "precise" toggle would be shown a switch that does nothing.
pub fn share_mode(permissions: &crate::permissions::Permissions) -> ShareMode {
    if permissions.is_coarse() { ShareMode::Coarse } else { ShareMode::Precise }
}

/// Build the post for this device's current position, if one is worth sending.
pub fn build_post(
    circle: &mut Circle,
    fix: &Fix,
    permissions: &crate::permissions::Permissions,
    name: &str,
    last: Option<&Fix>,
) -> Option<wire::Post> {
    let mode = share_mode(permissions);
    if !worth_posting(last, *fix, mode == ShareMode::Coarse, 0.0, MIN_INTERVAL_MS)
        .matches_post()
    {
        return None;
    }
    let who = me(circle.identity(), name, "", battery_of(fix), mode);
    circle.location(&who, msg::Fix::new(fix.lat, fix.lon, fix.acc), mode, fix.ts)
}

fn battery_of(fix: &Fix) -> f64 {
    fix.battery.clamp(0.0, 1.0)
}

impl Post {
    /// Whether this verdict means "send".
    pub fn sends(self) -> bool {
        !matches!(self, Post::Skip)
    }

    fn matches_post(self) -> bool {
        self.sends()
    }
}

/// What the app does when the user turns sharing on.
///
/// Split out so the tests can check the decision without a platform: turning sharing on
/// when the location permission is refused must start nothing, because a service that
/// posts nothing and claims to be sharing is exactly the failure this app exists to
/// avoid.
pub fn start_sharing(
    permissions: &crate::permissions::Permissions,
) -> Result<(), &'static str> {
    if !permissions.can_share() {
        return Err("Location is not allowed.");
    }
    if !permissions.service_is_visible() {
        // Android 13 and later will start a foreground service without showing its
        // notification, and the user would have no way to know they were being tracked.
        return Err(
            "Notifications are off, so there would be nothing to show that you are sharing.",
        );
    }
    Ok(())
}

/// Whether a share survives the app being closed.
pub fn survives_background(permissions: &crate::permissions::Permissions) -> bool {
    permissions.survives_background()
}

/// A one-line description of what sharing will do, for the toggle's label.
///
/// Written out in full rather than assembled from parts, because the whole point is
/// that a person reads it before agreeing to be located.
pub fn sharing_promise(permissions: &crate::permissions::Permissions) -> String {
    if !permissions.can_share() {
        return "Not sharing: without location, nobody can see where you are.".to_string();
    }
    let precision =
        if permissions.is_coarse() { "about a kilometre at a time" } else { "precisely" };
    let background = if permissions.survives_background() {
        "and keeps going when the app is closed"
    } else {
        "but stops when the app is closed"
    };
    format!("Sharing {precision} with your circle, {background}.")
}

/// Set up a new circle on this device.
///
/// The seed is thirty-two bytes from the system CSPRNG. Not from the user, not from
/// anything else on the device: this is the value every other member's location is
/// encrypted under, and a predictable one would make the whole scheme decorative.
pub fn create_circle(
    platform: &dyn Platform,
    name: &str,
    now: i64,
) -> std::io::Result<Circle> {
    let seed = random_bytes::<32>();
    let identity = Identity::generate();
    let circle = Circle::create(identity, &seed, now);

    // The identity first, then the seed. Interrupted between the two, the worst case is
    // an identity with no circle behind it, which is discarded and minted afresh next
    // time. The other order leaves a seed that no identity can use, and the app cannot
    // tell that from a first run.
    let stored = serde_json::to_vec(&StoredIdentity::from_identity(circle.identity()))
        .map_err(std::io::Error::other)?;
    store::write_private(&store::identity_path(), &stored)?;
    save_seed(&seed, None)?;

    let mut settings = store::load_settings();
    settings.name = name.to_string();
    store::save_settings(&settings)?;
    platform.notify("Kestrel", "Your circle is ready. Add someone to share with.");
    Ok(circle)
}

/// Restore the circle this device created, or `None` on a first run.
///
/// A file that will not parse is treated as no circle rather than as an error. The seed
/// and the identity are both unrecoverable if either is lost, so a partial write cannot
/// be repaired and the only useful thing to do is start again.
pub fn restore_circle(passcode: Option<&str>) -> Option<Circle> {
    let seed = load_seed(passcode)?;
    if !circle_is_persistable(&seed) {
        return None;
    }
    let identity = restore_identity()?;
    Some(Circle::create(identity, &seed, now_ms()))
}

/// This device's stored identity.
pub fn restore_identity() -> Option<Identity> {
    let bytes = store::read(&store::identity_path())?;
    let stored: StoredIdentity = serde_json::from_slice(&bytes).ok()?;
    stored.to_identity()
}

/// Whether this looks like a first run.
///
/// True when there is no seed, or a seed that no stored identity can use. Anything else
/// would open the map on a circle the app cannot actually post to.
pub fn is_first_run() -> bool {
    !store::has_circle() || restore_identity().is_none()
}

/// Mint an invitation for someone new.
pub fn mint_invite(circle: &Circle, now: i64) -> Invite {
    Invite::mint(circle.identity(), now, INVITE_TTL_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fix(lat: f64, lon: f64, ts: i64) -> Fix {
        Fix { lat, lon, acc: 5.0, ts, battery: 0.8 }
    }

    #[test]
    fn the_first_position_is_always_worth_sending() {
        let now = fix(44.98, -93.27, 1_000_000);
        assert!(worth_posting(None, now, false, 0.0, MIN_INTERVAL_MS).sends());
    }

    #[test]
    fn a_person_standing_still_is_not_a_stream_of_posts() {
        // The whole reason this rule exists: identical coordinates thirty times a second
        // say "the app is running" and nothing about where anyone is.
        let first = fix(44.98, -93.27, 1_000_000);
        assert!(worth_posting(None, first, false, 0.0, MIN_INTERVAL_MS).sends());

        // Walk an hour of fifteen-second fixes and count how many would be posted. The
        // property that matters is the rate, so it is written as a rate: a phone on a
        // desk for an hour posts a handful of times, not two hundred and forty.
        let mut last_sent = Some(first);
        let mut posts = 1;
        for step in 1..240 {
            let later = fix(44.98, -93.27, first.ts + step * MIN_INTERVAL_MS);
            if worth_posting(last_sent.as_ref(), later, false, 0.0, MIN_INTERVAL_MS).sends()
            {
                posts += 1;
                last_sent = Some(later);
            }
        }
        assert_eq!(posts, 1, "an hour of a stationary device produced {posts} posts");
    }

    #[test]
    fn moving_enough_is_worth_sending_even_at_the_interval() {
        let first = fix(44.98, -93.27, 1_000_000);
        // Thirty metres: about a minute of walking.
        let later = fix(44.98027, -93.27, first.ts + MIN_INTERVAL_MS);
        assert!(worth_posting(Some(&first), later, false, 0.0, MIN_INTERVAL_MS).sends());
    }

    #[test]
    fn coarse_sharing_needs_a_lot_more_movement() {
        // A coarse fix has a radius of about a city block. Posting every time someone
        // moves within it produces different coordinates for the same place, which is
        // noise pretending to be precision.
        let first = fix(44.98, -93.27, 1_000_000);
        let nearby = fix(44.9805, -93.27, first.ts + MIN_INTERVAL_MS);
        assert!(!worth_posting(Some(&first), nearby, true, 0.0, MIN_INTERVAL_MS).sends());
        let far = fix(44.99, -93.27, first.ts + MIN_INTERVAL_MS);
        assert!(worth_posting(Some(&first), far, true, 0.0, MIN_INTERVAL_MS).sends());
    }

    #[test]
    fn a_fix_older_than_one_already_sent_is_never_sent() {
        // A service delivering out of order must not rewind every marker in the circle.
        let first = fix(44.98, -93.27, 2_000_000);
        let older = fix(10.0, 10.0, 1_000_000);
        assert!(!worth_posting(Some(&first), older, false, 0.0, MIN_INTERVAL_MS).sends());
        let same = fix(0.0, 0.0, first.ts);
        assert!(!worth_posting(Some(&first), same, false, 0.0, MIN_INTERVAL_MS).sends());
    }

    #[test]
    fn an_unusable_fix_is_never_sent() {
        let first = fix(44.98, -93.27, 1_000_000);
        let zero = fix(0.0, 0.0, 2_000_000);
        assert!(!worth_posting(Some(&first), zero, false, 0.0, MIN_INTERVAL_MS).sends());
        assert!(!worth_posting(None, zero, false, 0.0, MIN_INTERVAL_MS).sends());
    }

    #[test]
    fn going_quiet_is_not_its_own_reason_to_post() {
        // Deliberate. The map fades a marker whose member has gone quiet, so a periodic
        // "still here" post would add nothing a reader could see — and would give the
        // relay an hour of identical coordinates for the phone sitting on a desk.
        let first = fix(44.98, -93.27, 1_000_000);
        for step in [1, 8, 40, 240] {
            let later = fix(44.98, -93.27, first.ts + MIN_INTERVAL_MS * step);
            assert!(
                !worth_posting(Some(&first), later, false, 0.0, MIN_INTERVAL_MS).sends(),
                "posted at +{step} intervals without moving"
            );
        }
    }

    #[test]
    fn an_invitation_is_live_for_an_hour_and_then_not() {
        let identity = Identity::generate();
        let now = 1_700_000_000_000;
        let invite = Invite::mint(&identity, now, INVITE_TTL_MS);
        assert!(invite_live(&invite, now));
        assert_eq!(invite_status(&invite, now), "Valid");
        assert!(invite_live(&invite, now + INVITE_TTL_MS - 1));
        assert!(!invite_live(&invite, now + INVITE_TTL_MS));
        assert_eq!(invite_status(&invite, now + INVITE_TTL_MS), "Expired");
        // And the warning comes before the fact, while there is still time to act.
        assert_eq!(invite_status(&invite, now + INVITE_TTL_MS - 60_000), "Expiring");
    }

    #[test]
    fn only_a_real_fragment_is_treated_as_an_invitation() {
        let identity = Identity::generate();
        let invite = Invite::mint(&identity, 1_700_000_000_000, INVITE_TTL_MS);
        assert!(is_invite_fragment(&invite.fragment()));
        assert!(is_invite_fragment(&format!("  {}  ", invite.fragment())));
        // Near-misses refused outright rather than half-parsed: accepting one would be a
        // way to make the app work for an attacker, and would leave an older
        // bearer-token invitation working.
        let fragment = invite.fragment();
        let bad: Vec<String> = vec![
            String::new(),
            "#j=".to_string(),
            "#j=onlysecret".to_string(),
            "#j=a.b.c".to_string(),
            format!("#j=notbase64.{}", "A".repeat(22)),
            format!("#x={}", fragment.trim_start_matches("#j=")),
            // One character short of a real one.
            format!("#j={}", &fragment[..fragment.len() - 1]),
        ];
        for bad in &bad {
            assert!(!is_invite_fragment(bad), "accepted {bad:?}");
        }
        // And the real one still parses, so the loop above is testing near-misses rather
        // than a parser that refuses everything.
        assert!(is_invite_fragment(&fragment));
        // A code copied out of a chat loses its `#`, and a person pasting it should not
        // be told it is wrong. This is deliberate in the core and checked here so a
        // future tightening does not quietly break the common case.
        assert!(is_invite_fragment(fragment.trim_start_matches('#')));
    }

    #[test]
    fn a_join_carries_no_location() {
        // A join post that included a position would publish it to a channel whose owner
        // has not been proven yet.
        let identity = Identity::generate();
        let plan = plan_join(
            &Invite::mint(&identity, 1_700_000_000_000, INVITE_TTL_MS).fragment(),
            &Identity::generate(),
            1_700_000_000_000,
        )
        .expect("a mint fragment should plan");
        assert!(!plan.channel.is_empty());
        assert!(plan.refused.is_none());
    }

    #[test]
    fn a_join_needs_a_fragment_to_work_from() {
        let identity = Identity::generate();
        assert!(plan_join("not an invite", &identity, 1).is_none());
    }

    #[test]
    fn sharing_cannot_start_without_location() {
        let p = crate::permissions::Permissions::default();
        assert!(start_sharing(&p).is_err());
        assert!(sharing_promise(&p).contains("Not sharing"));
    }

    #[test]
    fn sharing_cannot_start_without_a_visible_notification() {
        // Android 13 and later will start a foreground service whose notification the
        // user cannot see. That is a share the user cannot know about, let alone stop.
        use crate::permissions::{Report, apply_report};
        let mut p = crate::permissions::Permissions::default();
        apply_report(
            &Report {
                fine: "granted".into(),
                coarse: "granted".into(),
                notifications: "denied".into(),
                background: "unknown".into(),
                camera: "unknown".into(),
            },
            &mut p,
        );
        let err = start_sharing(&p).unwrap_err();
        assert!(err.contains("Notifications"), "{err}");
        assert!(sharing_promise(&p).contains("precisely"));
    }

    #[test]
    fn the_promise_says_precise_or_about_a_kilometre_and_nothing_in_between() {
        // The whole privacy question in one sentence, so the sentence is a test.
        use crate::permissions::{Report, apply_report};
        let mut p = crate::permissions::Permissions::default();
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
        let precise = sharing_promise(&p);
        assert!(precise.contains("precisely"), "{precise}");
        assert!(precise.contains("closed"), "{precise}");

        apply_report(
            &Report {
                fine: "denied".into(),
                coarse: "granted".into(),
                background: "granted".into(),
                notifications: "granted".into(),
                camera: "unknown".into(),
            },
            &mut p,
        );
        let coarse = sharing_promise(&p);
        assert!(coarse.contains("kilometre"), "{coarse}");
        assert!(!coarse.contains("precisely"), "{coarse}");
    }

    #[test]
    fn the_promise_says_when_a_share_will_not_survive_the_app_closing() {
        use crate::permissions::{Report, apply_report};
        let mut p = crate::permissions::Permissions::default();
        apply_report(
            &Report {
                fine: "granted".into(),
                coarse: "granted".into(),
                background: "denied".into(),
                notifications: "granted".into(),
                camera: "unknown".into(),
            },
            &mut p,
        );
        assert!(sharing_promise(&p).contains("stops when the app is closed"));
        assert!(!survives_background(&p));

        apply_report(
            &Report {
                background: "granted".into(),
                ..Report {
                    fine: "granted".into(),
                    coarse: "granted".into(),
                    background: "granted".into(),
                    notifications: "granted".into(),
                    camera: "unknown".into(),
                }
            },
            &mut p,
        );
        assert!(sharing_promise(&p).contains("keeps going"));
    }

    #[test]
    fn a_sealed_seed_needs_the_right_passcode_to_open() {
        let seed = [7u8; 32];
        let sealed = seal_seed(&seed, "a good passcode");
        assert_eq!(open_seed(&sealed, "a good passcode"), Some(seed));
        assert_ne!(open_seed(&sealed, "a different passcode"), Some(seed));
        assert_eq!(open_seed(&sealed, "another one"), None);
    }

    #[test]
    fn a_sealed_seed_is_not_the_seed() {
        let seed = [7u8; 32];
        let sealed = seal_seed(&seed, "a good passcode");
        assert!(!sealed.windows(32).any(|w| w == seed));
        // And two seals of the same seed differ, so the ciphertext is not a fingerprint.
        assert_ne!(seal_seed(&seed, "a good passcode"), sealed);
    }

    #[test]
    fn a_truncated_seed_is_refused_rather_than_half_read() {
        let sealed = seal_seed(&[7u8; 32], "a good passcode");
        for cut in [0, 1, 15, 16, 30] {
            assert_eq!(open_seed(&sealed[..cut], "a good passcode"), None, "cut at {cut}");
        }
    }

    #[test]
    fn a_seed_of_all_zeroes_is_not_a_circle() {
        // A zeroed seed would derive a channel everyone can compute. Written by a
        // truncated write or a failed read, and it must not be treated as a circle.
        assert!(!circle_is_persistable(&[0u8; 32]));
        assert!(circle_is_persistable(&[7u8; 32]));
    }

    #[test]
    fn coarse_mode_follows_the_permission_not_a_setting() {
        use crate::permissions::{Report, apply_report};
        let mut p = crate::permissions::Permissions::default();
        apply_report(
            &Report {
                fine: "granted".into(),
                coarse: "granted".into(),
                ..Report::default()
            },
            &mut p,
        );
        assert_eq!(share_mode(&p), ShareMode::Precise);
        apply_report(
            &Report {
                fine: "denied".into(),
                coarse: "granted".into(),
                ..Report::default()
            },
            &mut p,
        );
        assert_eq!(share_mode(&p), ShareMode::Coarse);
    }
}
