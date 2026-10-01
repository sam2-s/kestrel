//! Message bodies: what actually gets encrypted.
//!
//! Every body is JSON with a `t` discriminant, a protocol version, and a
//! timestamp that must match the one in the post header. Bodies are padded to a
//! fixed length by the sealing layer, so a relay cannot tell a short status
//! update from a re-key, or one name from another.
//!
//! Two message families share the format but never the same channel. On a
//! circle channel the types are `loc`, `checkin`, `sos`, `bye` and `rekey`. On
//! an invite channel they are `join`, `ack`, `welcome` and `member`. Keeping
//! them separate is not cosmetic: a `member` record carries a public keypair, so
//! accepting one from a circle channel would let any member graft a key onto
//! every roster, and removing them would not undo the graft.

use serde::{Deserialize, Serialize};

use crate::wire::{FUTURE_SKEW_MS, Post};

/// The protocol version carried in every body. Nothing gates on it; the version
/// is pinned by the string inside the associated data and the signature base,
/// where changing it would change every key and every signature.
pub const VERSION: i64 = 2;

/// Longest a member's display name may be.
pub const MAX_NAME: usize = 24;

/// Longest an avatar emoji may be, in characters.
pub const MAX_EMOJI: usize = 8;

/// Longest a self-set status may be.
pub const MAX_STATUS: usize = 24;

/// How precisely a position is being shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ShareMode {
    /// Full resolution, as the device reports it.
    #[default]
    Precise,
    /// Rounded to roughly a kilometre before encryption, so the ciphertext
    /// itself is coarse and no amount of post-hoc analysis recovers the rest.
    Coarse,
}

/// The fields every circle-channel message carries, identifying the sender.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Who {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub emoji: String,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub hue: i64,
    /// Battery fraction, 0.0 to 1.0. Zero means "not reported".
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub bat: f64,
    #[serde(default, skip_serializing_if = "is_default_mode")]
    pub mode: ShareMode,
    /// A short self-set caption. Empty is a deliberate clear, not an absence.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub st: String,
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}
fn is_zero_f64(v: &f64) -> bool {
    *v == 0.0
}
fn is_default_mode(v: &ShareMode) -> bool {
    *v == ShareMode::Precise
}

impl Who {
    /// Build a `Who`, clamping every free-text field to its limit.
    ///
    /// Clamping happens here rather than at the point of use so there is one
    /// rule, and so an over-long name cannot reach a text layout that has not
    /// accounted for its width.
    pub fn new(
        name: &str,
        emoji: &str,
        hue: i64,
        bat: f64,
        mode: ShareMode,
        status: &str,
    ) -> Self {
        Self {
            name: clamp(name, MAX_NAME),
            emoji: clamp(emoji, MAX_EMOJI),
            hue: hue.rem_euclid(360),
            bat: if bat.is_finite() { bat.clamp(0.0, 1.0) } else { 0.0 },
            mode,
            st: clamp(status, MAX_STATUS),
        }
    }
}

fn clamp(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// The position half of a message.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Fix {
    pub lat: f64,
    pub lon: f64,
    /// Horizontal accuracy in metres.
    pub acc: f64,
}

impl Fix {
    /// Round a fix to roughly a kilometre, for coarse sharing.
    ///
    /// Rounding happens before encryption, so the coarse position is what the
    /// relay stores and what every member sees. Quantising afterwards would
    /// leave the exact position in the ciphertext.
    pub fn coarse(&self) -> Fix {
        const DEG: f64 = 1.0 / 111_320.0; // metres per degree of latitude
        let step = 1000.0 * DEG;
        Fix {
            lat: (self.lat / step).round() * step,
            lon: (self.lon / step).round() * step,
            acc: self.acc.max(1000.0),
        }
    }

    /// True when both coordinates are finite and in range.
    pub fn is_valid(&self) -> bool {
        self.lat.is_finite()
            && self.lon.is_finite()
            && (-90.0..=90.0).contains(&self.lat)
            && (-180.0..=180.0).contains(&self.lon)
            && self.acc.is_finite()
    }
}

/// A message on a circle channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum CircleMsg {
    /// A position, and the sender's current details.
    #[serde(rename = "loc")]
    Loc {
        v: i64,
        ts: i64,
        #[serde(flatten)]
        who: Who,
        #[serde(flatten)]
        fix: Fix,
    },
    /// A deliberate check-in: the sender is here and is fine. Carries a
    /// position, so the circle still sees where "fine" is.
    #[serde(rename = "checkin")]
    CheckIn {
        v: i64,
        ts: i64,
        #[serde(flatten)]
        who: Who,
        #[serde(flatten)]
        fix: Fix,
    },
    /// An emergency. Hold-to-fire in the UI so it cannot be triggered by a
    /// pocket.
    #[serde(rename = "sos")]
    Sos {
        v: i64,
        ts: i64,
        #[serde(flatten)]
        who: Who,
        #[serde(flatten)]
        fix: Fix,
    },
    /// A signed goodbye, so the circle sees "stopped" rather than a dot frozen
    /// at wherever the device last was.
    #[serde(rename = "bye")]
    Bye {
        v: i64,
        ts: i64,
        #[serde(flatten)]
        who: Who,
    },
    /// A re-key, addressed to exactly one recipient. See [`crate::rekey`].
    #[serde(rename = "rekey")]
    ReKey {
        v: i64,
        ts: i64,
        /// The new generation number, exactly one more than the current one.
        g: i64,
        /// The epoch the new generation opens in.
        e0: i64,
        /// The epoch the next seed was mixed at.
        me: i64,
        /// The recipient's member id.
        to: String,
        /// Ephemeral agreement public key, 65 bytes, base64url.
        eph: String,
        /// The wrapped fresh seed: a nonce followed by a GCM ciphertext.
        w: String,
        /// Members removed in this generation, sorted.
        #[serde(default)]
        rm: Vec<String>,
        /// The roster hash the sender expects.
        #[serde(default)]
        rh: String,
    },
}

impl CircleMsg {
    pub fn timestamp(&self) -> i64 {
        match self {
            CircleMsg::Loc { ts, .. }
            | CircleMsg::CheckIn { ts, .. }
            | CircleMsg::Sos { ts, .. }
            | CircleMsg::Bye { ts, .. }
            | CircleMsg::ReKey { ts, .. } => *ts,
        }
    }

    /// Whether this message must only be honoured from a member that was
    /// already pinned before the current ingest pass.
    ///
    /// A re-key creates a new channel, so accepting one from a stranger would
    /// let anyone the relay names a member redirect a circle. Requiring prior
    /// pinning is what closes that.
    pub fn requires_prior_pin(&self) -> bool {
        matches!(self, CircleMsg::ReKey { .. })
    }

    pub fn is_control(&self) -> bool {
        matches!(self, CircleMsg::ReKey { .. })
    }

    /// The position this message carries, if it carries one.
    ///
    /// A single accessor rather than a pattern match at every call site, so a
    /// message type added later cannot be silently treated as having no position
    /// by one caller and as having one by another.
    pub fn fix(&self) -> Option<Fix> {
        match self {
            CircleMsg::Loc { fix, .. }
            | CircleMsg::CheckIn { fix, .. }
            | CircleMsg::Sos { fix, .. } => Some(*fix),
            CircleMsg::Bye { .. } | CircleMsg::ReKey { .. } => None,
        }
    }

    /// The sender's details, for a marker or a notification.
    pub fn who(&self) -> Option<&Who> {
        match self {
            CircleMsg::Loc { who, .. }
            | CircleMsg::CheckIn { who, .. }
            | CircleMsg::Sos { who, .. }
            | CircleMsg::Bye { who, .. } => Some(who),
            CircleMsg::ReKey { .. } => None,
        }
    }

    /// The member id this message was about, for a control message. `None` for
    /// everything else, which carries no addressee.
    pub fn addressed_to(&self) -> Option<&str> {
        match self {
            CircleMsg::ReKey { to, .. } => Some(to),
            _ => None,
        }
    }
}

/// A message on an invite channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum InviteMsg {
    /// A joiner asking to be let in, carrying their own public keys so the
    /// inviter can show a safety number before deciding.
    #[serde(rename = "join")]
    Join {
        v: i64,
        ts: i64,
        pk: String,
        epk: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        name: String,
    },
    /// The inviter claiming their own slot on the rendezvous channel. Sent
    /// before anything else, so the channel has an owner.
    #[serde(rename = "ack")]
    Ack { v: i64, ts: i64, to: String },
    /// The commit point: the new generation's seed, sealed to one joiner.
    #[serde(rename = "welcome")]
    Welcome {
        v: i64,
        ts: i64,
        g: i64,
        e0: i64,
        /// How many member records follow, though they were sent earlier.
        n: i64,
        eph: String,
        w: String,
    },
    /// One existing member's public keypair and name, sealed to a joiner.
    #[serde(rename = "member")]
    Member { v: i64, ts: i64, eph: String, w: String },
}

impl InviteMsg {
    pub fn timestamp(&self) -> i64 {
        match self {
            InviteMsg::Join { ts, .. }
            | InviteMsg::Ack { ts, .. }
            | InviteMsg::Welcome { ts, .. }
            | InviteMsg::Member { ts, .. } => *ts,
        }
    }
}

impl CircleMsg {
    /// A location post.
    pub fn loc(ts: i64, who: Who, fix: Fix) -> Self {
        CircleMsg::Loc { v: VERSION, ts, who, fix }
    }

    /// A check-in.
    pub fn check_in(ts: i64, who: Who, fix: Fix) -> Self {
        CircleMsg::CheckIn { v: VERSION, ts, who, fix }
    }

    /// An emergency.
    pub fn sos(ts: i64, who: Who, fix: Fix) -> Self {
        CircleMsg::Sos { v: VERSION, ts, who, fix }
    }

    /// A signed goodbye.
    pub fn bye(ts: i64, who: Who) -> Self {
        CircleMsg::Bye { v: VERSION, ts, who }
    }
}

impl Fix {
    /// A position from a latitude, longitude and accuracy.
    pub fn new(lat: f64, lon: f64, acc: f64) -> Self {
        Self { lat, lon, acc }
    }
}

impl Who {
    /// A plain identity, with no status and precise sharing.
    pub fn plain(name: &str, emoji: &str, hue: i64) -> Self {
        Who::new(name, emoji, hue, 0.0, ShareMode::Precise, "")
    }
}

/// The plaintext carried inside a welcome's wrap.
///
/// Unlike other bodies this is not padded: it is the generation seed, and
/// padding it would only make the ciphertext larger. The record-count ceiling
/// on the outer message is what bounds its size.
pub const WELCOME_SEED_LEN: usize = 32;

/// The plaintext carried inside a member record's wrap: raw JSON, unpadded.
///
/// This is a real asymmetry with the rest of the protocol and it is deliberate.
/// A member record holds a name, so padding it to 512 would push a long name
/// over the ceiling; instead the name is dropped when the record would not fit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemberRecord {
    pub alg: String,
    pub pk: String,
    pub epk: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
}

/// The plaintext inside a beacon's or circle's sealed body, decoded and
/// checked.
pub enum Body {
    Circle(CircleMsg),
    Invite(InviteMsg),
}

impl Body {
    pub fn timestamp(&self) -> i64 {
        match self {
            Body::Circle(m) => m.timestamp(),
            Body::Invite(m) => m.timestamp(),
        }
    }
}

/// Read the timestamp out of a sealed body without fully parsing it.
///
/// Used to check the inner timestamp against the post header *before* deciding
/// what kind of message it is, because that check gates everything else.
pub fn inner_timestamp_matches(body: &str, expected: i64) -> bool {
    serde_json::from_str::<TimestampProbe>(body)
        .map(|p| p.ts == expected && p.v == VERSION)
        .unwrap_or(false)
}

#[derive(Deserialize)]
struct TimestampProbe {
    v: i64,
    ts: i64,
}

/// Parse a sealed body for a given channel kind.
///
/// A body that parses but claims an impossible timestamp is refused here rather
/// than deeper in, so a message with a garbage clock is rejected at the same
/// place for every type.
pub fn parse_circle(body: &str) -> Option<CircleMsg> {
    let msg: CircleMsg = serde_json::from_str(body).ok()?;
    (msg.timestamp() > 0).then_some(msg)
}

pub fn parse_invite(body: &str) -> Option<InviteMsg> {
    let msg: InviteMsg = serde_json::from_str(body).ok()?;
    (msg.timestamp() > 0).then_some(msg)
}

/// A future timestamp is refused rather than clamped, so a device with a wrong
/// clock learns about it instead of being quietly ignored later.
pub fn timestamp_is_sane(ts: i64, now: i64) -> bool {
    ts > 0 && ts <= now + FUTURE_SKEW_MS
}

/// The sealed body of a post, for display and logging, without decrypting.
pub fn post_is_on_channel(post: &Post) -> bool {
    kestrel_is_member(&post.m)
}

fn kestrel_is_member(s: &str) -> bool {
    crate::kdf::is_member_id(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn who() -> Who {
        Who::new("Ana", "F", 210, 0.62, ShareMode::Precise, "omw")
    }

    fn fix() -> Fix {
        Fix { lat: 44.98, lon: -93.27, acc: 12.0 }
    }

    #[test]
    fn a_location_message_round_trips() {
        let m = CircleMsg::Loc { v: VERSION, ts: 1000, who: who(), fix: fix() };
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(
            json,
            r#"{"t":"loc","v":2,"ts":1000,"name":"Ana","emoji":"F","hue":210,"bat":0.62,"st":"omw","lat":44.98,"lon":-93.27,"acc":12.0}"#
        );
        assert_eq!(parse_circle(&json).unwrap(), m);
    }

    #[test]
    fn the_discriminant_is_t() {
        let json = serde_json::to_string(&CircleMsg::Bye { v: VERSION, ts: 1, who: who() })
            .unwrap();
        assert!(json.contains(r#""t":"bye""#));
    }

    #[test]
    fn every_body_type_is_distinguishable() {
        let cases = [
            CircleMsg::Loc { v: 2, ts: 1, who: who(), fix: fix() },
            CircleMsg::CheckIn { v: 2, ts: 1, who: who(), fix: fix() },
            CircleMsg::Sos { v: 2, ts: 1, who: who(), fix: fix() },
            CircleMsg::Bye { v: 2, ts: 1, who: who() },
            CircleMsg::ReKey {
                v: 2,
                ts: 1,
                g: 1,
                e0: 2,
                me: 2,
                to: "aa".into(),
                eph: "e".into(),
                w: "w".into(),
                rm: vec![],
                rh: "r".into(),
            },
        ];
        for c in &cases {
            let json = serde_json::to_string(c).unwrap();
            assert_eq!(parse_circle(&json).as_ref(), Some(c));
        }
    }

    #[test]
    fn invite_messages_are_a_separate_type() {
        let j = InviteMsg::Join {
            v: 2,
            ts: 1,
            pk: "p".into(),
            epk: "e".into(),
            name: "Cass".into(),
        };
        let json = serde_json::to_string(&j).unwrap();
        assert!(json.contains(r#""t":"join""#));
        // A circle-channel parse must not accept it.
        assert!(parse_circle(&json).is_none());
    }

    #[test]
    fn a_rekey_is_a_control_message_requiring_a_prior_pin() {
        let r = CircleMsg::ReKey {
            v: 2,
            ts: 1,
            g: 1,
            e0: 2,
            me: 2,
            to: "aa".into(),
            eph: "e".into(),
            w: "w".into(),
            rm: vec![],
            rh: String::new(),
        };
        assert!(r.requires_prior_pin());
        assert!(r.is_control());
        let l = CircleMsg::Loc { v: 2, ts: 1, who: who(), fix: fix() };
        assert!(!l.requires_prior_pin());
        assert!(!l.is_control());
    }

    #[test]
    fn free_text_fields_are_clamped() {
        let w = Who::new(
            &"n".repeat(100),
            &"e".repeat(100),
            400,
            5.0,
            ShareMode::Coarse,
            &"s".repeat(100),
        );
        assert_eq!(w.name.chars().count(), MAX_NAME);
        assert_eq!(w.emoji.chars().count(), MAX_EMOJI);
        assert_eq!(w.st.chars().count(), MAX_STATUS);
        assert_eq!(w.hue, 40, "hue is normalised into 0..360");
        assert_eq!(w.bat, 1.0, "battery is clamped into 0..1");
    }

    #[test]
    fn clamping_counts_characters_not_bytes() {
        // Four bytes each; eight characters fit where eight bytes would not.
        let w = Who::new(&"🦊".repeat(30), "", 0, 0.0, ShareMode::Precise, "");
        assert_eq!(w.name.chars().count(), MAX_NAME);
    }

    #[test]
    fn a_non_finite_battery_becomes_zero_rather_than_propagating() {
        let w = Who::new("A", "", 0, f64::NAN, ShareMode::Precise, "");
        assert_eq!(w.bat, 0.0);
    }

    #[test]
    fn coarse_rounding_happens_before_encryption() {
        let f = Fix { lat: 44.98123, lon: -93.27456, acc: 5.0 };
        let c = f.coarse();
        // About a kilometre out at most in each axis.
        assert!((f.lat - c.lat).abs() <= 0.005);
        assert!((f.lon - c.lon).abs() <= 0.005);
        // A coarse fix never claims better accuracy than it has.
        assert!(c.acc >= 1000.0);
    }

    #[test]
    fn coarse_rounding_is_deterministic() {
        let f = Fix { lat: 44.98123, lon: -93.27456, acc: 5.0 };
        assert_eq!(f.coarse(), f.coarse());
    }

    #[test]
    fn invalid_positions_are_detected() {
        assert!(Fix { lat: 0.0, lon: 0.0, acc: 0.0 }.is_valid());
        assert!(!Fix { lat: 91.0, lon: 0.0, acc: 0.0 }.is_valid());
        assert!(!Fix { lat: 0.0, lon: 181.0, acc: 0.0 }.is_valid());
        assert!(!Fix { lat: f64::NAN, lon: 0.0, acc: 0.0 }.is_valid());
        assert!(!Fix { lat: 0.0, lon: 0.0, acc: f64::NAN }.is_valid());
    }

    #[test]
    fn the_inner_timestamp_must_match_the_header() {
        let m = CircleMsg::Loc { v: 2, ts: 1000, who: who(), fix: fix() };
        let json = serde_json::to_string(&m).unwrap();
        assert!(inner_timestamp_matches(&json, 1000));
        assert!(!inner_timestamp_matches(&json, 1001));
    }

    #[test]
    fn the_inner_version_must_be_current() {
        let json = r#"{"t":"loc","v":1,"ts":5,"lat":0,"lon":0,"acc":0}"#;
        assert!(!inner_timestamp_matches(json, 5));
    }

    #[test]
    fn a_body_that_is_not_json_fails_the_timestamp_check() {
        assert!(!inner_timestamp_matches("not json", 1));
        assert!(!inner_timestamp_matches("", 1));
        assert!(!inner_timestamp_matches("{}", 1));
    }

    #[test]
    fn an_empty_status_is_a_deliberate_clear() {
        // An empty string serialises away, and a missing field reads back as
        // empty, so clearing a status round-trips.
        let m = CircleMsg::Loc {
            v: 2,
            ts: 1,
            who: Who::new("A", "", 0, 0.0, ShareMode::Precise, "busy"),
            fix: fix(),
        };
        let mut json = serde_json::to_string(&m).unwrap();
        assert!(json.contains(r#""st":"busy""#));
        json = json.replace(r#","st":"busy""#, "");
        let back = parse_circle(&json).unwrap();
        match back {
            CircleMsg::Loc { who, .. } => assert_eq!(who.st, ""),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn absurd_future_timestamps_are_refused() {
        let now = 1_000_000_000_000;
        assert!(timestamp_is_sane(now, now));
        assert!(timestamp_is_sane(now + FUTURE_SKEW_MS, now));
        assert!(!timestamp_is_sane(now + FUTURE_SKEW_MS + 1, now));
        assert!(!timestamp_is_sane(0, now));
        assert!(!timestamp_is_sane(-5, now));
    }

    #[test]
    fn a_rekey_serialises_its_removal_list_and_roster_hash() {
        let r = CircleMsg::ReKey {
            v: 2,
            ts: 1,
            g: 2,
            e0: 5,
            me: 5,
            to: "cfeb6c3eedeab2f19faf80ee98930d20".into(),
            eph: "E".into(),
            w: "W".into(),
            rm: vec!["cfeb6c3eedeab2f19faf80ee98930d20".into()],
            rh: "hash".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""rm":["cfeb6c3eedeab2f19faf80ee98930d20"]"#));
        assert_eq!(parse_circle(&json).unwrap(), r);
    }

    #[test]
    fn a_member_record_carries_both_keys() {
        let rec = MemberRecord {
            alg: "ed25519".into(),
            pk: "p".into(),
            epk: "e".into(),
            name: "Ana".into(),
        };
        let json = serde_json::to_string(&rec).unwrap();
        let back: MemberRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }
}
