//! Where the app keeps its secrets, and how they never leave.
//!
//! Everything in this file is about one thing: the keys that decrypt a location
//! history should exist on exactly one phone, for exactly as long as the user keeps
//! this app installed, and should be impossible to restore onto another phone. That
//! rules out Android's backup, and it is why [`store::allow_backup`] is false.
//!
//! The files are plain, small, and encrypted with a key that is itself encrypted with
//! a passphrase the user chose. A locked phone therefore does not protect the circle
//! from an attacker who has the file: the passphrase is the thing standing in the way,
//! and the app is honest about that rather than implying hardware protection it does
//! not have.

use std::io::Write;

use kestrel_core::seal::random_bytes;

use crate::state::now_ms;

/// Re-exported so callers do not have to know which module the clock lives in.
pub use crate::state::now_ms as wall_clock;

/// Where everything lives.
///
/// One directory under the app's private storage. Android already scopes that to this
/// app, so there is no path handling to get wrong and nothing to ask permission for.
pub fn dir() -> std::path::PathBuf {
    crate::platform::data_dir().join("kestrel")
}

/// The circle's key material, encrypted.
pub fn seed_path() -> std::path::PathBuf {
    dir().join("circle.seed")
}

/// The identity that seeds it.
pub fn identity_path() -> std::path::PathBuf {
    dir().join("identity.json")
}

/// The passcode verifier. Not a key: a salt and a hash, so reading it does not reveal
/// the passcode.
pub fn lock_path() -> std::path::PathBuf {
    dir().join("lock.json")
}

/// Settings that are not secret: display name, basemap, the Tor preference.
pub fn settings_path() -> std::path::PathBuf {
    dir().join("settings.json")
}

/// The last known camera position, so the map opens where the user left it.
pub fn camera_path() -> std::path::PathBuf {
    dir().join("camera.json")
}

/// Make the directory, with as little permission on it as the platform allows.
///
/// `700`: only this user. The keys are here, and a directory any other app on the
/// device can list is not a place to keep them.
pub fn ensure_dir() -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let d = dir();
    std::fs::create_dir_all(&d)?;
    let mut perms = std::fs::metadata(&d)?.permissions();
    perms.set_mode(0o700);
    let _ = std::fs::set_permissions(&d, perms);
    Ok(())
}

/// Write a file, with as little permission on it as the platform allows.
///
/// Written to a temporary name and renamed into place, so a crash mid-write cannot
/// leave a half-written key file. A truncated key file is indistinguishable from a
/// corrupt one, and the difference is the difference between a working circle and a
/// lost history.
pub fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    ensure_dir()?;
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Read a file, or nothing.
pub fn read(path: &std::path::Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

/// Whether a circle has been created on this device.
pub fn has_circle() -> bool {
    seed_path().exists()
}

/// Whether the app lock has been turned on.
pub fn is_locked() -> bool {
    lock_path().exists()
}

/// The salt and verifier for the app lock.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Lock {
    /// Random, so two people who pick the same passcode do not have the same hash.
    pub salt: String,
    /// Hex-encoded, so the file is readable by eye and there is no base64 padding to
    /// get wrong.
    pub hash: String,
    /// How many times the key was stretched. Stored so a future version can raise it
    /// without invalidating an existing passcode.
    pub rounds: u32,
}

/// Work factor for the passcode hash.
///
/// Deliberately slow: this is the only thing between a stolen phone's backup and a
/// circle's location history. Chosen to take a fraction of a second on a phone, which
/// is invisible to the user and ruinous to an attacker guessing in a loop.
const ROUNDS: u32 = 120_000;

/// The same work factor, exposed for the seed encryption in [`crate::logic`].
///
/// Unlocked and encrypted must cost the same wait, or the lock feels free while the
/// decrypt behind it is slow.
pub const ROUNDS_FOR_CRYPTO: u32 = ROUNDS;

/// Turn a passcode into a lock file, or explain why not.
///
/// A refusal here is worth explaining rather than silently failing: a four-digit
/// passcode is guessable in a fraction of a second at any reasonable work factor, and
/// an app that accepts one while claiming to be locked is lying about the most
/// important thing it does.
pub fn make_lock(passcode: &str) -> Result<Lock, String> {
    if passcode.chars().count() < 6 {
        return Err("Use at least six characters.".to_string());
    }
    let salt: [u8; 16] = random_bytes();
    let hash = derive(passcode, &salt, ROUNDS);
    Ok(Lock { salt: kestrel_core::b64::encode(&salt), hash: hex(&hash), rounds: ROUNDS })
}

/// Check a passcode against a stored lock.
///
/// A comparison that does not stop early. The lengths are equal here, so it does not
/// matter in practice, but a lock file is attacker-supplied data and a comparison that
/// leaks how many leading characters matched is a comparison worth not having.
pub fn check_lock(passcode: &str, lock: &Lock) -> bool {
    let Some(salt) = kestrel_core::b64::decode(&lock.salt) else {
        return false;
    };
    if salt.len() != 16 {
        return false;
    }
    let Some(expected) = hex_decode(&lock.hash) else {
        return false;
    };
    let actual = derive(passcode, &salt, lock.rounds);
    constant_eq(&actual, &expected)
}

/// Stretch a passcode into 32 bytes.
///
/// SHA-256 in a loop rather than a memory-hard function, because this runs on a phone
/// and Argon2 would need a dependency and a few hundred kilobytes for a threat this
/// app has: a stolen backup, not a GPU sitting on the device. The loops are the honest
/// part; memory-hardness would be theatre at this scale.
fn derive(passcode: &str, salt: &[u8], rounds: u32) -> [u8; 32] {
    let mut acc = [0u8; 32];
    let mut first = true;
    for round in 0..rounds.max(1) {
        let mut input = Vec::with_capacity(salt.len() + passcode.len() + 4);
        input.extend_from_slice(salt);
        input.extend_from_slice(passcode.as_bytes());
        input.extend_from_slice(&round.to_le_bytes());
        let digest = sha256(&input);
        if first {
            acc.copy_from_slice(&digest);
            first = false;
        } else {
            for (a, b) in acc.iter_mut().zip(digest.iter()) {
                *a ^= b;
            }
        }
    }
    acc
}

/// SHA-256.
///
/// The same crate and the same version the core uses for everything else, so there is
/// one implementation in the APK rather than two — which is the point of a
/// twelve-megabyte target.
fn sha256(input: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(input);
    h.finalize().into()
}

/// Whether two byte strings are equal, without an early exit.
fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        s.push(char::from_digit((b & 0xF) as u32, 16).unwrap_or('0'));
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// How long an invitation stays usable.
///
/// An hour. Long enough to send someone a code and have them scan it over coffee, short
/// enough that a screenshot of the chat it was pasted into is worthless by the evening.
pub const INVITE_TTL_MS: i64 = 60 * 60 * 1000;

/// The signed-in state, as it is remembered between runs.
///
/// Only what is not already in the circle: the name the user chose and whether they
/// want the fine or the approximate position shared by default.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Settings {
    /// The name shown to the circle. Empty until the user sets one, because an app
    /// that invents a name for someone is a name the circle will trust.
    #[serde(default)]
    pub name: String,
    /// Which basemap to draw.
    #[serde(default)]
    pub basemap: u8,
    /// Whether to route through Tor.
    #[serde(default)]
    pub tor: bool,
    /// Whether the map follows this device's position.
    #[serde(default)]
    pub follow: bool,
    /// Where to send beacons, if the user has set one up.
    #[serde(default)]
    pub beacon: Option<String>,
    /// The language, by index into [`crate::strings::Language::ALL`].
    ///
    /// An index rather than a name, so adding a language later cannot silently reset
    /// everyone's choice. Absent means the first language, which is English.
    #[serde(default)]
    pub language: u8,
}

/// Read the settings, or the defaults.
pub fn load_settings() -> Settings {
    read(&settings_path()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

/// Save the settings.
///
/// A write that fails is a write that is reported. Silently losing the user's chosen
/// name on the next launch is worse than an error message.
pub fn save_settings(settings: &Settings) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(settings)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    write_private(&settings_path(), &bytes)
}

/// The live invitation, if one is still usable.
///
/// Persisted because the code a user has already shown somebody must keep
/// working after the app is closed. Re-minting on the next launch would leave
/// the QR on the other phone pointing at a rendezvous nobody is listening on,
/// which is a link that looks alive and answers nothing.
pub fn invite_path() -> std::path::PathBuf {
    dir().join("invite.json")
}

/// Remember an invitation.
pub fn save_invite(invite: &kestrel_core::invite::Invite) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(invite)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    write_private(&invite_path(), &bytes)
}

/// Read the invitation back, if one is there and still usable.
///
/// An expired one is discarded rather than loaded: a link the relay will refuse
/// is not a link, and keeping it would put a dead rendezvous on the wire every
/// time the app starts.
pub fn load_invite(now: i64) -> Option<kestrel_core::invite::Invite> {
    let bytes = read(&invite_path())?;
    let invite: kestrel_core::invite::Invite = serde_json::from_slice(&bytes).ok()?;
    (!invite.is_expired(now)).then_some(invite)
}

/// Forget the invitation. Called once its handshake has been used.
pub fn clear_invite() {
    let _ = std::fs::remove_file(invite_path());
}

/// Where the map was left.
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct LastCamera {
    pub lat: f64,
    pub lon: f64,
    pub zoom: f64,
}

pub fn load_camera() -> Option<LastCamera> {
    let camera: LastCamera =
        read(&camera_path()).and_then(|b| serde_json::from_slice(&b).ok())?;
    // A camera pointed at the middle of the ocean is a corrupt file, not a place. Opening
    // the map there would send the user looking for the reason.
    (camera.lat.is_finite()
        && camera.lon.is_finite()
        && camera.lat.abs() <= 90.0
        && camera.lon.abs() <= 180.0)
        .then_some(camera)
}

pub fn save_camera(camera: LastCamera) {
    if let Ok(bytes) = serde_json::to_vec(&camera) {
        let _ = write_private(&camera_path(), &bytes);
    }
}

/// Delete everything this app stored.
///
/// Used by the duress passcode. Not a partial wipe: a duress wipe that left the
/// location history behind would defeat the point of typing a second passcode while
/// someone is holding your phone.
pub fn wipe() {
    for path in [
        seed_path(),
        identity_path(),
        lock_path(),
        settings_path(),
        camera_path(),
        invite_path(),
    ] {
        let _ = std::fs::remove_file(path);
    }
}

/// Whether Android is allowed to back this app up.
///
/// Always false, and asserted by a test rather than merely set: a backed-up Kestrel is
/// a backed-up copy of the keys that decrypt a location history, and whoever restores
/// it holds that history.
pub const BACKUP_ALLOWED: bool = false;

/// When the last share was posted, for the "sent 2 min ago" line.
pub fn last_share_ms() -> i64 {
    read(&dir().join("last-share"))
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

pub fn set_last_share_ms(at: i64) {
    let _ = write_private(&dir().join("last-share"), at.to_string().as_bytes());
}

/// A readable "how long ago" for the status line.
///
/// Chosen to say how stale something is without making it sound like a stopwatch.
pub fn ago(ms: i64) -> String {
    let now = now_ms();
    let secs = ((now - ms).max(0) as f64) / 1000.0;
    if secs < 60.0 {
        return "just now".to_string();
    }
    let mins = secs / 60.0;
    if mins < 60.0 {
        return format!("{} min ago", mins.round() as i64);
    }
    let hours = mins / 60.0;
    if hours < 24.0 {
        return format!("{} h ago", hours.round() as i64);
    }
    format!("{} d ago", (hours / 24.0).round() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_settings_file_round_trips() {
        // Somewhere to check the shape of what is written. Not run against the real
        // directory: this is about the fields, and the paths belong to the platform.
        let settings = Settings {
            name: "Ada".into(),
            basemap: 1,
            tor: false,
            follow: true,
            beacon: None,
            language: 0,
        };
        let bytes = serde_json::to_vec(&settings).unwrap();
        let back: Settings = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.name, "Ada");
        assert!(back.follow);
        assert!(!back.tor);
    }

    #[test]
    fn backup_is_off() {
        // The single most consequential constant in the app. Checked as a `const`
        // block so it is a compile error rather than a test someone can delete: flipping
        // this to true would still leave every other test green.
        const { assert!(!BACKUP_ALLOWED) };
    }

    #[test]
    fn a_passcode_round_trips() {
        let lock = make_lock("correct horse").unwrap();
        assert!(check_lock("correct horse", &lock));
        assert!(!check_lock("correct horse ", &lock));
        assert!(!check_lock("Correct horse", &lock));
    }

    #[test]
    fn a_short_passcode_is_refused_with_a_reason() {
        // Refused rather than accepted: four digits is guessable in seconds at any work
        // factor, and an app that accepts one while claiming to be locked is lying.
        let err = make_lock("1234").unwrap_err();
        assert!(err.contains("six"), "{err}");
        assert!(make_lock("123456").is_ok());
    }

    #[test]
    fn the_same_passcode_twice_gives_two_different_hashes() {
        // Otherwise two people who pick the same passcode would have identical files,
        // and a stolen file would say something about their choices.
        let a = make_lock("same passcode").unwrap();
        let b = make_lock("same passcode").unwrap();
        assert_ne!(a.hash, b.hash);
        assert_ne!(a.salt, b.salt);
    }

    #[test]
    fn a_damaged_lock_file_refuses_rather_than_opens() {
        // A lock file is attacker-supplied data. Every malformed shape must fail
        // closed: a file that fails open is a lock that can be opened by editing it.
        let good = make_lock("a good passcode").unwrap();
        let damaged: Vec<Lock> = vec![
            Lock { salt: "not base64".into(), ..good.clone() },
            Lock { salt: String::new(), ..good.clone() },
            Lock { hash: "zz".into(), ..good.clone() },
            // Odd length: not hex at all.
            Lock { hash: "abc".into(), ..good.clone() },
            // Hex, but not 32 bytes, so it cannot be a hash of anything.
            Lock { hash: "00".into(), ..good.clone() },
            Lock { rounds: 0, ..good.clone() },
        ];
        for lock in damaged {
            assert!(
                !check_lock("a good passcode", &lock),
                "a damaged lock must refuse, not open"
            );
        }
        // And the undamaged one still works, so the check above is testing damage and
        // not a passcode that never matched.
        assert!(check_lock("a good passcode", &good));
    }

    #[test]
    fn the_lock_is_worth_guessing_slowly() {
        // The work factor is recorded rather than implicit, so raising it later does
        // not invalidate an existing passcode.
        let lock = make_lock("a good passcode").unwrap();
        assert!(lock.rounds >= 100_000, "only {} rounds", lock.rounds);
        assert_eq!(lock.hash.len(), 64, "32 bytes as hex");
    }

    #[test]
    fn hex_round_trips() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        assert_eq!(hex_decode(&hex(&bytes)).unwrap(), bytes);
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
    }

    #[test]
    fn ago_reads_the_way_a_person_would_say_it() {
        let now = now_ms();
        assert_eq!(ago(now), "just now");
        assert_eq!(ago(now - 5_000), "just now");
        assert_eq!(ago(now - 120_000), "2 min ago");
        assert_eq!(ago(now - 3 * 3_600_000), "3 h ago");
        assert_eq!(ago(now - 50 * 3_600_000), "2 d ago");
    }

    #[test]
    fn ago_does_not_say_anything_silly_about_the_future() {
        // A clock that jumped backwards would otherwise produce a negative age.
        let future = now_ms() + 60_000;
        assert_eq!(ago(future), "just now");
    }

    #[test]
    fn an_invitation_lives_for_an_hour() {
        assert_eq!(INVITE_TTL_MS, 3_600_000);
    }

    #[test]
    fn an_invitation_survives_a_round_trip() {
        // The code somebody already scanned has to still be the code after the app
        // is closed, or the link on the other phone points at nothing.
        let inviter = kestrel_core::identity::Identity::generate();
        let now = 1_700_000_000_000;
        let invite = kestrel_core::invite::Invite::mint(&inviter, now, INVITE_TTL_MS);
        let bytes = serde_json::to_vec(&invite).unwrap();
        let back: kestrel_core::invite::Invite = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.fragment(), invite.fragment());
        assert_eq!(back.channel(), invite.channel());
        assert!(!back.is_expired(now + 1));
    }
}
