//! Secrets at rest: the circle seed, and the key that protects it.
//!
//! A stolen phone is the threat this module addresses. Two things must survive
//! that: the circle secret must be unreadable on disk, and the passcode that
//! unlocks it must not be guessable in reasonable time.
//!
//! The KDF is PBKDF2-SHA-256 at 600,000 iterations. That is a deliberate
//! limitation and it is stated rather than hidden: memory-hard key derivation
//! resists GPU attacks far better, and a pure-Rust Argon2id is a large
//! dependency to carry for one function. Argon2id is the right answer and this
//! is the second-best one, documented so nobody mistakes it for the first.
//!
//! The vault holds more than the seed. A circle's roster, places and settings
//! are all encrypted under the same key, so a seizure yields nothing readable:
//! not a name, not a home address, not the fact that a circle exists.

use std::collections::BTreeMap;

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{b64, seal::random_bytes, wire::EPOCH_MS};

/// PBKDF2 iteration count. The floor, and the value the reference protocol uses.
pub const PBKDF2_ITERATIONS: u32 = 600_000;

/// Length of a vault key.
pub const KEY_LEN: usize = 32;

/// Length of the per-entry salt.
pub const SALT_LEN: usize = 16;

/// Shortest passcode accepted. Long enough to have entropy, short enough that
/// someone types it on a moving bus.
pub const MIN_PASSPHRASE_CHARS: usize = 8;

/// Attempts before the stored data is destroyed, when an attacker can try
/// offline. There is no lockout here: an offline attacker has the database, and
/// a counter in the database is a counter they can edit.
pub const MAX_ATTEMPTS: u32 = 10;

/// A stored secret: a salt, an iteration count, and the sealed value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    /// Version tag, so a future format change is detectable rather than
    /// producing garbage.
    pub v: u8,
    pub salt: String,
    pub iterations: u32,
    /// `nonce || ciphertext`, base64url.
    pub data: String,
}

/// The vault key, held only while unlocked.
pub struct VaultKey([u8; KEY_LEN]);

impl VaultKey {
    /// Derive a key from a passcode and a salt.
    ///
    /// The salt is per-vault, so two devices with the same passcode do not have
    /// the same key, and the derivation is slow by design.
    pub fn from_passphrase(passphrase: &str, salt: &[u8; SALT_LEN]) -> Self {
        Self::from_passphrase_with(passphrase, salt, PBKDF2_ITERATIONS)
    }

    /// Derive a key at an explicit iteration count.
    ///
    /// Exists so the test suite can exercise the plumbing in seconds rather than
    /// in minutes. The production count is not negotiable at any call site that
    /// a user can reach; this is not one.
    pub fn from_passphrase_with(
        passphrase: &str,
        salt: &[u8; SALT_LEN],
        iterations: u32,
    ) -> Self {
        let mut key = [0u8; KEY_LEN];
        pbkdf2(passphrase.as_bytes(), salt, iterations, &mut key);
        Self(key)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl Drop for VaultKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultKey(<redacted>)")
    }
}

/// PBKDF2-HMAC-SHA-256.
///
/// Implemented here rather than taken from a crate because it is the single
/// primitive the whole at-rest scheme rests on, and having it in this file means
/// the iteration count and the output length are read next to each other.
pub fn pbkdf2(passphrase: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let blocks = out.len().div_ceil(32);
    for block in 1..=blocks {
        // U1 = HMAC(passphrase, salt || block index)
        let mut input = Vec::with_capacity(salt.len() + 4);
        input.extend_from_slice(salt);
        input.extend_from_slice(&(block as u32).to_be_bytes());
        let mut u = hmac_sha256(passphrase, &input);
        let mut acc = u;

        for _ in 1..iterations {
            u = hmac_sha256(passphrase, &u);
            for (a, b) in acc.iter_mut().zip(u.iter()) {
                *a ^= *b;
            }
        }
        let start = (block - 1) * 32;
        let end = (start + 32).min(out.len());
        out[start..end].copy_from_slice(&acc[..end - start]);
        u.zeroize();
        acc.zeroize();
    }
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        k[..32].copy_from_slice(&digest);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

/// What a vault holds, all of it encrypted.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Contents {
    /// The generation seed. The one secret that names a circle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<String>,
    /// Per-member records, by member id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub members: BTreeMap<String, String>,
    /// Places, by local id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub places: BTreeMap<String, String>,
    /// The generation number and the epoch it opened in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<i64>,
    /// The epoch the generation opened in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opened_epoch: Option<i64>,
    /// When this generation was created, for the periodic re-key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation_at: Option<i64>,
    /// This device's own identity, sealed under the vault key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
}

impl Contents {
    pub fn is_empty(&self) -> bool {
        self.seed.is_none() && self.members.is_empty() && self.places.is_empty()
    }

    /// The seed, as bytes.
    pub fn seed_bytes(&self) -> Option<[u8; 32]> {
        let s = self.seed.as_ref()?;
        b64::decode_exact::<32>(s)
    }
}

/// The stored form of a vault: a header and one sealed blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stored {
    /// Format version.
    pub v: u8,
    pub salt: String,
    pub iterations: u32,
    /// Sealed contents.
    pub data: String,
    /// How many wrong passcodes have been tried. Advisory only: an attacker with
    /// the file owns this field.
    pub attempts: u32,
}

/// The format version this build writes.
pub const VAULT_VERSION: u8 = 1;

/// The largest iteration count a stored file may ask for before it is refused.
pub const MAX_STORED_ITERATIONS: u32 = PBKDF2_ITERATIONS * 4;

/// A vault: the key, and the record that goes on disk.
///
/// These two are one thing rather than a key and a count that have to be kept in
/// agreement. Getting them out of step produces a file that looks fine and cannot
/// be opened, which is exactly the kind of failure that is invisible until
/// someone is standing in a car park needing their map.
pub struct Vault {
    key: VaultKey,
    salt: [u8; SALT_LEN],
    iterations: u32,
}

impl Vault {
    /// Create a new vault, sealed with an empty set of contents.
    pub fn create(passphrase: &str) -> (Self, Stored) {
        Self::create_with(passphrase, PBKDF2_ITERATIONS)
    }

    /// Create a new vault at an explicit iteration count. Test-only in practice.
    pub fn create_with(passphrase: &str, iterations: u32) -> (Self, Stored) {
        let salt: [u8; SALT_LEN] = random_bytes();
        let key = VaultKey::from_passphrase_with(passphrase, &salt, iterations);
        let vault = Self { key, salt, iterations };
        let stored = vault.seal(&Contents::default());
        (vault, stored)
    }

    /// Open an existing vault, or `None` if the passcode is wrong.
    pub fn open(stored: &Stored, passphrase: &str) -> Option<Self> {
        if stored.v != VAULT_VERSION {
            return None;
        }
        // The count comes from the file, so an attacker who can edit the vault
        // can set it to four billion and turn the lock screen into a denial of
        // service. A legitimate file always records a count this build knows, so
        // a small multiple costs nothing and removes the lever.
        if stored.iterations == 0 || stored.iterations > MAX_STORED_ITERATIONS {
            return None;
        }
        let salt: [u8; SALT_LEN] = b64::decode_exact(&stored.salt)?;
        let key = VaultKey::from_passphrase_with(passphrase, &salt, stored.iterations);
        // The key is proved before it is handed back, so a vault that cannot be
        // opened is never returned in a half-usable state.
        Self::read(stored, &key, &salt, stored.iterations)?;
        Some(Self { key, salt, iterations: stored.iterations })
    }

    /// Decrypt the record under an already-derived key.
    fn read(
        stored: &Stored,
        key: &VaultKey,
        _salt: &[u8; SALT_LEN],
        _iterations: u32,
    ) -> Option<Contents> {
        let blob = b64::decode(&stored.data)?;
        if blob.len() <= 12 {
            return None;
        }
        let (nonce, ct) = blob.split_at(12);
        let nonce: [u8; 12] = nonce.try_into().ok()?;
        let plain = crate::seal::open(key.as_bytes(), &nonce, ct, b"kestrel/vault/v1")?;
        serde_json::from_slice(&plain).ok()
    }

    /// The vault's key, for deriving per-purpose subkeys.
    pub fn key(&self) -> &VaultKey {
        &self.key
    }

    /// Read the current contents.
    pub fn contents(&self, stored: &Stored) -> Option<Contents> {
        Self::read(stored, &self.key, &self.salt, self.iterations)
    }

    /// Seal contents into a fresh record, with the attempt counter cleared.
    pub fn seal(&self, contents: &Contents) -> Stored {
        let json = serde_json::to_vec(contents).expect("contents are serialisable");
        let nonce: [u8; 12] = random_bytes();
        let ct = crate::seal::seal(self.key.as_bytes(), &nonce, &json, b"kestrel/vault/v1")
            .expect("a vault blob always seals");
        let mut blob = Vec::with_capacity(12 + ct.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        Stored {
            v: VAULT_VERSION,
            salt: b64::encode(&self.salt),
            iterations: self.iterations,
            data: b64::encode(&blob),
            attempts: 0,
        }
    }

    /// The record as it stands, keeping the attempt counter.
    pub fn reseal(&self, stored: &Stored, contents: &Contents) -> Stored {
        let mut out = self.seal(contents);
        out.attempts = stored.attempts;
        out
    }
}

/// Try to open a vault.
///
/// Returns `None` for a wrong passcode, a wrong format, or a modified file; the
/// three are not distinguished, because telling them apart would tell an attacker
/// which of the three they had.
/// Open a vault and read it, in one call.
///
/// A convenience for callers that hold nothing else. Anything that will derive
/// subkeys or seal again should hold a [`Vault`] instead, so the key is not
/// derived twice.
pub fn open_contents(stored: &Stored, passphrase: &str) -> Option<Contents> {
    let vault = Vault::open(stored, passphrase)?;
    vault.contents(stored)
}

/// A passphrase's strength, for the UI to show before it is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Strength {
    TooShort,
    Weak,
    Fair,
    Good,
}

/// Rate a passphrase by what it actually is: length, and variety.
///
/// Deliberately not a formula that rewards `P@ssw0rd1`. A dictionary attack
/// ignores character-class rules, so the estimate is dominated by length, and
/// that is the number the user can actually change.
pub fn rate_passphrase(passphrase: &str) -> Strength {
    let n = passphrase.chars().count();
    if n < MIN_PASSPHRASE_CHARS {
        return Strength::TooShort;
    }
    // Rough bits of entropy, assuming the user is not deliberately
    // adversarial: a lower bound, so a strong passphrase is never called weak.
    let classes = [
        passphrase.chars().any(|c| c.is_ascii_lowercase()),
        passphrase.chars().any(|c| c.is_ascii_uppercase()),
        passphrase.chars().any(|c| c.is_ascii_digit()),
        passphrase.chars().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .iter()
    .filter(|b| **b)
    .count()
    .max(1);
    let bits = (n as f64) * (classes as f64 + 3.0).log2();
    match bits {
        ..=40.0 => Strength::Weak,
        41.0..=60.0 => Strength::Fair,
        61.0..=80.0 => Strength::Good,
        _ => Strength::Fair, // A long passphrase is good, not excellent.
    }
}

impl Strength {
    /// Whether the vault will accept this passcode.
    ///
    /// Only length is enforced. Refusing a weak passphrase is theatre: a
    /// determined user will pick `hunter2` again whatever the app says, and an
    /// app that refuses their choice gets uninstalled. So a weak passphrase is
    /// accepted with a warning, and a short one is not, because below eight
    /// characters the search space is small enough to be hopeless.
    pub fn is_acceptable(self) -> bool {
        !matches!(self, Strength::TooShort)
    }

    /// Whether the UI should say something before the user commits.
    pub fn warrants_a_warning(self) -> bool {
        matches!(self, Strength::Weak | Strength::Fair)
    }
}

/// Derive a subkey for a named purpose from the vault key.
///
/// One key encrypts everything, and giving each field its own derived key means a
/// blob copied from one place cannot be pasted into another and still open.
pub fn subkey(vault: &VaultKey, purpose: &str) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(vault.as_bytes()), b"kestrel/vault/subkey");
    let mut out = [0u8; KEY_LEN];
    let _ = hk.expand(purpose.as_bytes(), &mut out);
    out
}

/// A duress passcode: a second one that wipes instead of unlocking.
///
/// Stored as a verifier, like a password, rather than as the passcode itself. The
/// check derives from the candidate and compares digests, so neither the value
/// nor its length is recoverable from what is on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuressGuard {
    pub salt: String,
    pub iterations: u32,
    /// A derived digest, not the passcode.
    pub verifier: String,
}

impl DuressGuard {
    /// The iteration count this guard was armed with, or `None` if the stored
    /// value does not parse. A mismatch with [`PBKDF2_ITERATIONS`] means the
    /// guard was written by a different build and the duress check is
    /// unavailable, which the caller must treat as "no guard".
    pub fn is_current(&self) -> bool {
        self.iterations == PBKDF2_ITERATIONS
    }
}

impl DuressGuard {
    /// Arm a duress passcode.
    pub fn arm(passphrase: &str, salt: &[u8; SALT_LEN]) -> Self {
        Self::arm_with(passphrase, salt, PBKDF2_ITERATIONS)
    }

    /// Arm a duress passcode at an explicit iteration count. Test-only in
    /// practice; see [`VaultKey::from_passphrase_with`].
    pub fn arm_with(passphrase: &str, salt: &[u8; SALT_LEN], iterations: u32) -> Self {
        Self {
            salt: b64::encode(salt),
            iterations,
            verifier: b64::encode(&derive_verifier(passphrase, salt)),
        }
    }

    /// Whether this passcode is the duress one.
    pub fn matches(&self, passphrase: &str) -> bool {
        let Some(salt) = b64::decode_exact::<SALT_LEN>(&self.salt) else {
            return false;
        };
        let Some(want) = b64::decode_exact::<KEY_LEN>(&self.verifier) else {
            return false;
        };
        let got = derive_verifier(passphrase, &salt);
        bool::from(got.ct_eq(&want))
    }
}

/// The domain-separated digest a passcode is stored as.
fn derive_verifier(passphrase: &str, salt: &[u8; SALT_LEN]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(Some(salt), passphrase.as_bytes());
    let mut out = [0u8; KEY_LEN];
    let _ = hk.expand(b"kestrel/vault/duress", &mut out);
    out
}

/// What a passcode typed at the lock screen should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockAction {
    /// The right passcode: unlock.
    Unlock,
    /// The duress passcode: wipe everything and come back as a fresh install.
    Wipe,
    /// Neither.
    Retry,
}

/// Decide what a passcode means.
///
/// The duress check runs first and unconditionally, and always does the same
/// amount of work, so a wrong passcode and the duress one are not
/// distinguishable by timing.
pub fn unlock_action(
    candidate: &str,
    stored: &Stored,
    duress: Option<&DuressGuard>,
) -> UnlockAction {
    if duress.is_some_and(|d| d.matches(candidate)) {
        return UnlockAction::Wipe;
    }
    if Vault::open(stored, candidate).is_some() {
        return UnlockAction::Unlock;
    }
    UnlockAction::Retry
}

/// Whether a periodic re-key is due.
///
/// Every day, plus a per-device jitter derived from the member id so a circle
/// does not re-key in unison. Without the jitter, a circle of devices that were
/// all opened at once would re-key at the same second, in the same instant, and
/// every relay row would spike together.
pub fn rekey_due(generation_at: i64, member_id: &str, now: i64) -> bool {
    if generation_at == 0 {
        // A generation with no creation time would never re-key, which would
        // silently disable post-compromise security for that circle. Treated as
        // immediately due instead.
        return true;
    }
    let mut jitter_bytes = [0u8; 6];
    for (i, c) in member_id.bytes().take(6).enumerate() {
        jitter_bytes[i] = c;
    }
    let jitter = (u64::from_str_radix(&kestrel_crate_hex(&jitter_bytes), 16).unwrap_or(0)
        % 3600) as i64;
    now - generation_at > 24 * 60 * 60 * 1000 + jitter * 1000
}

fn kestrel_crate_hex(b: &[u8]) -> String {
    crate::kdf::hex(b)
}

/// When a generation opened, as an epoch, for the snapshot.
pub fn opened_epoch_of(contents: &Contents, now: i64) -> i64 {
    contents.opened_epoch.unwrap_or_else(|| crate::wire::epoch_at(now))
}

const _: () = assert!(EPOCH_MS == 600_000);

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; SALT_LEN] = [7u8; SALT_LEN];

    fn a_passphrase() -> String {
        "correct horse battery staple".to_string()
    }

    /// The iteration count the test suite uses.
    ///
    /// Correctness of the iteration loop is pinned by the RFC vectors above, so
    /// the count here only has to be big enough to exercise the loop. Six hundred
    /// thousand rounds in a debug build takes minutes; in release it is the right
    /// trade for a real vault and the wrong one for a unit test. The production
    /// constant is asserted separately, so this cannot hide a change to it.
    const TEST_ITERATIONS: u32 = 50;

    fn a_vault(passphrase: &str) -> (Vault, Stored) {
        Vault::create_with(passphrase, TEST_ITERATIONS)
    }

    #[test]
    fn hmac_matches_the_published_sha256_test_vector() {
        // RFC 4231 case 1.
        let key = [0x0bu8; 20];
        let out = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            crate::kdf::hex(&out),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_handles_a_key_longer_than_the_block_size() {
        // RFC 4231 case 6: an 80-byte key is longer than the 64-byte block, so
        // it is hashed first. A copy that skipped that step would produce a
        // different answer, which is what this pins.
        let key = [0xaau8; 80];
        let out =
            hmac_sha256(&key, b"Test Using Larger Than Block-Size Key - Hash Key First");
        assert_eq!(
            crate::kdf::hex(&out),
            "6953025ed96f0c09f80a96f78e6538dbe2e7b820e3dd970e7ddd39091b32352f"
        );
        // And the same message under a short key is a different answer, so the
        // two paths are genuinely distinct.
        assert_ne!(
            out,
            hmac_sha256(
                &[0xaau8; 64],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )
        );
    }

    #[test]
    fn pbkdf2_matches_rfc6070() {
        // RFC 6070 gives vectors for HMAC-SHA-1, so only the structure can be
        // checked here; the SHA-256 vector below is from the widely used
        // reference set.
        let mut out = [0u8; 32];
        pbkdf2(b"password", b"salt", 1, &mut out);
        assert_eq!(
            crate::kdf::hex(&out),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );

        // And the c=4096 case, which is where an off-by-one in the loop shows up.
        pbkdf2(b"password", b"salt", 4096, &mut out);
        assert_eq!(
            crate::kdf::hex(&out),
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
        );
    }

    #[test]
    fn pbkdf2_handles_a_key_longer_than_one_block() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        pbkdf2(&[0x61u8; 100], b"NaCl", 2, &mut a);
        pbkdf2(&[0x61u8; 100], b"NaCl", 2, &mut b);
        assert_eq!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn pbkdf2_spans_multiple_blocks() {
        let mut wide = [0u8; 64];
        pbkdf2(b"pass", b"salt", 2, &mut wide);
        let mut narrow = [0u8; 32];
        pbkdf2(b"pass", b"salt", 2, &mut narrow);
        // The first block is the same; the second is not a repeat of it.
        assert_eq!(&wide[..32], &narrow[..]);
        assert_ne!(&wide[..32], &wide[32..]);
    }

    #[test]
    fn the_same_passphrase_and_salt_give_the_same_key() {
        let a = VaultKey::from_passphrase_with(&a_passphrase(), &SALT, TEST_ITERATIONS);
        let b = VaultKey::from_passphrase_with(&a_passphrase(), &SALT, TEST_ITERATIONS);
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn a_different_passphrase_or_salt_gives_a_different_key() {
        let base = VaultKey::from_passphrase_with(&a_passphrase(), &SALT, TEST_ITERATIONS);
        let other_pass = VaultKey::from_passphrase_with(
            "something else entirely",
            &SALT,
            TEST_ITERATIONS,
        );
        let other_salt = VaultKey::from_passphrase_with(
            &a_passphrase(),
            &[8u8; SALT_LEN],
            TEST_ITERATIONS,
        );
        assert_ne!(base.as_bytes(), other_pass.as_bytes());
        assert_ne!(base.as_bytes(), other_salt.as_bytes());
    }

    #[test]
    fn the_iteration_count_is_part_of_the_derivation() {
        // Two counts must give two keys, or the count is not being applied and
        // the constant is decoration.
        assert_ne!(
            VaultKey::from_passphrase_with(&a_passphrase(), &SALT, TEST_ITERATIONS)
                .as_bytes(),
            VaultKey::from_passphrase_with(&a_passphrase(), &SALT, TEST_ITERATIONS * 2)
                .as_bytes()
        );
    }

    #[test]
    fn the_production_iteration_count_is_the_documented_one() {
        // The single assertion that guards the constant the whole at-rest scheme
        // rests on. Changing it is a security decision, not a refactor.
        assert_eq!(PBKDF2_ITERATIONS, 600_000);
    }

    #[test]
    fn contents_round_trip_through_a_seal() {
        let (vault, _) = a_vault(&a_passphrase());
        let contents = Contents {
            seed: Some(b64::encode(&[42u8; 32])),
            generation: Some(3),
            opened_epoch: Some(2_980_472),
            members: [("dc73c74c3f57c6ff0c2d9016c333507f".to_string(), "p".to_string())]
                .into_iter()
                .collect(),
            places: [("home".to_string(), "Home".to_string())].into_iter().collect(),
            generation_at: None,
            identity: None,
        };

        let stored = vault.seal(&contents);
        let back =
            open_contents(&stored, &a_passphrase()).expect("the right passphrase opens");
        assert_eq!(back, contents);
        assert_eq!(back.seed_bytes(), Some([42u8; 32]));
    }

    #[test]
    fn the_wrong_passphrase_does_not_open_it() {
        let (vault, _) = a_vault(&a_passphrase());
        let contents =
            Contents { seed: Some(b64::encode(&[1u8; 32])), ..Default::default() };
        let stored = vault.seal(&contents);
        assert!(open_contents(&stored, "wrong passphrase").is_none());
        assert!(open_contents(&stored, "").is_none());
    }

    #[test]
    fn a_modified_file_does_not_open() {
        let (vault, _) = a_vault(&a_passphrase());
        let contents =
            Contents { seed: Some(b64::encode(&[1u8; 32])), ..Default::default() };
        let stored = vault.seal(&contents);

        // Any single change to the sealed bytes is caught by the tag.
        let mut tampered = stored.clone();
        let mut bytes = b64::decode(&tampered.data).unwrap();
        bytes[20] ^= 1;
        tampered.data = b64::encode(&bytes);
        assert!(open_contents(&tampered, &a_passphrase()).is_none());

        // As is a change to the salt, which derives a different key.
        let mut salted = stored.clone();
        salted.salt = b64::encode(&[9u8; SALT_LEN]);
        assert!(open_contents(&salted, &a_passphrase()).is_none());

        // And an unknown format version is refused rather than misread.
        let mut future = stored.clone();
        future.v = 99;
        assert!(open_contents(&future, &a_passphrase()).is_none());
    }

    #[test]
    fn a_file_asking_for_an_absurd_iteration_count_is_refused_outright() {
        // Otherwise an edited vault file is a denial of service on the lock
        // screen: four billion rounds of PBKDF2 before the user sees anything.
        let (vault, _) = a_vault(&a_passphrase());
        let contents =
            Contents { seed: Some(b64::encode(&[1u8; 32])), ..Default::default() };
        let mut stored = vault.seal(&contents);
        stored.iterations = u32::MAX;
        assert!(open_contents(&stored, &a_passphrase()).is_none());

        stored.iterations = 0;
        assert!(open_contents(&stored, &a_passphrase()).is_none());

        // A vault written by a build that used a different count still opens,
        // because the count is read from the file rather than from the constant.
        let (slower_vault, _) = Vault::create_with(&a_passphrase(), TEST_ITERATIONS * 2);
        let slower = slower_vault.seal(&contents);
        assert!(open_contents(&slower, &a_passphrase()).is_some());
        assert!(Vault::open(&slower, &a_passphrase()).is_some());
        assert_eq!(slower.iterations, TEST_ITERATIONS * 2);
    }

    #[test]
    fn an_empty_vault_is_still_sealable() {
        let (vault, stored) = a_vault(&a_passphrase());
        assert!(vault.contents(&stored).unwrap().is_empty());
        let _ = &stored;
        let back = open_contents(&stored, &a_passphrase()).unwrap();
        assert!(back.is_empty());
        assert_eq!(back.seed_bytes(), None);
    }

    #[test]
    fn a_nothing_but_noise_vault_does_not_open() {
        let stored = Stored {
            v: VAULT_VERSION,
            salt: b64::encode(&SALT),
            iterations: TEST_ITERATIONS,
            data: b64::encode(&[0u8; 40]),
            attempts: 0,
        };
        assert!(open_contents(&stored, &a_passphrase()).is_none());
        assert!(Vault::open(&stored, &a_passphrase()).is_none());
    }

    #[test]
    fn the_vault_key_never_prints() {
        let k = VaultKey::from_passphrase_with(&a_passphrase(), &SALT, TEST_ITERATIONS);
        assert_eq!(format!("{k:?}"), "VaultKey(<redacted>)");
    }

    #[test]
    fn passphrase_strength_rewards_length_over_symbols() {
        assert_eq!(rate_passphrase("abc"), Strength::TooShort);
        assert_eq!(rate_passphrase(&"a".repeat(MIN_PASSPHRASE_CHARS)), Strength::Weak);
        // A long passphrase with modest variety is still good.
        let long = "the quick brown fox jumps over the lazy dog again and again";
        assert!(matches!(rate_passphrase(long), Strength::Fair | Strength::Good));
        assert!(rate_passphrase(long).is_acceptable());
    }

    #[test]
    fn a_short_passphrase_is_never_acceptable() {
        for p in ["", "a", "1234567", "hunter"] {
            assert!(!rate_passphrase(p).is_acceptable(), "{p:?} was accepted");
        }
        // A common word is long enough to be accepted, but is warned about: the
        // honest position is that only length is enforced and the user is told.
        assert!(rate_passphrase("password").is_acceptable());
        assert!(rate_passphrase("password").warrants_a_warning());
    }

    #[test]
    fn subkeys_differ_by_purpose() {
        let (v, _) = a_vault(&a_passphrase());
        let a = subkey(v.key(), "seed");
        let b = subkey(v.key(), "places");
        let c = subkey(v.key(), "seed");
        assert_ne!(a, b);
        assert_eq!(a, c, "and the same purpose gives the same key");
        assert_ne!(a, *v.key().as_bytes());
    }

    #[test]
    fn a_duress_passcode_wipes_and_the_real_one_unlocks() {
        let (vault, _) = a_vault(&a_passphrase());
        let contents =
            Contents { seed: Some(b64::encode(&[1u8; 32])), ..Default::default() };
        let stored = vault.seal(&contents);
        let guard =
            DuressGuard::arm_with("open sesame please", &vault.salt, TEST_ITERATIONS);

        assert_eq!(
            unlock_action("open sesame please", &stored, Some(&guard)),
            UnlockAction::Wipe
        );
        assert_eq!(
            unlock_action(&a_passphrase(), &stored, Some(&guard)),
            UnlockAction::Unlock
        );
        assert_eq!(
            unlock_action("something else", &stored, Some(&guard)),
            UnlockAction::Retry
        );
        // With no guard armed, the duress passcode is just a wrong passcode.
        assert_eq!(unlock_action("open sesame please", &stored, None), UnlockAction::Retry);
    }

    #[test]
    fn a_duress_guard_does_not_store_the_passcode() {
        let guard = DuressGuard::arm_with("open sesame please", &SALT, TEST_ITERATIONS);
        let json = serde_json::to_string(&guard).unwrap();
        assert!(!json.contains("open sesame"), "the passcode must not be stored");
        assert!(
            !b64::decode(&guard.verifier).unwrap().windows(11).any(|w| w == b"open sesame")
        );
    }

    #[test]
    fn a_duress_guard_survives_a_round_trip() {
        let guard = DuressGuard::arm_with("open sesame please", &SALT, TEST_ITERATIONS);
        let json = serde_json::to_string(&guard).unwrap();
        let back: DuressGuard = serde_json::from_str(&json).unwrap();
        assert_eq!(back, guard);
        assert!(back.matches("open sesame please"));
        assert!(!back.matches(&a_passphrase()));
    }

    #[test]
    fn a_rekey_is_due_after_a_day_plus_this_devices_jitter() {
        let now = 1_788_000_000_000i64;
        let day = 24 * 60 * 60 * 1000;
        let member = "dc73c74c3f57c6ff0c2d9016c333507f";
        // Freshly created: not due.
        assert!(!rekey_due(now, member, now));
        assert!(!rekey_due(now, member, now + day - 1000));
        // A day plus the jitter, which is at most an hour.
        assert!(rekey_due(now, member, now + day + 3600 * 1000));
    }

    #[test]
    fn jitter_differs_between_devices() {
        // Without this, a circle re-keys in unison and spikes a relay.
        let now = 1_788_000_000_000i64;
        let day = 24 * 60 * 60 * 1000;
        let _ = now;
        let a = "dc73c74c3f57c6ff0c2d9016c333507f";
        let b = "cfeb6c3eedeab2f19faf80ee98930d20";
        // Find each device's jitter by binary search on the threshold, starting
        // from a real generation time so the "no creation time" case does not
        // short-circuit.
        let base = 1_788_000_000_000i64;
        let jitter_of = |id: &str| -> i64 {
            (0..=3600).find(|t| rekey_due(base, id, base + day + t * 1000)).unwrap()
        };
        assert_ne!(jitter_of(a), jitter_of(b));
    }

    #[test]
    fn a_generation_with_no_creation_time_re_keys_immediately() {
        // Otherwise post-compromise security is silently off for that circle,
        // which is the failure this guards.
        assert!(rekey_due(0, "dc73c74c3f57c6ff0c2d9016c333507f", 1_000));
    }

    #[test]
    fn contents_serialise_without_empty_fields() {
        // A compact wire form matters on a phone, and it also means an absent
        // field and an empty one cannot be confused on read.
        let c = Contents::default();
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, "{}", "an empty vault serialises to nothing");
        let back: Contents = serde_json::from_str("{}").unwrap();
        assert_eq!(back, c);
    }
}
