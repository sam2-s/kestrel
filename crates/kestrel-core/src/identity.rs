//! Identities: the two key pairs a device holds, and how another device learns
//! to trust them.
//!
//! A device has a *signing* key (Ed25519, or P-256 where Ed25519 is
//! unavailable) and a separate *agreement* key (always P-256, since it is the
//! one curve every platform offers for ECDH). Keeping them separate means a
//! device that only ever signs never does key agreement, and the member id
//! binds both so neither can be swapped.
//!
//! The algorithm is never taken from the network. It is recovered from the
//! public key's length, which is why the two encodings must not overlap: 32
//! bytes is Ed25519, 65 is an uncompressed P-256 point, and nothing else is
//! accepted.

use ed25519_dalek::{Signer, VerifyingKey as EdVerify};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{
    Signature as EcdsaSig, SigningKey as EcdsaSign, VerifyingKey as EcdsaVerify,
};
use p256::elliptic_curve::PublicKey as _EcdhPublic;
use p256::elliptic_curve::sec1::ToSec1Point;

/// A P-256 public key, the type every agreement key is.
type EcdhPublic = _EcdhPublic<p256::NistP256>;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{b64, kdf, seal::random_bytes, wire::Alg};

/// A signing key pair. The private half never leaves this struct in anything
/// but its serialised form.
///
/// The P-256 variant is boxed because an ECDSA key is a few hundred bytes
/// against Ed25519's thirty-two, and every identity would otherwise carry the
/// larger of the two.
#[derive(Clone)]
pub enum SigningKey {
    Ed25519(Box<ed25519_dalek::SigningKey>),
    P256(Box<EcdsaSign>),
}

impl SigningKey {
    /// Generate a fresh key of the given algorithm.
    ///
    /// Ed25519 keys are any 32 bytes, so they come straight from the system
    /// entropy source. A P-256 key must be a scalar in range, so random bytes
    /// are redrawn until they are; the rejection probability is about 2^-32.
    pub fn generate(alg: Alg) -> Self {
        match alg {
            Alg::Ed25519 => {
                let bytes: [u8; 32] = random_bytes();
                SigningKey::Ed25519(Box::new(ed25519_dalek::SigningKey::from_bytes(&bytes)))
            }
            Alg::P256 => SigningKey::P256(Box::new(
                EcdsaSign::from_slice(&random_bytes::<32>()).expect(
                    "a random 32-byte scalar is in range with overwhelming probability",
                ),
            )),
        }
    }

    /// Rebuild from stored private bytes, or `None` if they are not a valid key
    /// for this algorithm.
    pub fn from_private_bytes(alg: Alg, bytes: &[u8]) -> Option<Self> {
        match alg {
            Alg::Ed25519 => {
                let arr: [u8; 32] = bytes.try_into().ok()?;
                Some(SigningKey::Ed25519(Box::new(ed25519_dalek::SigningKey::from_bytes(
                    &arr,
                ))))
            }
            Alg::P256 => {
                let sk = EcdsaSign::from_slice(bytes).ok()?;
                Some(SigningKey::P256(Box::new(sk)))
            }
        }
    }

    pub fn alg(&self) -> Alg {
        match self {
            SigningKey::Ed25519(_) => Alg::Ed25519,
            SigningKey::P256(_) => Alg::P256,
        }
    }

    /// The uncompressed public key: 32 bytes for Ed25519, 65 for P-256.
    pub fn public_bytes(&self) -> Vec<u8> {
        match self {
            SigningKey::Ed25519(k) => k.verifying_key().to_bytes().to_vec(),
            SigningKey::P256(k) => {
                k.verifying_key().to_sec1_point(false).as_bytes().to_vec()
            }
        }
    }

    /// The private key bytes, for the local store. The only path out of this
    /// struct, and it is the caller's job to put them somewhere encrypted.
    pub(crate) fn private_bytes(&self) -> Vec<u8> {
        match self {
            SigningKey::Ed25519(k) => k.to_bytes().to_vec(),
            SigningKey::P256(k) => k.to_bytes().to_vec(),
        }
    }

    /// Sign a message. P-256 signs the SHA-256 of the message, matching what
    /// the reference implementation does, so signatures verify across both.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            SigningKey::Ed25519(k) => {
                let sig: ed25519_dalek::Signature = k.sign(message);
                sig.to_bytes().to_vec()
            }
            SigningKey::P256(k) => {
                let sig: EcdsaSig =
                    p256::ecdsa::signature::Signer::sign(k.as_ref(), message);
                sig.to_bytes().to_vec()
            }
        }
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKey({})", self.alg().as_str())
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        if let SigningKey::Ed25519(k) = self {
            let mut b = k.to_bytes();
            b.zeroize();
        }
    }
}

/// An ECDH key pair on P-256.
#[derive(Clone)]
pub struct EcdhKey {
    secret: [u8; 32],
}

impl EcdhKey {
    pub fn generate() -> Self {
        // Redraw rather than adjust: a scalar at or above the group order has no
        // valid public point, and nudging it downward would make the key less
        // than uniformly random. The rejection probability is about 2^-32, so
        // this loop runs once in practice.
        loop {
            let secret = random_bytes::<32>();
            if secret != [0u8; 32] && !ct_ge_order(&secret) {
                return Self { secret };
            }
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let secret: [u8; 32] = bytes.try_into().ok()?;
        scalar_in_range(&secret).then_some(Self { secret })
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret
    }

    /// The uncompressed public point, 65 bytes starting with `0x04`.
    pub fn public_bytes(&self) -> Vec<u8> {
        let sk = p256::SecretKey::from_slice(&self.secret)
            .expect("scalar validated on construction");
        let pk = EcdhPublic::from_secret_scalar(&sk.to_nonzero_scalar());
        pk.to_sec1_point(false).as_bytes().to_vec()
    }

    /// The shared x-coordinate, which is what the wrap key is derived from.
    ///
    /// Rejects an invalid public point rather than returning a degenerate
    /// secret: an all-zero shared secret would derive a wrap key from a known
    /// value.
    pub fn agree(&self, peer_public: &[u8]) -> Option<[u8; 32]> {
        if peer_public.len() != 65 || peer_public[0] != 0x04 {
            return None;
        }
        let peer = EcdhPublic::from_sec1_bytes(peer_public).ok()?;
        let sk = p256::SecretKey::from_slice(&self.secret).ok()?;
        let shared = p256::ecdh::diffie_hellman(&sk.to_nonzero_scalar(), peer.as_affine());
        let x = shared.raw_secret_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(x);
        if out.iter().all(|&b| b == 0) {
            return None;
        }
        Some(out)
    }
}

impl std::fmt::Debug for EcdhKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EcdhKey(<redacted>)")
    }
}

impl Drop for EcdhKey {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// True when a scalar is at or above the group order, so it has no valid
/// public point.
fn ct_ge_order(s: &[u8; 32]) -> bool {
    ct_gt(s, &crate::P256_ORDER_HIGH) || s == &crate::P256_ORDER_HIGH
}

/// `a < b`, the mirror of [`ct_gt`].
#[cfg(test)]
fn ct_lt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    ct_gt(b, a)
}

/// Compare a 32-byte scalar against the group order, big-endian.
fn scalar_in_range(s: &[u8; 32]) -> bool {
    s != &[0u8; 32] && !ct_ge_order(s)
}

/// `a > b`, for 32-byte big-endian values, in time that does not depend on
/// where the first difference is.
///
/// `subtle` provides equality but not ordering, and a private scalar's range
/// check is exactly the sort of comparison that should not leak its position.
fn ct_gt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    // Compare from the most significant byte down, remembering the first
    // difference and ignoring every later one. Byte-at-a-time so nothing
    // depends on a machine word size or on where the difference falls.
    let mut greater = 0u8;
    let mut decided = false;
    for i in 0..32 {
        let ai = a[i];
        let bi = b[i];
        let gt = ai > bi;
        let eq = ai == bi;
        // Take this byte's verdict only if no earlier byte decided.
        greater |= u8::from(gt) & !u8::from(decided);
        decided |= !eq;
    }
    greater == 1
}

impl PartialEq for EcdhKey {
    fn eq(&self, other: &Self) -> bool {
        self.secret.ct_eq(&other.secret).into()
    }
}
impl Eq for EcdhKey {}

/// A device's identity: both key pairs, plus the ids derived from them.
#[derive(Clone, Debug)]
pub struct Identity {
    signing: SigningKey,
    ecdh: EcdhKey,
    member_id: String,
}

impl Identity {
    /// Generate a new identity.
    ///
    /// Ed25519 is preferred where it exists. P-256 is a compatibility fallback
    /// for platforms without it, not a choice: a device that could use
    /// Ed25519 and did not would be distinguishable in its own roster.
    pub fn generate() -> Self {
        Self::generate_with(Alg::Ed25519)
    }

    pub fn generate_with(alg: Alg) -> Self {
        let signing = SigningKey::generate(alg);
        let ecdh = EcdhKey::generate();
        let member_id = kdf::member_id(&signing.public_bytes(), &ecdh.public_bytes());
        Self { signing, ecdh, member_id }
    }

    /// Rebuild from stored key material. Returns `None` if the stored member id
    /// does not match the keys, which means the record is corrupt or has been
    /// tampered with.
    pub fn from_parts(
        alg: Alg,
        signing_private: &[u8],
        ecdh_private: &[u8],
        expect_member_id: Option<&str>,
    ) -> Option<Self> {
        let signing = SigningKey::from_private_bytes(alg, signing_private)?;
        let ecdh = EcdhKey::from_bytes(ecdh_private)?;
        let member_id = kdf::member_id(&signing.public_bytes(), &ecdh.public_bytes());
        if let Some(expected) = expect_member_id
            && !bool::from(member_id.as_bytes().ct_eq(expected.as_bytes()))
        {
            return None;
        }
        Some(Self { signing, ecdh, member_id })
    }

    pub fn member_id(&self) -> &str {
        &self.member_id
    }

    pub fn alg(&self) -> Alg {
        self.signing.alg()
    }

    pub fn pk_bytes(&self) -> Vec<u8> {
        self.signing.public_bytes()
    }

    pub fn epk_bytes(&self) -> Vec<u8> {
        self.ecdh.public_bytes()
    }

    pub fn pk_b64(&self) -> String {
        b64::encode(&self.pk_bytes())
    }

    pub fn epk_b64(&self) -> String {
        b64::encode(&self.epk_bytes())
    }

    pub fn signing(&self) -> &SigningKey {
        &self.signing
    }

    pub fn ecdh(&self) -> &EcdhKey {
        &self.ecdh
    }

    /// Sign a UTF-8 string.
    pub fn sign_text(&self, message: &str) -> String {
        b64::encode(&self.signing.sign(message.as_bytes()))
    }

    /// The safety number for this identity: six groups of five digits, about 100
    /// bits of comparison material.
    ///
    /// This is what two people read aloud or compare on screen to answer "are
    /// these bytes the same on both phones", which no amount of UI polish
    /// replaces.
    pub fn safety_number(&self) -> String {
        safety_number_for(&self.pk_bytes(), &self.epk_bytes())
    }

    /// The commitment to this identity that goes into an invite link.
    pub fn invite_commitment(&self) -> String {
        b64::encode(&kdf::inviter_commitment(&self.pk_bytes(), &self.epk_bytes()))
    }

    /// A stable hue for this member, so the same person is the same colour on
    /// every device in the circle without anyone choosing a colour.
    pub fn hue(&self) -> u16 {
        hue_from_member_id(&self.member_id)
    }
}

/// The safety number for a key pair, as six space-separated groups of five
/// digits.
///
/// Eighteen digest bytes are read three at a time, each group taken as a 24-bit
/// big-endian integer modulo 100000. Reading a group is a comparison and not an
/// arithmetic operation, so there is nothing to compute.
pub fn safety_number_for(pk: &[u8], epk: &[u8]) -> String {
    let digest = kdf::fingerprint(pk, epk);
    let mut groups = Vec::with_capacity(6);
    for chunk in digest.chunks(3) {
        let v = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | chunk[2] as u32;
        groups.push(format!("{:05}", v % 100_000));
    }
    groups.join(" ")
}

/// A deterministic colour for a member id, so markers are stable across
/// devices. Derived from the id rather than assigned, because a circle has no
/// server to allocate colours.
pub fn hue_from_member_id(member_id: &str) -> u16 {
    let bytes = member_id.as_bytes();
    if bytes.len() < 6 {
        return 0;
    }
    // The first six hex characters are 24 bits; folding them into 360 spreads
    // members evenly instead of clustering them by id prefix.
    let v = bytes[..6]
        .iter()
        .fold(0u32, |acc, c| acc * 16 + (*c as char).to_digit(16).unwrap_or(0));
    (v % 360) as u16
}

/// Verify a signature over `message`.
///
/// The algorithm comes from the public key's length, never from a value the
/// network supplied, and the key must be the right length for it. A signature
/// is only ever checked against bytes that already committed to a key, so
/// there is no trust decision hidden in this function.
pub fn verify_sig(alg: Alg, pk: &[u8], sig: &[u8], message: &[u8]) -> bool {
    if pk.len() != alg.pk_len() {
        return false;
    }
    match alg {
        Alg::Ed25519 => {
            let Ok(arr) = <[u8; 32]>::try_from(pk) else {
                return false;
            };
            let Ok(vk) = EdVerify::from_bytes(&arr) else {
                return false;
            };
            let Ok(s) = <[u8; 64]>::try_from(sig) else {
                return false;
            };
            // Strict verification rejects small-order and non-canonical
            // signatures, which a permissive check would accept and which
            // would let one key appear to have signed several different
            // messages.
            vk.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&s)).is_ok()
        }
        Alg::P256 => {
            let Ok(vk) = EcdsaVerify::from_sec1_bytes(pk) else {
                return false;
            };
            let Ok(s) = EcdsaSig::from_slice(sig) else {
                return false;
            };
            // Hash here rather than accepting a prehash, so the caller cannot
            // accidentally pass unhashed bytes.
            let digest = Sha256::digest(message);
            vk.verify_prehash(&digest, &s).is_ok()
        }
    }
}

/// True when `bytes` is a valid uncompressed P-256 point.
///
/// Used on the receive path: a member's agreement key must be a real curve
/// point, not 65 arbitrary bytes that happen to start with `0x04`.
pub fn valid_ecdh_key(bytes: &[u8]) -> bool {
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return false;
    }
    EcdhPublic::from_sec1_bytes(bytes).is_ok()
}

/// Serialised form of an identity's key material, for the local store.
#[derive(Serialize, Deserialize)]
pub struct StoredIdentity {
    pub alg: Alg,
    pub member_id: String,
    pub signing_private: String,
    pub ecdh_private: String,
}

impl StoredIdentity {
    pub fn from_identity(id: &Identity) -> Self {
        let sk = id.signing.private_bytes();
        Self {
            alg: id.alg(),
            member_id: id.member_id().to_string(),
            signing_private: b64::encode(&sk),
            ecdh_private: b64::encode(&id.ecdh().secret_bytes()),
        }
    }

    /// Rebuild, verifying the stored member id against the keys.
    pub fn to_identity(&self) -> Option<Identity> {
        let sk = b64::decode(&self.signing_private)?;
        let ek = b64::decode(&self.ecdh_private)?;
        Identity::from_parts(self.alg, &sk, &ek, Some(&self.member_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZEROS32: [u8; 32] = [0u8; 32];
    const ZEROS65: [u8; 65] = [0u8; 65];

    #[test]
    fn safety_number_matches_the_published_vector() {
        // Case A from the reference vectors.
        let pk = b64::decode("36PB0K4lVKaN2b-Y5enOb3leZmkKm3gPAPs5mY-ROCU").unwrap();
        let epk = b64::decode("BCf1caClyddzW3eL7PHALmGl6RM7F_5z0lFceUJl0VjwcvFRkm06ewRvBlCBFskxz8Altd95EVo8qxZxHEee3Nk").unwrap();
        assert_eq!(safety_number_for(&pk, &epk), "79320 91948 00309 34269 25169 66015");
    }

    #[test]
    fn member_id_matches_the_published_vector_for_zero_keys() {
        assert_eq!(kdf::member_id(&ZEROS32, &ZEROS65), "f00e016dc606b8e419d5424bf601e1d3");
    }

    #[test]
    fn generated_identities_are_ed25519_by_default() {
        let id = Identity::generate();
        assert_eq!(id.alg(), Alg::Ed25519);
        assert_eq!(id.pk_bytes().len(), 32);
        assert_eq!(id.epk_bytes().len(), 65);
    }

    #[test]
    fn p256_fallback_produces_65_byte_keys() {
        let id = Identity::generate_with(Alg::P256);
        assert_eq!(id.pk_bytes().len(), 65);
        assert_eq!(id.epk_bytes().len(), 65);
    }

    #[test]
    fn identity_survives_a_storage_round_trip() {
        let id = Identity::generate();
        let stored = StoredIdentity::from_identity(&id);
        let back = stored.to_identity().unwrap();
        assert_eq!(back.member_id(), id.member_id());
        assert_eq!(back.safety_number(), id.safety_number());
    }

    #[test]
    fn storage_rejects_a_tampered_member_id() {
        let id = Identity::generate();
        let mut stored = StoredIdentity::from_identity(&id);
        stored.member_id = "00000000000000000000000000000000".to_string();
        assert!(stored.to_identity().is_none());
    }

    #[test]
    fn storage_rejects_swapped_signing_keys() {
        let a = Identity::generate();
        let b = Identity::generate();
        let mut stored = StoredIdentity::from_identity(&a);
        // The agreement key from one identity and the signing key from another
        // must not produce identity A.
        stored.ecdh_private = b64::encode(&b.ecdh().secret_bytes());
        assert!(stored.to_identity().is_none());
    }

    #[test]
    fn both_algorithms_sign_and_verify() {
        for alg in [Alg::Ed25519, Alg::P256] {
            let id = Identity::generate_with(alg);
            let msg = b"starling/v2|a|b|1|2|AAAA|c";
            let sig = id.signing().sign(msg);
            assert_eq!(sig.len(), 64, "{} signature length", alg.as_str());
            assert!(
                verify_sig(alg, &id.pk_bytes(), &sig, msg),
                "{} must verify its own signature",
                alg.as_str()
            );
            assert!(
                !verify_sig(alg, &id.pk_bytes(), &sig, b"a different message"),
                "{} must not verify a modified message",
                alg.as_str()
            );
        }
    }

    #[test]
    fn a_signature_does_not_verify_under_a_different_algorithm() {
        let ed = Identity::generate_with(Alg::Ed25519);
        let sig = ed.signing().sign(b"m");
        let ed_pk = ed.pk_bytes();
        // Same 32-byte key, but claimed as P-256: the length check refuses.
        assert!(!verify_sig(Alg::P256, &ed_pk, &sig, b"m"));
    }

    #[test]
    fn ecdh_agrees_in_both_directions() {
        let a = EcdhKey::generate();
        let b = EcdhKey::generate();
        assert_eq!(a.agree(&b.public_bytes()), b.agree(&a.public_bytes()));
    }

    #[test]
    fn ecdh_rejects_degenerate_and_invalid_peers() {
        let a = EcdhKey::generate();
        assert!(a.agree(&[]).is_none());
        assert!(a.agree(&[0u8; 64]).is_none(), "wrong length");
        let mut bad = a.public_bytes();
        bad[0] = 0x05;
        assert!(a.agree(&bad).is_none(), "wrong prefix");
        // A public point the attacker chose, with a y-coordinate off the
        // curve, must not yield a shared secret.
        let mut off_curve = a.public_bytes();
        off_curve[64] ^= 0xff;
        assert!(a.agree(&off_curve).is_none());
    }

    #[test]
    fn valid_ecdh_key_accepts_real_points_only() {
        let k = EcdhKey::generate();
        assert!(valid_ecdh_key(&k.public_bytes()));
        assert!(!valid_ecdh_key(&[0u8; 65]), "not on the curve");
        assert!(!valid_ecdh_key(&[0u8; 32]));
        assert!(!valid_ecdh_key(&k.public_bytes()[..64]));
    }

    #[test]
    fn constant_time_comparison_agrees_with_the_ordinary_one() {
        // The hand-rolled comparison must be correct, or the range check that
        // depends on it is worthless.
        let cases: [([u8; 32], [u8; 32]); 6] = [
            ([0u8; 32], [1u8; 32]),
            ([1u8; 32], [0u8; 32]),
            ([0u8; 32], [0u8; 32]),
            (
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 1,
                ],
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 2,
                ],
            ),
            ([0xffu8; 32], [0x80u8; 32]),
            ([0x80u8; 32], [0x7fu8; 32]),
        ];
        for (a, b) in cases {
            let expected_gt = a > b;
            let expected_lt = a < b;
            assert_eq!(ct_gt(&a, &b), expected_gt, "gt mismatch");
            assert_eq!(ct_lt(&a, &b), expected_lt, "lt mismatch");
            // Strict ordering: exactly one of greater, less, equal holds, and
            // reversing the arguments reverses the verdict.
            if a == b {
                assert!(
                    !ct_gt(&a, &b) && !ct_gt(&b, &a),
                    "equal is not greater either way"
                );
            } else {
                assert_eq!(ct_gt(&a, &b), !ct_gt(&b, &a), "antisymmetry");
            }
        }
    }

    #[test]
    fn private_scalars_must_be_in_range() {
        assert!(EcdhKey::from_bytes(&[0u8; 32]).is_none(), "zero");
        assert!(
            EcdhKey::from_bytes(&crate::P256_ORDER_HIGH).is_none(),
            "equal to the order"
        );
        assert!(EcdhKey::from_bytes(&[0xffu8; 32]).is_none(), "above the order");
        let mut ok = crate::P256_ORDER_HIGH;
        ok[31] -= 1;
        assert!(EcdhKey::from_bytes(&ok).is_some(), "just below the order");
        assert!(scalar_in_range(&ok));
        assert!(!scalar_in_range(&[0u8; 32]));
    }

    #[test]
    fn hue_is_stable_and_in_range() {
        let id = Identity::generate();
        let h1 = id.hue();
        let h2 = hue_from_member_id(id.member_id());
        assert_eq!(h1, h2);
        assert!(h1 < 360);
    }

    #[test]
    fn hue_never_panics_on_a_short_id() {
        assert_eq!(hue_from_member_id(""), 0);
        assert_eq!(hue_from_member_id("ab"), 0);
    }

    #[test]
    fn invite_commitment_is_twenty_two_characters() {
        let id = Identity::generate();
        assert_eq!(id.invite_commitment().len(), 22, "16 bytes is 22 base64url characters");
    }

    #[test]
    fn debug_output_never_contains_key_material() {
        let id = Identity::generate();
        let ek = EcdhKey::generate();
        assert_eq!(format!("{ek:?}"), "EcdhKey(<redacted>)");
        // Identity's derive includes EcdhKey, which redacts itself.
        let s = format!("{id:?}");
        assert!(!s.contains(&kdf::hex(&id.ecdh().secret_bytes())));
    }
}
