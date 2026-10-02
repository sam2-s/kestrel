//! The roster: which members a device trusts, and the rules for admitting one.
//!
//! A device learns a stranger's public keys from the relay and then decides for
//! itself whether to believe them. That decision is the only trust anchor in the
//! protocol, and it is made in exactly one place so every path — a feed, a join
//! request, a welcome record — goes through the same checks.
//!
//! The checks, in order:
//!
//! 1. both keys decode;
//! 2. the agreement key is a real P-256 curve point, not 65 bytes that merely
//!    start with `0x04`;
//! 3. the algorithm is recovered from the signing key's length, never read off
//!    the wire;
//! 4. the member id is recomputed from both keys and must equal the claimed id;
//! 5. the roster has room.
//!
//! Step 4 is the one that makes pinning mean something. An id commits to both
//! public keys, so a device that admits id X has admitted one specific keypair
//! and cannot be shown a different one later.

use std::collections::BTreeMap;

use crate::{
    identity::valid_ecdh_key,
    kdf,
    wire::{Alg, MEMBER_CAP, TTL_MS},
};

/// What a device knows about one member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub member_id: String,
    pub alg: Alg,
    /// Signing public key, in its one canonical spelling.
    pub pk: String,
    /// Agreement public key, canonical spelling.
    pub epk: String,
    /// Whether the member was confirmed in person by comparing safety numbers.
    pub verified: bool,
    /// Display name, as last advertised.
    pub name: String,
    /// The member's colour, derived from their id.
    pub hue: u16,
    /// When this member was last admitted, for pruning.
    pub admitted_at: i64,
}

impl Member {
    /// Whether a post claiming to be from this member presents the keys the
    /// roster pinned.
    ///
    /// Compares decoded bytes rather than text: base64url's final character
    /// carries two bits no byte uses, so one key has four valid spellings and a
    /// text comparison would report a false key change.
    pub fn matches_keys(&self, pk: &str, epk: &str) -> bool {
        same_key(&self.pk, pk) && same_key(&self.epk, epk)
    }

    pub fn safety_number(&self) -> String {
        match (crate::b64::decode(&self.pk), crate::b64::decode(&self.epk)) {
            (Some(pk), Some(epk)) => crate::identity::safety_number_for(&pk, &epk),
            _ => String::new(),
        }
    }
}

/// Whether two base64url spellings denote the same bytes.
pub fn same_key(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    match (crate::b64::decode(a), crate::b64::decode(b)) {
        (Some(x), Some(y)) => x.ct_eq(&y).into(),
        _ => false,
    }
}

/// Why a member was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitError {
    /// A key field was not decodable base64url.
    Undecodable,
    /// The agreement key is not a point on the curve.
    BadAgreementKey,
    /// The signing key length does not correspond to any algorithm.
    BadSigningKey,
    /// The keys do not hash to the claimed member id.
    IdMismatch,
    /// The roster is full.
    Full,
    /// The id is not 32 lowercase hex characters.
    MalformedId,
}

/// The set of members a device trusts for one circle.
#[derive(Debug, Clone, Default)]
pub struct Roster {
    members: BTreeMap<String, Member>,
}

impl Roster {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub fn get(&self, member_id: &str) -> Option<&Member> {
        self.members.get(member_id)
    }

    pub fn contains(&self, member_id: &str) -> bool {
        self.members.contains_key(member_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Member> {
        self.members.values()
    }

    pub fn ids(&self) -> Vec<String> {
        self.members.keys().cloned().collect()
    }

    /// The member ids a re-key expects to see afterwards: everyone currently
    /// held except the person doing the re-key, plus the sender.
    ///
    /// A device does not pin its own identity (it knows it already), so it adds
    /// itself back. The rotator is excluded because a device is not asked to
    /// re-wrap to itself, so the roster it converges on is the one that excludes
    /// the rotator.
    pub fn roster_view(&self, self_id: &str, rotator: &str) -> Vec<String> {
        let mut ids: Vec<String> =
            self.members.keys().filter(|id| *id != rotator).cloned().collect();
        if !ids.iter().any(|id| id == self_id) {
            ids.push(self_id.to_string());
        }
        ids
    }

    /// The roster hash a re-key from this device would expect.
    pub fn roster_hash(&self, self_id: &str, rotator: &str) -> String {
        kdf::roster_hash(&self.roster_view(self_id, rotator))
    }

    /// Admit a member, or explain why not.
    ///
    /// A member already present is never re-pinned: the existing record is
    /// authoritative, so a later post cannot change the keys behind an id that
    /// has already been trusted.
    pub fn admit(
        &mut self,
        member_id: &str,
        pk: &str,
        epk: &str,
        now: i64,
        cap: usize,
    ) -> Result<bool, AdmitError> {
        if !kdf::is_member_id(member_id) {
            return Err(AdmitError::MalformedId);
        }

        let pk_bytes = crate::b64::decode(pk).ok_or(AdmitError::Undecodable)?;
        let epk_bytes = crate::b64::decode(epk).ok_or(AdmitError::Undecodable)?;

        if !valid_ecdh_key(&epk_bytes) {
            return Err(AdmitError::BadAgreementKey);
        }
        let alg = Alg::from_pk(&pk_bytes).ok_or(AdmitError::BadSigningKey)?;
        if kdf::member_id(&pk_bytes, &epk_bytes) != member_id {
            return Err(AdmitError::IdMismatch);
        }

        if self.members.contains_key(member_id) {
            return Ok(false);
        }
        if self.members.len() >= cap {
            return Err(AdmitError::Full);
        }

        let member = Member {
            member_id: member_id.to_string(),
            alg,
            // Store one spelling, so two records holding the same key compare
            // equal as text as well as as bytes.
            pk: crate::b64::encode(&pk_bytes),
            epk: crate::b64::encode(&epk_bytes),
            verified: false,
            name: String::new(),
            hue: crate::identity::hue_from_member_id(member_id),
            admitted_at: now,
        };
        self.members.insert(member_id.to_string(), member);
        Ok(true)
    }

    /// Mark a member as confirmed in person.
    pub fn mark_verified(&mut self, member_id: &str) {
        if let Some(m) = self.members.get_mut(member_id) {
            m.verified = true;
        }
    }

    /// Update a member's advertised name.
    pub fn set_name(&mut self, member_id: &str, name: &str) {
        if let Some(m) = self.members.get_mut(member_id) {
            m.name = name.chars().take(crate::msg::MAX_NAME).collect();
        }
    }

    /// Remove a member, returning whether they were held.
    pub fn remove(&mut self, member_id: &str) -> bool {
        self.members.remove(member_id).is_some()
    }

    /// A member whose last word is older than the retention window has gone
    /// quiet; drop them so the roster does not fill with devices that left.
    pub fn prune(&mut self, now: i64) {
        self.members.retain(|_, m| now.saturating_sub(m.admitted_at) <= TTL_MS);
    }
}

/// What a receiver concluded about a post's sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyVerdict {
    /// First time seen; admitted now.
    Admitted,
    /// Already known, same keys.
    Known,
    /// Known, but the keys differ. A device cannot present a different keypair
    /// under an id, so this means either a relay rewriting a field or a
    /// compromised device. The point is dropped and the user is told.
    Changed,
}

/// Compare a presented keypair against the roster and say which it is.
pub fn key_change_verdict(
    roster: &Roster,
    member_id: &str,
    pk: &str,
    epk: &str,
) -> KeyVerdict {
    match roster.get(member_id) {
        Some(m) if m.matches_keys(pk, epk) => KeyVerdict::Known,
        Some(_) => KeyVerdict::Changed,
        None => KeyVerdict::Admitted,
    }
}

/// How many *other* members a device will hold.
///
/// One less than the relay's cap, because this device occupies a relay row of
/// its own. Getting this wrong means a device fills its roster and then cannot
/// accept anyone, or leaves a slot the relay will refuse.
pub const LOCAL_CAP: usize = MEMBER_CAP - 1;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    /// The base64url alphabet, for enumerating the spellings of one key.
    use crate::b64::decode;

    const ALPHABET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    fn admit(roster: &mut Roster, id: &Identity) -> Result<bool, AdmitError> {
        roster.admit(id.member_id(), &id.pk_b64(), &id.epk_b64(), 1_000_000, LOCAL_CAP)
    }

    #[test]
    fn a_valid_member_is_admitted() {
        let mut r = Roster::new();
        let id = Identity::generate();
        assert_eq!(admit(&mut r, &id), Ok(true));
        assert!(r.contains(id.member_id()));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn admitting_twice_is_a_no_op_not_an_error() {
        let mut r = Roster::new();
        let id = Identity::generate();
        assert_eq!(admit(&mut r, &id), Ok(true));
        assert_eq!(admit(&mut r, &id), Ok(false));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn a_mismatched_member_id_is_refused() {
        let mut r = Roster::new();
        let id = Identity::generate();
        let other = Identity::generate();
        // The right id, the wrong keys.
        assert_eq!(
            r.admit(id.member_id(), &other.pk_b64(), &other.epk_b64(), 0, LOCAL_CAP),
            Err(AdmitError::IdMismatch)
        );
        assert!(r.is_empty());
    }

    #[test]
    fn a_swapped_agreement_key_is_refused() {
        let mut r = Roster::new();
        let a = Identity::generate();
        let b = Identity::generate();
        assert_eq!(
            r.admit(a.member_id(), &a.pk_b64(), &b.epk_b64(), 0, LOCAL_CAP),
            Err(AdmitError::IdMismatch)
        );
    }

    #[test]
    fn a_non_point_agreement_key_is_refused() {
        let mut r = Roster::new();
        let a = Identity::generate();
        let b = Identity::generate();
        // 65 bytes that decode but are not on the curve.
        assert_eq!(
            r.admit(
                b.member_id(),
                &b.pk_b64(),
                &crate::b64::encode(&[0u8; 65]),
                0,
                LOCAL_CAP
            ),
            Err(AdmitError::BadAgreementKey)
        );
        assert!(r.is_empty());
        let _ = a;
    }

    #[test]
    fn an_undecodable_key_is_refused() {
        let mut r = Roster::new();
        let id = Identity::generate();
        assert_eq!(
            r.admit(id.member_id(), "not base64!", &id.epk_b64(), 0, LOCAL_CAP),
            Err(AdmitError::Undecodable)
        );
    }

    #[test]
    fn an_unrecognised_signing_key_length_is_refused() {
        let mut r = Roster::new();
        let id = Identity::generate();
        assert_eq!(
            r.admit(
                id.member_id(),
                &crate::b64::encode(&[0u8; 33]),
                &id.epk_b64(),
                0,
                LOCAL_CAP
            ),
            Err(AdmitError::BadSigningKey)
        );
    }

    #[test]
    fn a_malformed_member_id_is_refused() {
        let mut r = Roster::new();
        let id = Identity::generate();
        assert_eq!(
            r.admit("short", &id.pk_b64(), &id.epk_b64(), 0, LOCAL_CAP),
            Err(AdmitError::MalformedId)
        );
    }

    #[test]
    fn the_roster_refuses_to_grow_past_the_local_cap() {
        let mut r = Roster::new();
        for _ in 0..LOCAL_CAP {
            let id = Identity::generate();
            admit(&mut r, &id).unwrap();
        }
        assert_eq!(r.len(), LOCAL_CAP);
        let extra = Identity::generate();
        assert_eq!(admit(&mut r, &extra), Err(AdmitError::Full));
    }

    #[test]
    fn the_local_cap_leaves_room_for_this_device_on_the_relay() {
        assert_eq!(LOCAL_CAP, MEMBER_CAP - 1);
    }

    #[test]
    fn keys_are_compared_as_bytes_not_as_text() {
        let id = Identity::generate();
        // A 32-byte key encodes to 43 characters, and the last character carries
        // only four significant bits, so it has four valid spellings. The
        // variants differ in the two *high* bits, which no byte uses.
        let canonical = id.pk_b64();
        assert_eq!(canonical.len(), 43);
        let mut seen = std::collections::HashSet::new();
        seen.insert(canonical.clone());
        for &tail in ALPHABET {
            let mut alt = canonical[..42].to_string();
            alt.push(tail as char);
            let decoded = decode(&alt).expect("every alphabet character decodes");
            if decoded.len() == 32 && decoded == decode(&canonical).unwrap() {
                seen.insert(alt);
            }
        }
        assert_eq!(seen.len(), 4, "exactly four spellings of one 32-byte key");
        for alt in &seen {
            assert!(same_key(&canonical, alt));
        }
    }

    #[test]
    fn a_member_matches_only_its_own_keys() {
        let a = Identity::generate();
        let b = Identity::generate();
        let mut r = Roster::new();
        admit(&mut r, &a).unwrap();
        let m = r.get(a.member_id()).unwrap();
        assert!(m.matches_keys(&a.pk_b64(), &a.epk_b64()));
        assert!(!m.matches_keys(&b.pk_b64(), &a.epk_b64()));
        assert!(!m.matches_keys(&a.pk_b64(), &b.epk_b64()));
    }

    #[test]
    fn the_verdict_distinguishes_new_known_and_changed() {
        let a = Identity::generate();
        let b = Identity::generate();
        let mut r = Roster::new();
        assert_eq!(
            key_change_verdict(&r, a.member_id(), &a.pk_b64(), &a.epk_b64()),
            KeyVerdict::Admitted
        );
        admit(&mut r, &a).unwrap();
        assert_eq!(
            key_change_verdict(&r, a.member_id(), &a.pk_b64(), &a.epk_b64()),
            KeyVerdict::Known
        );
        assert_eq!(
            key_change_verdict(&r, a.member_id(), &b.pk_b64(), &a.epk_b64()),
            KeyVerdict::Changed
        );
    }

    #[test]
    fn the_roster_view_excludes_the_rotator_and_includes_self() {
        let mut r = Roster::new();
        let me = Identity::generate();
        let a = Identity::generate();
        let b = Identity::generate();
        for id in [&me, &a, &b] {
            admit(&mut r, id).unwrap();
        }
        // Everyone except the rotator, plus me.
        let view = r.roster_view(me.member_id(), a.member_id());
        assert_eq!(view.len(), 2);
        assert!(view.contains(&me.member_id().to_string()));
        assert!(view.contains(&b.member_id().to_string()));
        assert!(!view.contains(&a.member_id().to_string()));
    }

    #[test]
    fn the_roster_view_does_not_duplicate_self() {
        let mut r = Roster::new();
        let me = Identity::generate();
        let a = Identity::generate();
        for id in [&me, &a] {
            admit(&mut r, id).unwrap();
        }
        let view = r.roster_view(me.member_id(), a.member_id());
        assert_eq!(view.len(), 1);
        assert_eq!(view, vec![me.member_id().to_string()]);
    }

    #[test]
    fn the_roster_hash_is_order_independent() {
        let mut r = Roster::new();
        let me = Identity::generate();
        let a = Identity::generate();
        let b = Identity::generate();
        for id in [&me, &a, &b] {
            admit(&mut r, id).unwrap();
        }
        let h1 = r.roster_hash(me.member_id(), a.member_id());
        let h2 = r.roster_hash(me.member_id(), a.member_id());
        assert_eq!(h1, h2);
    }

    #[test]
    fn verification_and_naming_are_recorded() {
        let mut r = Roster::new();
        let id = Identity::generate();
        admit(&mut r, &id).unwrap();
        assert!(!r.get(id.member_id()).unwrap().verified);
        r.mark_verified(id.member_id());
        assert!(r.get(id.member_id()).unwrap().verified);
        r.set_name(id.member_id(), "Ana");
        assert_eq!(r.get(id.member_id()).unwrap().name, "Ana");
        // Names are clamped.
        r.set_name(id.member_id(), &"n".repeat(100));
        assert_eq!(
            r.get(id.member_id()).unwrap().name.chars().count(),
            crate::msg::MAX_NAME
        );
    }

    #[test]
    fn a_member_can_be_removed() {
        let mut r = Roster::new();
        let id = Identity::generate();
        admit(&mut r, &id).unwrap();
        assert!(r.remove(id.member_id()));
        assert!(!r.remove(id.member_id()));
        assert!(r.is_empty());
    }

    #[test]
    fn quiet_members_are_pruned_after_the_retention_window() {
        let mut r = Roster::new();
        let id = Identity::generate();
        r.admit(id.member_id(), &id.pk_b64(), &id.epk_b64(), 0, LOCAL_CAP).unwrap();
        r.prune(TTL_MS);
        assert_eq!(r.len(), 1, "still inside the window");
        r.prune(TTL_MS + 1);
        assert_eq!(r.len(), 0, "past the window");
    }

    #[test]
    fn a_member_safety_number_is_available_for_comparison() {
        let mut r = Roster::new();
        let id = Identity::generate();
        admit(&mut r, &id).unwrap();
        assert_eq!(r.get(id.member_id()).unwrap().safety_number(), id.safety_number());
    }
}
