//! Key wraps: how a fresh generation seed reaches one member and nobody else.
//!
//! A wrap is an ephemeral ECDH exchange followed by an AES-256-GCM seal. The
//! ephemeral key is fresh per wrap, so the shared secret is unique, and the
//! receiver's public key comes from the roster rather than from the message, so
//! a wrap cannot be redirected.
//!
//! The part that matters most is the *context* string bound into the associated
//! data. It names the rotator, the generation, the opening epoch, the mix epoch,
//! the expected roster hash and the removal list. Without it, any member could
//! take another's wrap and present it with a different removal list, framing an
//! innocent member for removal or hiding one. The context is rebuilt from the
//! message's own fields on receipt, so a sender cannot put one value in the
//! associated data and another in the message.

use zeroize::Zeroize;

use crate::{
    identity::{EcdhKey, Identity},
    kdf,
    msg::CircleMsg,
    seal::{open, random_bytes, seal},
    wire::wrap_aad,
};

/// Length of the fresh entropy mixed into a new generation's seed.
pub const FRESH_ENTROPY_LEN: usize = 32;

/// Length of the wrapped plaintext: a generation seed.
pub const WRAPPED_SEED_LEN: usize = 32;

/// A wrap ready to be posted: the ephemeral public key and the sealed blob.
pub struct Wrap {
    /// The ephemeral agreement public key, 65 bytes, base64url.
    pub eph: String,
    /// `nonce || ciphertext`, base64url.
    pub w: String,
}

/// The fields that make up a re-key's context string.
///
/// Every one of these is bound into the associated data, so changing any of them
/// invalidates the wrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekeyContext {
    /// The member performing the re-key.
    pub by: String,
    /// The new generation number.
    pub g: i64,
    /// The epoch the new generation opens in.
    pub e0: i64,
    /// The epoch the next seed was mixed at.
    pub me: i64,
    /// The roster hash the sender expects after the re-key.
    pub rh: String,
    /// Members being removed, which the receiver sorts before comparing.
    pub rm: Vec<String>,
}

impl RekeyContext {
    /// The exact string bound into the associated data: six `|`-separated
    /// terms, with the removal list sorted and comma-joined.
    pub fn to_context(&self) -> String {
        let mut rm = self.rm.clone();
        rm.sort();
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.by,
            self.g,
            self.e0,
            self.me,
            self.rh,
            rm.join(",")
        )
    }
}

/// The context string for a welcome. A welcome has no mix epoch and no roster
/// hash, so it does not go through [`RekeyContext::to_context`].
pub fn welcome_context(by: &str, g: i64, e0: i64) -> String {
    format!("{}/welcome|{}|{}|{}", kdf::PROTO, by, g, e0)
}

/// Seal `plaintext` to one recipient.
///
/// `context` is bound into the associated data alongside the channel and the
/// recipient, so a wrap only opens for the recipient it was addressed to and
/// only under the exact circumstances it was created for.
pub fn wrap_to(
    _sender: &Identity,
    recipient_epk: &[u8],
    channel: &str,
    recipient_member: &str,
    context: &str,
    plaintext: &[u8],
) -> Option<Wrap> {
    // A fresh ephemeral key per wrap. Reusing one across recipients would make
    // the shared secrets related.
    let ephemeral = EcdhKey::generate();
    let shared = ephemeral.agree(recipient_epk)?;
    let key = kdf::wrap_key(&shared, channel, recipient_member);
    let aad = wrap_aad(channel, recipient_member, context);

    let nonce_bytes: [u8; 12] = random_bytes();
    let ct = seal(&key, &nonce_bytes, plaintext, aad.as_bytes())?;

    let mut blob = Vec::with_capacity(nonce_bytes.len() + ct.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);

    Some(Wrap {
        eph: crate::b64::encode(&ephemeral.public_bytes()),
        w: crate::b64::encode(&blob),
    })
}

/// Open a wrap addressed to this device.
///
/// The ephemeral key must be a real curve point: 65 bytes is not enough, the
/// bytes must be a point, or the shared secret is attacker-chosen.
pub fn open_wrap(
    recipient: &Identity,
    eph_b64: &str,
    w_b64: &str,
    channel: &str,
    context: &str,
) -> Option<Vec<u8>> {
    let eph_bytes = crate::b64::decode(eph_b64)?;
    if !crate::identity::valid_ecdh_key(&eph_bytes) {
        return None;
    }
    let blob = crate::b64::decode(w_b64)?;
    // A blob is a 12-byte nonce plus at least a 16-byte tag.
    if blob.len() <= 12 {
        return None;
    }
    let (nonce, ct) = blob.split_at(12);
    let nonce: [u8; 12] = nonce.try_into().ok()?;

    let shared = recipient.ecdh().agree(&eph_bytes)?;
    let key = kdf::wrap_key(&shared, channel, recipient.member_id());
    let aad = wrap_aad(channel, recipient.member_id(), context);
    open(&key, &nonce, ct, aad.as_bytes())
}

/// Open a wrap and require it to contain exactly a generation seed.
pub fn open_seed(
    recipient: &Identity,
    eph_b64: &str,
    w_b64: &str,
    channel: &str,
    context: &str,
) -> Option<[u8; WRAPPED_SEED_LEN]> {
    let plain = open_wrap(recipient, eph_b64, w_b64, channel, context)?;
    <[u8; WRAPPED_SEED_LEN]>::try_from(plain.as_slice()).ok()
}

/// Build the re-key message for one recipient.
///
/// `fresh_entropy` is mixed into the next generation's seed at the mix epoch, so
/// every recipient derives the same next seed from their own copy of the chain
/// key at `me`. It is 32 fresh bytes per re-key, not per recipient.
#[allow(clippy::too_many_arguments)]
pub fn build_rekey(
    sender: &Identity,
    recipient_epk: &[u8],
    recipient_member: &str,
    from_channel: &str,
    _to_channel: &str,
    g: i64,
    e0: i64,
    me: i64,
    ts: i64,
    rh: &str,
    rm: &[String],
    _fresh_entropy: &[u8; FRESH_ENTROPY_LEN],
    next_seed: &[u8; 32],
) -> Option<CircleMsg> {
    let ctx = RekeyContext {
        by: sender.member_id().to_string(),
        g,
        e0,
        me,
        rh: rh.to_string(),
        rm: rm.to_vec(),
    };
    // The wrap's associated data names the channel that is *ending*, because
    // that is the channel the message travels on and the one a replay of it
    // would land on.
    let wrap = wrap_to(
        sender,
        recipient_epk,
        from_channel,
        recipient_member,
        &ctx.to_context(),
        next_seed,
    )?;

    Some(CircleMsg::ReKey {
        v: crate::msg::VERSION,
        ts,
        g,
        e0,
        me,
        to: recipient_member.to_string(),
        eph: wrap.eph,
        w: wrap.w,
        rm: rm.to_vec(),
        rh: rh.to_string(),
    })
}

/// Rebuild a re-key's context from the message's own fields, which is what a
/// receiver uses to open the wrap.
pub fn context_from_message(msg: &CircleMsg, sender_member: &str) -> Option<String> {
    match msg {
        CircleMsg::ReKey { g, e0, me, rh, rm, .. } => Some(
            RekeyContext {
                by: sender_member.to_string(),
                g: *g,
                e0: *e0,
                me: *me,
                rh: rh.clone(),
                rm: rm.clone(),
            }
            .to_context(),
        ),
        _ => None,
    }
}

/// Whether a re-key's opening epoch is believable.
///
/// Bounded against the *message's own* epoch rather than the receiver's clock,
/// deliberately. A re-key that sat in the relay across an epoch boundary must
/// stay valid, and an unbounded check here once allowed a single message to
/// destroy every other device's circle by claiming an absurd `e0`.
pub fn e0_is_plausible(msg_epoch: i64, e0: i64, now_epoch: i64) -> bool {
    if e0 < 0 {
        return false;
    }
    // Bounded against the message's epoch, with the same two-epoch tolerance
    // used everywhere else.
    (e0 - msg_epoch).abs() <= crate::wire::MAX_SKEW_EPOCHS
        // And not so far in the future that it would walk a receiver's chain.
        && e0 <= now_epoch + crate::wire::MAX_SKEW_EPOCHS
}

/// Whether a mix epoch is believable: it cannot be in the future, because it
/// names an epoch whose chain key must already exist.
pub fn me_is_plausible(msg_epoch: i64, me: i64) -> bool {
    me >= 0 && me <= msg_epoch
}

/// Derive the next generation's seed from the mix-epoch chain key.
pub fn derive_next_seed(
    ck_at_mix: &[u8; 32],
    fresh_entropy: &[u8; FRESH_ENTROPY_LEN],
) -> [u8; 32] {
    kdf::next_seed(ck_at_mix, fresh_entropy)
}

/// Zeroize a seed after use.
pub fn wipe_seed(seed: &mut [u8; 32]) {
    seed.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{identity::Identity, msg::VERSION, seal::random_bytes, wire::EPOCH_MS};

    const CHANNEL: &str = "f1c695a80bae6baf8bb34828bc177bc9";
    const NEXT_CHANNEL: &str = "fc41f5d4ce4f7c09d8006c4b4bc4d367";

    fn at(e: i64) -> i64 {
        e * EPOCH_MS
    }

    fn seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        s
    }

    #[test]
    fn a_wrap_round_trips_to_its_recipient() {
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let ctx = RekeyContext {
            by: sender.member_id().to_string(),
            g: 1,
            e0: 2,
            me: 2,
            rh: "hash".into(),
            rm: vec![],
        };
        let w = wrap_to(
            &sender,
            &recipient.epk_bytes(),
            CHANNEL,
            recipient.member_id(),
            &ctx.to_context(),
            &seed(),
        )
        .unwrap();
        let out = open_wrap(&recipient, &w.eph, &w.w, CHANNEL, &ctx.to_context()).unwrap();
        assert_eq!(out, seed());
    }

    #[test]
    fn a_wrap_does_not_open_for_a_different_recipient() {
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let stranger = Identity::generate();
        let ctx = RekeyContext {
            by: sender.member_id().into(),
            g: 1,
            e0: 2,
            me: 2,
            rh: String::new(),
            rm: vec![],
        };
        let w = wrap_to(
            &sender,
            &recipient.epk_bytes(),
            CHANNEL,
            recipient.member_id(),
            &ctx.to_context(),
            &seed(),
        )
        .unwrap();
        // The associated data names the recipient, so a third party cannot open
        // it even with the right shared secret.
        assert!(open_wrap(&stranger, &w.eph, &w.w, CHANNEL, &ctx.to_context()).is_none());
    }

    #[test]
    fn a_wrap_does_not_open_under_a_different_context() {
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let base = RekeyContext {
            by: sender.member_id().into(),
            g: 1,
            e0: 2,
            me: 2,
            rh: "hash".into(),
            rm: vec![],
        };
        let w = wrap_to(
            &sender,
            &recipient.epk_bytes(),
            CHANNEL,
            recipient.member_id(),
            &base.to_context(),
            &seed(),
        )
        .unwrap();

        // Changing the removal list must invalidate the wrap. This is the
        // splicing attack the context exists to prevent.
        let spliced = RekeyContext {
            rm: vec!["cfeb6c3eedeab2f19faf80ee98930d20".into()],
            ..base.clone()
        };
        assert!(
            open_wrap(&recipient, &w.eph, &w.w, CHANNEL, &spliced.to_context()).is_none()
        );

        // As must changing the roster hash, the generation, or the mix epoch.
        for mutated in [
            RekeyContext { rh: "other".into(), ..base.clone() },
            RekeyContext { g: 2, ..base.clone() },
            RekeyContext { e0: 3, ..base.clone() },
            RekeyContext { me: 3, ..base.clone() },
            RekeyContext { by: "someoneelse".into(), ..base.clone() },
        ] {
            assert!(
                open_wrap(&recipient, &w.eph, &w.w, CHANNEL, &mutated.to_context())
                    .is_none(),
                "context change must invalidate the wrap"
            );
        }
    }

    #[test]
    fn a_wrap_does_not_open_on_a_different_channel() {
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let ctx = RekeyContext {
            by: sender.member_id().into(),
            g: 1,
            e0: 2,
            me: 2,
            rh: String::new(),
            rm: vec![],
        };
        let w = wrap_to(
            &sender,
            &recipient.epk_bytes(),
            CHANNEL,
            recipient.member_id(),
            &ctx.to_context(),
            &seed(),
        )
        .unwrap();
        assert!(
            open_wrap(&recipient, &w.eph, &w.w, NEXT_CHANNEL, &ctx.to_context()).is_none()
        );
    }

    #[test]
    fn the_context_string_is_exactly_six_terms() {
        let ctx = RekeyContext {
            by: "dc73c74c3f57c6ff0c2d9016c333507f".into(),
            g: 1,
            e0: 2980472,
            me: 2980472,
            rh: "W9DL9QIok5IlC_F3JA_ZA5xu0J_3q0g1HVKcBpFa8DQ".into(),
            rm: vec![],
        };
        // This is the published vector for a re-key with an empty removal list.
        assert_eq!(
            ctx.to_context(),
            "dc73c74c3f57c6ff0c2d9016c333507f|1|2980472|2980472|W9DL9QIok5IlC_F3JA_ZA5xu0J_3q0g1HVKcBpFa8DQ|"
        );
    }

    #[test]
    fn the_context_sorts_the_removal_list() {
        let a = "11111111111111111111111111111111".to_string();
        let b = "22222222222222222222222222222222".to_string();
        let forward = RekeyContext {
            by: "x".into(),
            g: 1,
            e0: 1,
            me: 1,
            rh: String::new(),
            rm: vec![a.clone(), b.clone()],
        };
        let reverse = RekeyContext {
            by: "x".into(),
            g: 1,
            e0: 1,
            me: 1,
            rh: String::new(),
            rm: vec![b, a],
        };
        assert_eq!(forward.to_context(), reverse.to_context());
        assert!(forward.to_context().ends_with(
            "11111111111111111111111111111111,22222222222222222222222222222222"
        ));
    }

    #[test]
    fn the_welcome_context_matches_the_published_vector() {
        assert_eq!(
            welcome_context("dc73c74c3f57c6ff0c2d9016c333507f", 1, 2980472),
            "starling/v2/welcome|dc73c74c3f57c6ff0c2d9016c333507f|1|2980472"
        );
    }

    #[test]
    fn a_welcome_wrap_uses_its_own_context() {
        let sender = Identity::generate();
        let joiner = Identity::generate();
        let ctx = welcome_context(sender.member_id(), 1, 2);
        let w = wrap_to(
            &sender,
            &joiner.epk_bytes(),
            CHANNEL,
            joiner.member_id(),
            &ctx,
            &seed(),
        )
        .unwrap();
        assert_eq!(open_wrap(&joiner, &w.eph, &w.w, CHANNEL, &ctx).unwrap(), seed());
        // A re-key context must not open it.
        let rekey_ctx = RekeyContext {
            by: sender.member_id().into(),
            g: 1,
            e0: 2,
            me: 2,
            rh: String::new(),
            rm: vec![],
        };
        assert!(
            open_wrap(&joiner, &w.eph, &w.w, CHANNEL, &rekey_ctx.to_context()).is_none()
        );
    }

    #[test]
    fn an_invalid_ephemeral_key_is_refused() {
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let ctx = welcome_context("x", 1, 2);
        let w = wrap_to(
            &sender,
            &recipient.epk_bytes(),
            CHANNEL,
            recipient.member_id(),
            &ctx,
            &seed(),
        )
        .unwrap();

        // 65 bytes that are not a curve point.
        let bad = crate::b64::encode(&[0u8; 65]);
        assert!(open_wrap(&recipient, &bad, &w.w, CHANNEL, &ctx).is_none());
        // Wrong length.
        assert!(
            open_wrap(&recipient, &crate::b64::encode(&[0u8; 32]), &w.w, CHANNEL, &ctx)
                .is_none()
        );
    }

    #[test]
    fn a_truncated_blob_is_refused() {
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let ctx = welcome_context("x", 1, 2);
        let w = wrap_to(
            &sender,
            &recipient.epk_bytes(),
            CHANNEL,
            recipient.member_id(),
            &ctx,
            &seed(),
        )
        .unwrap();
        // Shorter than a nonce plus a tag.
        let short = crate::b64::encode(&[0u8; 11]);
        assert!(open_wrap(&recipient, &w.eph, &short, CHANNEL, &ctx).is_none());
    }

    #[test]
    fn a_seed_must_be_exactly_32_bytes() {
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let ctx = welcome_context("x", 1, 2);
        let short = wrap_to(
            &sender,
            &recipient.epk_bytes(),
            CHANNEL,
            recipient.member_id(),
            &ctx,
            &[0u8; 31],
        )
        .unwrap();
        assert!(open_seed(&recipient, &short.eph, &short.w, CHANNEL, &ctx).is_none());
        let right = wrap_to(
            &sender,
            &recipient.epk_bytes(),
            CHANNEL,
            recipient.member_id(),
            &ctx,
            &seed(),
        )
        .unwrap();
        assert!(open_seed(&recipient, &right.eph, &right.w, CHANNEL, &ctx).is_some());
    }

    #[test]
    fn each_wrap_uses_a_fresh_ephemeral_key() {
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let ctx = welcome_context("x", 1, 2);
        let a = wrap_to(
            &sender,
            &recipient.epk_bytes(),
            CHANNEL,
            recipient.member_id(),
            &ctx,
            &seed(),
        )
        .unwrap();
        let b = wrap_to(
            &sender,
            &recipient.epk_bytes(),
            CHANNEL,
            recipient.member_id(),
            &ctx,
            &seed(),
        )
        .unwrap();
        assert_ne!(a.eph, b.eph, "two wraps must not share an ephemeral key");
        assert_ne!(a.w, b.w, "so the same plaintext seals differently each time");
    }

    #[test]
    fn the_next_seed_is_a_function_of_the_chain_key_and_the_entropy() {
        let ck = [1u8; 32];
        let ns = [2u8; 32];
        assert_eq!(derive_next_seed(&ck, &ns), kdf::next_seed(&ck, &ns));
        // Different entropy, different seed.
        assert_ne!(derive_next_seed(&ck, &ns), derive_next_seed(&ck, &[3u8; 32]));
    }

    #[test]
    fn a_rekey_message_reconstructs_its_own_context() {
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let ns = [5u8; 32];
        let msg = build_rekey(
            &sender,
            &recipient.epk_bytes(),
            recipient.member_id(),
            CHANNEL,
            NEXT_CHANNEL,
            1,
            2,
            2,
            1_000_000_000,
            "hash",
            &[],
            &ns,
            &ns,
        )
        .unwrap();

        let ctx = context_from_message(&msg, sender.member_id()).unwrap();
        let opened =
            open_seed(&recipient, msg_eph(&msg), msg_w(&msg), CHANNEL, &ctx).unwrap();
        assert_eq!(opened, ns);
    }

    fn msg_eph(m: &CircleMsg) -> &str {
        match m {
            CircleMsg::ReKey { eph, .. } => eph,
            _ => panic!("not a rekey"),
        }
    }
    fn msg_w(m: &CircleMsg) -> &str {
        match m {
            CircleMsg::ReKey { w, .. } => w,
            _ => panic!("not a rekey"),
        }
    }

    #[test]
    fn a_rekey_names_exactly_one_recipient() {
        let sender = Identity::generate();
        let a = Identity::generate();
        let b = Identity::generate();
        let ns = [7u8; 32];
        let msg = build_rekey(
            &sender,
            &a.epk_bytes(),
            a.member_id(),
            CHANNEL,
            NEXT_CHANNEL,
            1,
            2,
            2,
            1,
            "hash",
            &[],
            &ns,
            &ns,
        )
        .unwrap();
        assert!(context_from_message(&msg, sender.member_id()).is_some());
        let ctx = context_from_message(&msg, sender.member_id()).unwrap();
        // B is not the recipient, so the wrap does not open for B.
        assert!(open_wrap(&b, msg_eph(&msg), msg_w(&msg), CHANNEL, &ctx).is_none());
    }

    #[test]
    fn the_opening_epoch_is_bounded_by_the_message_epoch() {
        // A backlogged re-key stays valid.
        assert!(e0_is_plausible(2980472, 2980472, 2980472));
        assert!(e0_is_plausible(2980472, 2980474, 2980476), "+2 is allowed");
        // Unbounded e0 was a one-message remote wipe; it must stay refused.
        assert!(!e0_is_plausible(2980472, 2980490, 2980490));
        assert!(!e0_is_plausible(2980472, 0, 2980472), "e0=0 is not plausible here");
        assert!(!e0_is_plausible(2980472, -1, 2980472));
        // A re-key cannot open the future.
        assert!(!e0_is_plausible(2980472, 2990000, 2980472));
    }

    #[test]
    fn the_mix_epoch_cannot_be_in_the_future() {
        assert!(me_is_plausible(10, 10));
        assert!(me_is_plausible(10, 9));
        assert!(!me_is_plausible(10, 11));
        assert!(!me_is_plausible(10, -1));
    }

    #[test]
    fn a_generation_seed_is_stable_across_derivations() {
        // A sender and a recipient walking the chain independently must reach
        // the same next seed, or the circle silently splits.
        let seed0 = seed();
        let now = at(2980471);
        let mut sender = crate::ratchet::Ratchet::new(&seed0, now);
        let mut recipient = crate::ratchet::Ratchet::new(&seed0, now);
        let entropy = random_bytes::<32>();

        let ck_sender = sender.chain_key_at(2980472, at(2980472)).unwrap();
        let ck_recipient = recipient.chain_key_at(2980472, at(2980472)).unwrap();
        assert_eq!(ck_sender, ck_recipient);
        assert_eq!(
            derive_next_seed(&ck_sender, &entropy),
            derive_next_seed(&ck_recipient, &entropy)
        );
    }

    #[test]
    fn a_rekey_wrap_is_addressed_on_the_ending_channel() {
        // The message travels on the channel that is ending, so that is the
        // channel bound into the associated data.
        let sender = Identity::generate();
        let recipient = Identity::generate();
        let ns = [9u8; 32];
        let msg = build_rekey(
            &sender,
            &recipient.epk_bytes(),
            recipient.member_id(),
            CHANNEL,
            NEXT_CHANNEL,
            1,
            2,
            2,
            1,
            "h",
            &[],
            &ns,
            &ns,
        )
        .unwrap();
        let ctx = context_from_message(&msg, sender.member_id()).unwrap();
        assert!(open_seed(&recipient, msg_eph(&msg), msg_w(&msg), CHANNEL, &ctx).is_some());
        assert!(
            open_seed(&recipient, msg_eph(&msg), msg_w(&msg), NEXT_CHANNEL, &ctx).is_none()
        );
    }

    #[test]
    fn the_removal_list_travels_with_the_message() {
        let sender = Identity::generate();
        let keep = Identity::generate();
        let ns = [3u8; 32];
        let removed = "cfeb6c3eedeab2f19faf80ee98930d20".to_string();
        let msg = build_rekey(
            &sender,
            &keep.epk_bytes(),
            keep.member_id(),
            CHANNEL,
            NEXT_CHANNEL,
            2,
            3,
            3,
            1,
            "h",
            std::slice::from_ref(&removed),
            &ns,
            &ns,
        )
        .unwrap();
        match &msg {
            CircleMsg::ReKey { rm, v, .. } => {
                assert_eq!(rm, &vec![removed]);
                assert_eq!(*v, VERSION);
            }
            _ => panic!("not a rekey"),
        }
    }
}
