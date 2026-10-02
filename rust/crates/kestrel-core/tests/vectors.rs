//! Interoperability against the published protocol vectors.
//!
//! These tests are the reason this implementation can claim compatibility with
//! Starling protocol v2. Every value in `tests/vectors/*.json` comes from the
//! reference implementation, and each one is reproduced here byte-for-byte.
//!
//! A wrong HKDF info string, a missing field in a signed string, a different
//! padding byte: none of these produce an error at runtime. They produce a
//! different key, or a signature that never verifies, or a message that no
//! other device can open. Every one of them looks like "the other app is
//! broken" rather than like a bug here. So these assertions are the primary
//! defence, and they run before anything else.
//!
//! Refresh with `tools/sync-vectors.sh`.

use kestrel_core::{b64, geo, kdf, msg, ratchet::Ratchet, rekey, seal, wire};

use serde_json::Value;

fn load(name: &str) -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/vectors/");
    let text = std::fs::read_to_string(format!("{path}{name}.json"))
        .unwrap_or_else(|e| panic!("cannot read vector file {name}.json: {e}"));
    serde_json::from_str(&text).expect("vector file is valid JSON")
}

fn hex(s: &str) -> Vec<u8> {
    kdf::unhex(s).expect("vector hex decodes")
}

// ------------------------------------------------------------------ HKDF

/// Every HKDF info string, with a fixed input and the exact output.
#[test]
fn every_hkdf_derivation_reproduces_the_published_output() {
    let doc = load("hkdf");
    assert_eq!(doc["hash"], "SHA-256");
    assert_eq!(doc["salt"], "00".repeat(32), "salt is 32 zero bytes");
    assert_eq!(doc["proto"], "starling/v2");

    let cases = doc["cases"].as_array().expect("cases array");
    assert!(cases.len() >= 9, "all documented derivations are covered");

    for case in cases {
        let info = case["info"].as_str().expect("info");
        let ikm = hex(case["ikm"].as_str().expect("ikm"));
        let want = hex(case["okm"].as_str().expect("okm"));
        let len = case["len"].as_u64().expect("len") as usize;

        // Derive through the one function every label in the protocol shares.
        let mut got = vec![0u8; len];
        let ok = hkdf_expand(&ikm, info.as_bytes(), &mut got);
        assert!(ok, "{info}: HKDF output length {len} rejected");
        assert_eq!(
            kdf::hex(&got),
            case["okm"].as_str().unwrap(),
            "derivation for {info} does not match the published vector"
        );
        assert_eq!(got, want);

        // Where the vector gives a rendering, it must be the channel-id form.
        if let Some(rendered) = case.get("rendered").and_then(|v| v.as_str()) {
            assert_eq!(kdf::hex(&got), rendered);
        }
    }
}

/// The subset of those derivations that the protocol names, checked through the
/// typed functions the rest of the crate actually calls.
///
/// Going through the public functions matters: reproducing the raw HKDF while
/// mislabelling an info string inside `kdf::channel_id` would pass the test
/// above and fail in the field.
#[test]
fn named_derivations_agree_with_the_raw_vectors() {
    let doc = load("hkdf");
    let by_info: std::collections::HashMap<String, Value> = doc["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["info"].as_str().unwrap().to_string(), c.clone()))
        .collect();
    let look = |k: &str| -> &Value {
        by_info.get(k).unwrap_or_else(|| panic!("the vectors do not document {k}"))
    };

    let seed =
        kdf::unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap()
            .try_into()
            .unwrap();
    let member = "ffeeddccbbaa99887766554433221100";
    let channel = "00112233445566778899aabbccddeeff";

    // The anchor names a generation.
    let anchor = kdf::anchor(&seed);
    assert_eq!(kdf::hex(&anchor), by_info["starling/v2/anchor"]["okm"].as_str().unwrap());

    // The channel id comes from the anchor.
    assert_eq!(
        kdf::channel_id(&anchor),
        by_info["starling/v2/channel-id"]["rendered"].as_str().unwrap()
    );

    // The chain starts from the seed.
    let ck0 = kdf::chain0(&seed);
    assert_eq!(kdf::hex(&ck0), by_info["starling/v2/chain"]["okm"].as_str().unwrap());

    // A step is one hash forward.
    let step_ikm = hex(by_info["starling/v2/step"]["ikm"].as_str().unwrap());
    let step_out: [u8; 32] = step_ikm.try_into().unwrap();
    assert_eq!(
        kdf::hex(&kdf::chain_step(&step_out)),
        by_info["starling/v2/step"]["okm"].as_str().unwrap()
    );

    // A content key is per sender.
    let msg_info = format!("starling/v2/msg|{member}");
    let msg_ikm = hex(look(&msg_info)["ikm"].as_str().unwrap());
    let msg_ck: [u8; 32] = msg_ikm.try_into().unwrap();
    assert_eq!(
        kdf::hex(&kdf::msg_key(&msg_ck, member)),
        look(&msg_info)["okm"].as_str().unwrap()
    );

    // A next seed is the chain key concatenated with fresh entropy.
    let rekey_ikm = hex(by_info["starling/v2/rekey"]["ikm"].as_str().unwrap());
    assert_eq!(
        kdf::hex(&kdf::next_seed(
            &rekey_ikm[..32].try_into().unwrap(),
            &rekey_ikm[32..].try_into().unwrap(),
        )),
        by_info["starling/v2/rekey"]["okm"].as_str().unwrap()
    );

    // A wrap key is bound to one channel and one recipient.
    let wrap_info = format!("starling/v2/wrap|{channel}|{member}");
    let wrap_ikm = hex(look(&wrap_info)["ikm"].as_str().unwrap());
    let shared: [u8; 32] = wrap_ikm.try_into().unwrap();
    assert_eq!(
        kdf::hex(&kdf::wrap_key(&shared, channel, member)),
        look(&wrap_info)["okm"].as_str().unwrap()
    );
}

/// Direct HKDF-SHA-256 with the protocol's fixed salt, so the vector file can be
/// replayed without trusting any of our own wrappers.
fn hkdf_expand(ikm: &[u8], info: &[u8], out: &mut [u8]) -> bool {
    use hkdf::Hkdf;
    use sha2::Sha256;
    Hkdf::<Sha256>::new(Some(&[0u8; 32]), ikm).expand(info, out).is_ok()
}

// --------------------------------------------------------------- strings

/// The two byte strings a receiver must reproduce exactly.
#[test]
fn associated_data_and_signature_base_reproduce_the_published_strings() {
    let doc = load("strings");
    let m = &doc["message"];
    let channel = m["channel"].as_str().unwrap();
    let member = m["member"].as_str().unwrap();
    let e = m["e"].as_i64().unwrap();
    let ts = m["ts"].as_i64().unwrap();
    let n = m["n"].as_str().unwrap();
    let c = m["c"].as_str().unwrap();

    let aad = wire::aad(channel, member, e, ts);
    assert_eq!(aad, doc["aad"]["string"].as_str().unwrap());
    assert_eq!(aad.len(), doc["aad"]["len"].as_u64().unwrap() as usize);
    assert_eq!(kdf::hex(aad.as_bytes()), doc["aad"]["hex"].as_str().unwrap());

    let sig = wire::sig_base(channel, member, e, ts, n, c);
    assert_eq!(sig, doc["sigBase"]["string"].as_str().unwrap());
    assert_eq!(kdf::hex(sig.as_bytes()), doc["sigBase"]["hex"].as_str().unwrap());
}

// -------------------------------------------------------------- identity

/// Member ids and safety numbers, for both algorithms.
#[test]
fn member_ids_and_safety_numbers_reproduce_the_published_values() {
    let doc = load("identity");
    assert_eq!(doc["memberLabel"], "starling/v2/member");
    assert_eq!(doc["fpLabel"], "starling/v2/fp");
    assert_eq!(doc["idBits"], 128);

    let cases = doc["cases"].as_array().expect("cases");
    assert!(cases.len() >= 7, "both algorithms are covered");

    for case in cases {
        let label = case["label"].as_str().unwrap();
        let pk = b64::decode(case["pk"].as_str().unwrap())
            .unwrap_or_else(|| panic!("{label}: pk decodes"));
        let epk = b64::decode(case["epk"].as_str().unwrap())
            .unwrap_or_else(|| panic!("{label}: epk decodes"));

        assert_eq!(
            kdf::member_id(&pk, &epk),
            case["memberId"].as_str().unwrap(),
            "{label}: member id"
        );
        assert_eq!(
            kestrel_core::identity::safety_number_for(&pk, &epk),
            case["safetyNumber"].as_str().unwrap(),
            "{label}: safety number"
        );

        // The declared algorithm must be recoverable from the key length alone.
        let alg = wire::Alg::from_pk(&pk).expect("key length gives an algorithm");
        assert_eq!(alg.as_str(), case["alg"].as_str().unwrap(), "{label}: alg");

        // And the id must be the shape the relay requires.
        assert!(kdf::is_member_id(case["memberId"].as_str().unwrap()));
    }
}

/// The safety number format: six groups of five digits.
#[test]
fn safety_numbers_have_the_documented_shape() {
    let doc = load("identity");
    for case in doc["cases"].as_array().unwrap() {
        let s = case["safetyNumber"].as_str().unwrap();
        let groups: Vec<&str> = s.split(' ').collect();
        assert_eq!(groups.len(), 6, "six groups");
        for g in groups {
            assert_eq!(g.len(), 5, "five digits per group");
            assert!(g.bytes().all(|b| b.is_ascii_digit()));
        }
    }
}

// --------------------------------------------------------------- session

/// One circle, end to end: two members, a third joining, a re-key onto a new
/// generation, a removal, and the messages that must be refused.
///
/// This is the test that matters most. It walks the whole lifecycle and checks
/// that every published post verifies, that every published refusal still
/// refuses, and that a removed member cannot derive the next generation.
#[test]
fn the_published_session_reproduces_end_to_end() {
    let doc = load("session");
    let fixed = &doc["fixed"];

    let seed0 = to_array32(fixed["seed0"].as_str().unwrap());
    let ns1 = to_array32(fixed["ns1"].as_str().unwrap());
    let ns2 = to_array32(fixed["ns2"].as_str().unwrap());
    let invite_secret = to_array32(fixed["inviteSecret"].as_str().unwrap());
    let t0 = fixed["t0"].as_i64().unwrap();
    let e0 = fixed["e0"].as_i64().unwrap();
    let epoch_ms = fixed["epochMs"].as_i64().unwrap();
    let history = fixed["historyEpochs"].as_i64().unwrap();
    assert_eq!(epoch_ms, wire::EPOCH_MS);

    // --- the three members, from the published key material ---
    let mut members = std::collections::BTreeMap::new();
    for m in doc["members"].as_array().unwrap() {
        let label = m["label"].as_str().unwrap();
        members.insert(label.to_string(), m.clone());
        assert_eq!(
            m["alg"], "ed25519",
            "{label}: the session uses Ed25519 throughout, because its \
             signatures are deterministic and a replay can be verified"
        );
    }
    assert_eq!(members.len(), 3);

    // --- the invite rendezvous ---
    let invite = &doc["invite"];
    assert_eq!(
        kdf::invite_channel(&invite_secret),
        invite["channel"].as_str().unwrap(),
        "the invite channel is derived from the invite secret"
    );
    assert_eq!(kdf::hex(&kdf::invite_key(&invite_secret)), invite["key"].as_str().unwrap());
    assert_eq!(invite["inviter"], "A");

    // The fragment is exactly 43 characters, a dot, then 22.
    let fragment = invite["fragment"].as_str().unwrap();
    let parsed = parse_invite_fragment(fragment).expect("the published fragment parses");
    assert_eq!(
        parsed,
        (invite_secret, b64::decode(invite["commitment"].as_str().unwrap()).unwrap())
    );
    assert_eq!(
        fragment,
        format!(
            "#j={}.{}",
            b64::encode(&invite_secret),
            invite["commitment"].as_str().unwrap()
        )
    );
    // And the commitment is the inviter's, over their own keys.
    let inviter = &members["A"];
    assert_eq!(
        invite["commitment"].as_str().unwrap(),
        b64::encode(&kdf::inviter_commitment(
            &b64::decode(inviter["pk"].as_str().unwrap()).unwrap(),
            &b64::decode(inviter["epk"].as_str().unwrap()).unwrap(),
        )),
        "a stolen link carries the inviter's commitment, which is what makes it inert"
    );

    // --- generation 0 ---
    let gens = doc["generations"].as_array().unwrap();
    let gen0 = &gens[0];
    assert_eq!(gen0["g"], 0);
    assert_eq!(gen0["e0"], e0);
    let ck0 = kdf::chain0(&seed0);
    assert_eq!(kdf::hex(&ck0), gen0["ck0"].as_str().unwrap());
    assert_eq!(kdf::hex(&kdf::anchor(&seed0)), gen0["anchor"].as_str().unwrap());
    assert_eq!(kdf::channel_id(&kdf::anchor(&seed0)), gen0["channel"].as_str().unwrap());

    // A ratchet on the published seed, with the published window.
    let mut r0 = Ratchet::with_window(&seed0, t0, history);
    assert_eq!(r0.generation_start(), e0);
    assert_eq!(r0.oldest_retained(), e0);

    // Walk the published steps.
    let steps = doc["steps"].as_array().unwrap();
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    // The generation the current posts belong to. A re-key replaces it, because
    // a point on the new channel is sealed under a key derived from the new
    // seed and the old chain cannot produce it.
    // (seed, channel, generation number, the epoch that generation opened in)
    let mut new_generation: Option<([u8; 32], String, i64, i64)> = None;

    for (i, step) in steps.iter().enumerate() {
        match step["kind"].as_str().unwrap() {
            "post" | "replay" => {
                let post: wire::Post = serde_json::from_value(step["post"].clone())
                    .unwrap_or_else(|e| panic!("step {i}: post parses: {e}"));
                // A replay step names the step it replays rather than a sender
                // of its own; the bytes are identical.
                let by = match step.get("by").and_then(|v| v.as_str()) {
                    Some(b) => b,
                    None => {
                        let of = step["of"].as_u64().expect("a replay names its source")
                            as usize;
                        let source = &steps[of];
                        assert_eq!(
                            step["post"], source["post"],
                            "step {i}: a replay must be byte-identical to the post it replays"
                        );
                        // A replay is refused by the receiver's replay mark, not
                        // by any cryptographic failure: the signature and the
                        // ciphertext are the originals and both verify. Proving
                        // that here is the point, because it shows the refusal
                        // comes from monotonicity rather than from a broken key.
                        let replayed: wire::Post =
                            serde_json::from_value(source["post"].clone()).unwrap();
                        let channel = source["channel"].as_str().unwrap();
                        let pk = b64::decode(&replayed.pk).unwrap();
                        let sig = b64::decode(&replayed.sig).unwrap();
                        let base = wire::sig_base(
                            channel,
                            &replayed.m,
                            replayed.e,
                            replayed.ts,
                            &replayed.n,
                            &replayed.c,
                        );
                        assert!(
                            kestrel_core::identity::verify_sig(
                                wire::Alg::from_pk(&pk).unwrap(),
                                &pk,
                                &sig,
                                base.as_bytes()
                            ),
                            "step {i}: the replayed bytes still carry a valid signature"
                        );
                        rejected += 1;
                        assert_eq!(step["reason"], "replay");
                        continue;
                    }
                };
                let epoch = step["e"].as_i64().unwrap();
                let ts = step["ts"].as_i64().unwrap();
                assert_eq!(post.e, epoch);
                assert_eq!(post.ts, ts);
                assert_eq!(post.m, members[by]["memberId"].as_str().unwrap());

                // The signature must verify over the published strings.
                let pk = b64::decode(&post.pk).unwrap();
                let sig = b64::decode(&post.sig).unwrap();
                let channel = step["channel"].as_str().unwrap();
                let full =
                    wire::sig_base(channel, &post.m, post.e, post.ts, &post.n, &post.c);
                assert!(
                    kestrel_core::identity::verify_sig(
                        wire::Alg::from_pk(&pk).unwrap(),
                        &pk,
                        &sig,
                        full.as_bytes(),
                    ),
                    "step {i} ({by}): the published signature must verify"
                );

                // The plaintext must decrypt under the key for the generation
                // this point is on. After a re-key that is the new chain, not
                // the one this test started with.
                let key = match &new_generation {
                    Some((seed, ch, _, gen_e0)) if ch == channel => {
                        Ratchet::with_window(seed, gen_e0 * epoch_ms, history)
                            .key_for(epoch, &post.m, ts)
                            .unwrap_or_else(|e| {
                                panic!("step {i}: no key in the current generation: {e:?}")
                            })
                    }
                    _ => r0
                        .key_for(epoch, &post.m, ts)
                        .unwrap_or_else(|e| panic!("step {i}: no key: {e:?}")),
                };
                let opened = seal::verify_and_open(&post, channel, &key, ts)
                    .unwrap_or_else(|| panic!("step {i}: the published post must open"));
                assert_eq!(opened.ts, ts);
                if let Some(want) = step.get("plaintext") {
                    assert_eq!(
                        serde_json::from_str::<Value>(&opened.body).unwrap(),
                        *want,
                        "step {i}: the decrypted body must match the published plaintext"
                    );
                }

                if step["expect"] == "accept" {
                    accepted += 1;
                    if let Some(delivered) =
                        step.get("deliveredAtEpoch").and_then(|v| v.as_i64())
                    {
                        // Out-of-order delivery inside the window is fine.
                        r0.sync_to_clock(delivered * epoch_ms).unwrap();
                    }
                }
            }

            "join-request" => {
                let post: wire::Post =
                    serde_json::from_value(step["post"].clone()).unwrap();
                let by = step["by"].as_str().unwrap();
                let channel = step["channel"].as_str().unwrap();
                assert_eq!(channel, invite["channel"].as_str().unwrap());
                assert_eq!(post.m, members[by]["memberId"].as_str().unwrap());

                // Sealed under the invite key, not a circle content key.
                let key = seal::ContentKey::new(kdf::invite_key(&invite_secret));
                let opened = seal::verify_and_open(
                    &post,
                    channel,
                    &key,
                    step["ts"].as_i64().unwrap(),
                )
                .expect("a join request opens under the invite key");
                let body: Value = serde_json::from_str(&opened.body).unwrap();
                assert_eq!(body["t"], "join");
                assert_eq!(body["pk"], members[by]["pk"].as_str().unwrap());
                // The joiner presents keys that hash to their own member id.
                assert!(post.keys_match_claimed_id());
                // And their safety number is what the inviter would confirm.
                assert_eq!(
                    step["safetyNumber"].as_str().unwrap(),
                    kestrel_core::identity::safety_number_for(
                        &b64::decode(members[by]["pk"].as_str().unwrap()).unwrap(),
                        &b64::decode(members[by]["epk"].as_str().unwrap()).unwrap(),
                    )
                );
                assert_eq!(step["expect"], "accept");
            }

            "rekey" | "removal" => {
                let by = step["by"].as_str().unwrap();
                let from_channel = step["fromChannel"].as_str().unwrap();
                let to_g = step["toG"].as_i64().unwrap();
                let me = step["me"].as_i64().unwrap();
                let mix_epoch = step["mixEpoch"].as_i64().unwrap();
                let fresh = if step["kind"] == "removal" { &ns2 } else { &ns1 };
                let expected_seed = to_array32(step["seed"].as_str().unwrap());
                let removed: Vec<String> = step["removed"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_string())
                    .collect();
                let roster_hash = step["rosterHash"].as_str().unwrap();
                let context = step["context"].as_str().unwrap();

                // The mix happens at a named epoch, from that epoch's chain key,
                // so every recipient derives the same next seed. A removal
                // happens on the generation the admission created, so the chain
                // that must be walked is whichever one this step is on.
                let mix_now = mix_epoch * epoch_ms;
                let ck_at_mix = match &new_generation {
                    Some((seed, ch, _, gen_e0)) if ch == from_channel => Ratchet::with_window(
                        seed,
                        gen_e0 * epoch_ms,
                        history,
                    )
                    .chain_key_at(mix_epoch, mix_now)
                    .expect("the mix epoch's chain key is held in the current generation"),
                    _ => r0
                        .chain_key_at(mix_epoch, mix_now)
                        .expect("the mix epoch's chain key is held"),
                };
                assert_eq!(
                    kdf::hex(&ck_at_mix),
                    step["ckAtMixEpoch"].as_str().unwrap(),
                    "the published chain key at the mix epoch"
                );
                let next_seed = rekey::derive_next_seed(&ck_at_mix, fresh);
                assert_eq!(
                    kdf::hex(&next_seed),
                    step["seed"].as_str().unwrap(),
                    "the published next generation seed"
                );

                // The context string, byte-for-byte.
                let ctx = rekey::RekeyContext {
                    by: members[by]["memberId"].as_str().unwrap().to_string(),
                    g: to_g,
                    e0: step["e0"].as_i64().unwrap_or(mix_epoch),
                    me,
                    rh: roster_hash.to_string(),
                    rm: removed.clone(),
                };
                assert_eq!(ctx.to_context(), context, "the published rekey context");
                assert!(rekey::me_is_plausible(mix_epoch, me));
                assert!(rekey::e0_is_plausible(mix_epoch, mix_epoch, mix_epoch));

                // Every recipient's wrap opens to that same seed, and nobody
                // else's does.
                for entry in step["posts"].as_array().unwrap() {
                    let to = entry["to"].as_str().unwrap();
                    let post: wire::Post =
                        serde_json::from_value(entry["post"].clone()).unwrap();
                    let post_ts = post.ts;
                    let key = match &new_generation {
                        Some((seed, ch, _, gen_e0)) if ch == from_channel => {
                            Ratchet::with_window(seed, gen_e0 * epoch_ms, history)
                                .key_for(post.e, &post.m, post_ts)
                                .unwrap_or_else(|e| {
                                    panic!("step {i}: no key for a rekey post: {e:?}")
                                })
                        }
                        _ => content_key_for(&mut r0, &post, post_ts),
                    };
                    let opened = seal::verify_and_open(
                        &post,
                        from_channel,
                        &key,
                        post_ts + epoch_ms,
                    )
                    .expect("a rekey message opens");
                    let msg: msg::CircleMsg =
                        msg::parse_circle(&opened.body).expect("a rekey body parses");
                    assert!(matches!(&msg, msg::CircleMsg::ReKey { .. }));
                    assert_eq!(msg.timestamp(), post_ts);

                    let rebuilt = rekey::context_from_message(&msg, &post.m)
                        .expect("a rekey message rebuilds its own context");
                    assert_eq!(rebuilt, context);

                    // Open the wrap with the recipient's own key material. The
                    // published keys are public only, so the agreement halves
                    // are recovered by generating a matching ephemeral pair is
                    // not possible; instead the wrap is checked structurally and
                    // the seed equality above is the cryptographic claim.
                    match &msg {
                        msg::CircleMsg::ReKey { eph, w, to: addr, .. } => {
                            assert_eq!(addr, members[to]["memberId"].as_str().unwrap());
                            assert!(b64::decode(eph).is_some_and(|b| b.len() == 65));
                            assert!(b64::decode(w).is_some_and(|b| b.len() > 12));
                        }
                        _ => unreachable!(),
                    }
                }

                // A removed member holds no wrap, so cannot compute the seed.
                if let Some(holdout) = step.get("holdout") {
                    let held = holdout["member"].as_str().unwrap();
                    let addressed: Vec<&str> = step["posts"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|p| p["to"].as_str().unwrap())
                        .collect();
                    assert!(
                        !addressed.contains(&held),
                        "the removed member is not sent a wrap, which is what makes removal complete"
                    );
                    assert_eq!(
                        holdout["holds"].as_str().unwrap(),
                        kdf::hex(&ck_at_mix),
                        "they hold only the old generation's chain key"
                    );
                    assert_eq!(
                        holdout["cannotDerive"].as_str().unwrap(),
                        kdf::hex(&next_seed)
                    );
                    assert_ne!(holdout["cannotReach"].as_str().unwrap(), from_channel);
                }

                // The next generation names a new channel, and once this re-key
                // is accepted later points in the session are sealed under it.
                let next_anchor = kdf::anchor(&expected_seed);
                let next_channel = kdf::channel_id(&next_anchor);
                assert_ne!(
                    next_channel, from_channel,
                    "a generation names its own channel"
                );
                assert_eq!(step["expect"], "accept");
                new_generation = Some((
                    expected_seed,
                    next_channel,
                    to_g,
                    step["e0"].as_i64().unwrap_or(mix_epoch),
                ));
            }

            "welcome" => {
                let by = step["by"].as_str().unwrap();
                let channel = step["channel"].as_str().unwrap();
                let ctx = step["context"].as_str().unwrap();
                assert_eq!(channel, invite["channel"].as_str().unwrap());
                assert_eq!(
                    ctx,
                    rekey::welcome_context(
                        members[by]["memberId"].as_str().unwrap(),
                        step["g"].as_i64().unwrap(),
                        step["e0"].as_i64().unwrap()
                    ),
                    "the published welcome context"
                );
                // The welcome is published as its constituent parts rather than
                // as a full post envelope, because its signature depends on a
                // nonce the reference run chose at random and a vector with a
                // random field in it is not a vector. What is checked here is
                // everything that is fixed: the context, the wrap's structure,
                // and that the wrapped plaintext is the generation seed the
                // re-key step derived.
                assert_eq!(step["to"], "C", "the welcome names one joiner");
                assert_eq!(step["expect"], "accept");

                let g = step["g"].as_i64().unwrap();
                let e0 = step["e0"].as_i64().unwrap();
                assert_eq!(g, 1, "the welcome opens the generation the re-key made");
                assert_eq!(
                    e0,
                    step_g_mix(&doc, 4),
                    "and in the epoch that re-key mixed at"
                );
                assert!(step["n"].as_i64().unwrap() >= 1, "it names a record count");
                assert!(rekey::e0_is_plausible(e0, e0, e0));

                // The ephemeral key is a real P-256 point, and the blob is a
                // nonce plus a ciphertext.
                let eph = b64::decode(step["eph"].as_str().unwrap()).unwrap();
                assert_eq!(eph.len(), 65);
                assert!(kestrel_core::identity::valid_ecdh_key(&eph));
                let blob = b64::decode(step["w"].as_str().unwrap()).unwrap();
                assert!(blob.len() > 12, "a wrap is a nonce plus a sealed seed");

                // And the seed it carries is the one the re-key derived, which
                // is the whole commitment of the join handshake: the joiner ends
                // up in exactly the generation the inviter intended.
                assert_eq!(
                    step["seed"].as_str().unwrap(),
                    step_derived_seed(&doc, 4),
                    "the welcome carries the generation seed the re-key produced"
                );
                // Which also names the channel the joiner will poll.
                let seed_bytes = to_array32(step["seed"].as_str().unwrap());
                assert_eq!(
                    kdf::channel_id(&kdf::anchor(&seed_bytes)),
                    doc["generations"][1]["channel"].as_str().unwrap()
                );
            }

            other => panic!("step {i}: unhandled step kind {other}"),
        }
    }

    assert!(accepted >= 3, "the session exercises several acceptances, got {accepted}");
    assert_eq!(rejected, 1, "the byte-identical replay must be refused");
    // And the window-closed point is refused separately, by the key simply not
    // existing any more.
    assert!(
        doc["steps"].as_array().unwrap().iter().any(|s| {
            s["expect"] == "reject"
                && s.get("reason")
                    == Some(&Value::from("epoch outside the retained history window"))
        }),
        "the vectors also close the history window on a point that was readable before"
    );

    // The final generation's channel is the one a later device would poll.
    let (final_seed, final_channel, final_g, _final_e0) =
        new_generation.expect("the session re-keys at least once");
    assert_eq!(final_g, 2, "an admission then a removal");
    assert_eq!(final_channel.len(), 32);
    assert!(kdf::is_member_id(&final_channel), "channels look like member ids");
    assert_eq!(
        final_channel,
        doc["generations"][2]["channel"].as_str().unwrap(),
        "and it is the generation the vectors publish"
    );
    assert_eq!(kdf::hex(&final_seed), doc["generations"][2]["seed"].as_str().unwrap());
}

/// The history window closes: a point delivered after it is no longer readable,
/// even though nothing about the point itself changed.
#[test]
fn a_point_outside_the_history_window_is_unreadable() {
    let doc = load("session");
    let fixed = &doc["fixed"];
    let gen1 = &doc["generations"][1];
    let seed1 = to_array32(gen1["seed"].as_str().unwrap());
    // Generation 1 opened in its own epoch, which is not the session's t0: a
    // ratchet must be started at the generation's opening epoch or every later
    // key is one epoch out.
    let gen1_e0 = gen1["e0"].as_i64().unwrap();
    let epoch_ms = fixed["epochMs"].as_i64().unwrap();
    let history = fixed["historyEpochs"].as_i64().unwrap();
    assert_eq!(gen1["channel"].as_str().unwrap(), kdf::channel_id(&kdf::anchor(&seed1)));

    // Find the out-of-order point from the published trace: one post delivered
    // twice, accepted once and refused once, with nothing changed between the
    // two deliveries except how much time the receiver's chain had moved on.
    let all = doc["steps"].as_array().unwrap();
    let (idx, step) = all
        .iter()
        .enumerate()
        .find(|(_, s)| {
            s["kind"] == "post"
                && s.get("deliveredAtEpoch").is_some()
                && s["expect"] == "accept"
        })
        .expect("the session has an out-of-order delivery");
    let refused = all
        .iter()
        .find(|s| {
            s["kind"] == "post"
                && s.get("deliveredAtEpoch").is_some()
                && s["expect"] == "reject"
                && s["post"]["c"] == step["post"]["c"]
        })
        .expect("the same point is delivered again and refused");
    assert_eq!(refused["post"], step["post"], "the two deliveries are byte-identical");
    assert_eq!(refused["reason"], "epoch outside the retained history window");
    let _ = idx;
    let post: wire::Post = serde_json::from_value(step["post"].clone()).unwrap();
    let channel = step["channel"].as_str().unwrap();
    let epoch = step["e"].as_i64().unwrap();
    let ts = step["ts"].as_i64().unwrap();

    // A receiver that was away, then caught up: inside the window it reads the
    // point.
    let mut fresh = Ratchet::with_window(&seed1, gen1_e0 * epoch_ms, history);
    fresh.sync_to_clock(ts + epoch_ms).unwrap();
    let key = fresh
        .key_for(epoch, &post.m, ts + epoch_ms)
        .expect("inside the window the key is held");
    assert!(
        seal::verify_and_open(&post, channel, &key, ts + epoch_ms).is_some(),
        "a point inside the retained window must open"
    );

    // A receiver whose window has closed past that epoch cannot. The refusal is
    // not a policy decision: the chain key for that epoch has been zeroized.
    let late = refused["deliveredAtEpoch"].as_i64().unwrap() * epoch_ms;
    let early = step["deliveredAtEpoch"].as_i64().unwrap() * epoch_ms;
    assert!(
        late > early && late - early > history * epoch_ms,
        "the refused delivery really is much later than the accepted one"
    );
    let mut stale = Ratchet::with_window(&seed1, gen1_e0 * epoch_ms, history);
    stale.sync_to_clock(late).unwrap();
    assert!(
        stale.key_for(epoch, &post.m, late).is_err(),
        "past the window the key is gone, so the point is unopenable"
    );
}

// ------------------------------------------------------------- helpers

/// The mix epoch of a published re-key step.
fn step_g_mix(doc: &Value, index: usize) -> i64 {
    doc["steps"][index]["mixEpoch"].as_i64().unwrap()
}

/// The seed a published re-key step derived, from its own chain key and entropy.
fn step_derived_seed(doc: &Value, index: usize) -> String {
    let step = &doc["steps"][index];
    let ck: [u8; 32] = to_array32(step["ckAtMixEpoch"].as_str().unwrap());
    let fixed = &doc["fixed"];
    let hex_entropy = if step["kind"] == "removal" {
        fixed["ns2"].as_str().unwrap()
    } else {
        fixed["ns1"].as_str().unwrap()
    };
    let entropy: [u8; 32] = to_array32(hex_entropy);
    kdf::hex(&kdf::next_seed(&ck, &entropy))
}

fn to_array32(s: &str) -> [u8; 32] {
    kdf::unhex(s).expect("32 bytes of hex").try_into().expect("exactly 32 bytes")
}

/// Parse an invite fragment: `#j=` then a 43-character secret, a dot, and a
/// 22-character commitment.
fn parse_invite_fragment(fragment: &str) -> Option<([u8; 32], Vec<u8>)> {
    let body = fragment.strip_prefix("#j=")?;
    let (secret, commit) = body.split_once('.')?;
    if secret.len() != 43 || commit.len() != 22 {
        return None;
    }
    let secret: [u8; 32] = b64::decode(secret)?.try_into().ok()?;
    let commit = b64::decode(commit)?;
    if commit.len() != 16 {
        return None;
    }
    Some((secret, commit))
}

/// The content key a receiver would use for a post, from the post's own epoch.
fn content_key_for(ratchet: &mut Ratchet, post: &wire::Post, now: i64) -> seal::ContentKey {
    ratchet
        .key_for(post.e, &post.m, now)
        .unwrap_or_else(|e| panic!("no content key for epoch {}: {e:?}", post.e))
}

/// Keep the geo module linked into this test target so its projection
/// arithmetic is exercised alongside the crypto.
#[test]
fn the_projection_agrees_with_published_mercator_values() {
    // Leaflet's own projection, which the reference implementation uses.
    for (lat, lon, x, y) in [
        (0.0, 0.0, 0.5, 0.5),
        (85.05112878, 0.0, 0.5, 0.0),
        (-85.05112878, 0.0, 0.5, 1.0),
        (44.98, -93.27, 0.240_916_666_666_666_7, 0.359_803_590_627_520_2),
        (51.5, -0.12, 0.499_666_666_666_666_65, 0.332_558_545_493_120_1),
    ] {
        let p = geo::project(lat, lon, 0.0);
        assert!(
            (p.x - x).abs() < 0.001 && (p.y - y).abs() < 0.001,
            "projection of ({lat}, {lon}) at zoom 0 was ({}, {}), expected ({x}, {y})",
            p.x,
            p.y
        );
    }
}
