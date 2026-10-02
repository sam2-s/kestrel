//! The client state machine: what a device knows, and what it does with a post
//! it has just read off the relay.
//!
//! This is where the protocol's rules about *order* live. The cryptography is in
//! `seal` and `kdf`; what is left is deciding which of two individually valid
//! messages to believe, and in what sequence.
//!
//! The receive path, for one post, in the order the checks must run:
//!
//! 1. is this my own post? (I would reject it on the replay mark anyway, but
//!    there is no reason to decrypt it)
//! 2. are these the keys the roster pinned for this member? If the member is
//!    known and the keys differ, this is not that member any more — the point is
//!    dropped and the user is told, rather than being silently accepted.
//! 3. admit the member if they are new, subject to the cap
//! 4. does the signature verify, under the algorithm the *key length* implies?
//! 5. does it decrypt under the one key the message's own epoch selects?
//! 6. does the inner timestamp equal the header's?
//! 7. for a control message, was this member already pinned *before this pass*?
//!    A re-key creates a new channel, so accepting one from a stranger would let
//!    anyone the relay names a member redirect a circle.
//! 8. is it newer than the last thing this member said?
//!
//! Steps 2 and 7 are the ones that are easy to get subtly wrong, and both are
//! about *prior* state: the pinned roster as it was before this post, not as it
//! is after.

use std::collections::{HashMap, VecDeque};

use crate::{
    b64,
    identity::Identity,
    kdf,
    msg::{self, CircleMsg, Fix, ShareMode, Who},
    places::{Alert, Places},
    ratchet::{HistoryWindow, Ratchet, Snapshot, window_start},
    roster::{AdmitError, KeyVerdict, LOCAL_CAP, Member, Roster, key_change_verdict},
    seal::ContentKey,
    wire::{self, MEMBER_CAP, Post, TRAIL_CAP},
};

/// How many control-message receipts to remember.
///
/// Separate from the position high-water mark, and deliberately so. Sharing one
/// mark means a relay that serves a later position first permanently suppresses
/// that member's re-key: the re-key is older than the position that arrived first,
/// and the shared mark has already passed it.
const CONTROL_SEEN_CAP: usize = 512;

/// The newest position this device has accepted from a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct HighWater {
    epoch: i64,
    ts: i64,
}

/// What a device knows about one member, as the map needs it.
#[derive(Debug, Clone, PartialEq)]
pub struct MemberState {
    pub member: Member,
    /// The newest accepted position.
    pub last: Option<CircleMsg>,
    /// A bounded trail of accepted positions, oldest first.
    pub trail: Vec<CircleMsg>,
    /// The member's hue, from their id.
    pub hue: u16,
    /// When this device last heard anything at all from them.
    pub last_seen: i64,
    /// Whether they have been removed from this generation.
    pub removed: bool,
}

impl MemberState {
    /// Whether this member's dot should be drawn as live.
    ///
    /// Three minutes, which is generous: a phone in a pocket with the screen off
    /// stops posting for reasons that have nothing to do with where its owner is.
    pub fn is_live(&self, now: i64) -> bool {
        self.last_seen > 0 && now.saturating_sub(self.last_seen) <= STALE_MS
    }

    /// The newest position, if it is recent enough to draw.
    ///
    /// A member's *current* position, so a goodbye makes this `None`: they are
    /// not there any more. Use [`MemberState::last_fix`] to draw them where they
    /// last were, greyed out.
    pub fn position(&self, now: i64) -> Option<Fix> {
        self.last
            .as_ref()
            .filter(|m| now.saturating_sub(m.timestamp()) <= STALE_MS)
            .and_then(|m| m.fix())
    }

    /// The newest position in this member's trail, whenever it was.
    ///
    /// For a member who has stopped: the map should show where they last were,
    /// not nothing, because a missing dot reads as "nobody is there" and a greyed
    /// one reads as "they are not there now".
    pub fn last_fix(&self) -> Option<Fix> {
        self.trail.iter().rev().find_map(|m| m.fix())
    }

    /// When this member last said anything, position or not.
    pub fn last_spoke(&self) -> i64 {
        self.last.as_ref().map(|m| m.timestamp()).unwrap_or(0)
    }
}

/// How old a position may be before a member's dot greys out.
pub const STALE_MS: i64 = 3 * 60 * 1000;

/// Something that happened while reading a feed.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// A member's position was accepted.
    Position { member: String, message: CircleMsg },
    /// A member stopped sharing, by saying so.
    Stopped { member: String },
    /// A member was removed from the circle.
    Removed { member: String },
    /// A re-key was accepted and a new generation is now current.
    Rekeyed { generation: i64, by: String },
    /// A member's keys changed. Their points are dropped from now on.
    KeyChanged { member: String },
    /// A new member was admitted to the roster.
    Joined { member: String },
    /// A place was entered or left.
    Place(Alert),
}

/// Why a post was not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Our own post, coming back to us.
    OwnPost,
    /// The member is known and their keys are not the pinned ones.
    KeyChanged,
    /// The member could not be admitted.
    NotAdmissible(AdmitError),
    /// The signature did not verify.
    BadSignature,
    /// No key opened it: the epoch is unknown, out of the window, or the
    /// ciphertext is not what it claims to be.
    Undecryptable,
    /// The inner timestamp did not match the header's.
    TimestampMismatch,
    /// A re-key from a member who was not already pinned.
    StrangerControl,
    /// Not newer than the last thing this member said.
    Replay,
    /// The body was not one of this channel's message types.
    WrongKind,
    /// A claim outside the acceptable clock range.
    Implausible,
}

/// One device's view of one circle.
pub struct Circle {
    identity: Identity,
    channel: String,
    ratchet: Ratchet,
    roster: Roster,
    members: HashMap<String, MemberState>,
    /// Newest accepted position per member.
    high_water: HashMap<String, HighWater>,
    /// Receipts for control messages, in arrival order, separate from the position
    /// mark. A queue rather than a set, because the eviction policy is "oldest
    /// first" and a set has no order to evict from.
    control_seen: VecDeque<String>,
    /// Members this generation was founded with. A re-key is honoured only from
    /// one of these.
    founding: Vec<String>,
    generation: i64,
    opened_epoch: i64,
    generation_at: i64,
    /// When a roster hash mismatch was first seen, for the grace period.
    roster_mismatch_since: Option<i64>,
    /// Places, and the alerts they have produced.
    pub places: Places,
    /// The last outgoing timestamp, so ours strictly increases.
    last_sent_ts: i64,
    /// The last outgoing epoch, tracked separately from the head.
    sent_epoch: i64,
}

/// What a rotation produced, before the rotator joins its own new generation.
///
/// Returned rather than posted, because where each part goes is the caller's
/// decision and getting it wrong is silent: a re-key on the rendezvous channel
/// is a message nobody will ever read.
#[derive(Debug, Clone)]
pub struct Rotation {
    /// The re-keys for everyone still in, sealed to the channel that is ending.
    pub rekeys: Vec<Post>,
    /// The new generation's seed. For the welcome; the rotator already holds it.
    pub seed: [u8; 32],
    pub generation: i64,
    pub opening_epoch: i64,
    /// The channel the circle moves to.
    pub channel: String,
}

impl Circle {
    /// A brand new circle, from a fresh seed.
    pub fn create(identity: Identity, seed: &[u8; 32], now: i64) -> Self {
        let anchor = kdf::anchor(seed);
        let channel = kdf::channel_id(&anchor);
        let ratchet = Ratchet::new(seed, now);
        let opened_epoch = ratchet.generation_start();
        let mut roster = Roster::new();
        // This device occupies a relay row, so the roster is one short of the cap.
        let _ = roster.admit(
            identity.member_id(),
            &identity.pk_b64(),
            &identity.epk_b64(),
            now,
            LOCAL_CAP,
        );
        let founding = roster.ids();
        Self {
            identity,
            channel,
            ratchet,
            roster,
            members: HashMap::new(),
            high_water: HashMap::new(),
            control_seen: VecDeque::new(),
            founding,
            generation: 0,
            opened_epoch,
            generation_at: now,
            roster_mismatch_since: None,
            places: Places::new(),
            last_sent_ts: 0,
            sent_epoch: opened_epoch,
        }
    }

    /// A circle this device is joining, from a welcome.
    pub fn join(
        identity: Identity,
        seed: &[u8; 32],
        channel: String,
        generation: i64,
        opened_epoch: i64,
        roster: Roster,
        now: i64,
    ) -> Self {
        let ratchet = Ratchet::restore(
            &Snapshot {
                e0: opened_epoch,
                ck0: kdf::chain0(seed),
                window: HistoryWindow::Default.epochs(),
            },
            now,
        );
        let founding = roster.ids();
        let mut circle = Self {
            identity,
            channel,
            ratchet,
            roster,
            members: HashMap::new(),
            high_water: HashMap::new(),
            control_seen: VecDeque::new(),
            founding,
            generation,
            opened_epoch,
            generation_at: now,
            roster_mismatch_since: None,
            places: Places::new(),
            last_sent_ts: 0,
            sent_epoch: opened_epoch,
        };
        // This device is a member from the moment it joins, even though it does
        // not pin itself: a re-key's roster hash is computed over a view that
        // includes it.
        let _ = circle.roster.admit(
            circle.identity.member_id(),
            &circle.identity.pk_b64(),
            &circle.identity.epk_b64(),
            now,
            LOCAL_CAP,
        );
        circle
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn channel(&self) -> &str {
        &self.channel
    }

    pub fn generation(&self) -> i64 {
        self.generation
    }

    pub fn opened_epoch(&self) -> i64 {
        self.opened_epoch
    }

    pub fn generation_at(&self) -> i64 {
        self.generation_at
    }

    pub fn roster(&self) -> &Roster {
        &self.roster
    }

    pub fn ratchet(&self) -> &Ratchet {
        &self.ratchet
    }

    pub fn snapshot(&self) -> Snapshot {
        self.ratchet.snapshot()
    }

    /// The members, for the member sheet.
    pub fn members(&self) -> Vec<&MemberState> {
        let mut v: Vec<&MemberState> = self.members.values().collect();
        v.sort_by(|a, b| a.member.name.cmp(&b.member.name));
        v
    }

    pub fn member(&self, id: &str) -> Option<&MemberState> {
        self.members.get(id)
    }

    /// Where the feed poll should start.
    ///
    /// The oldest retained epoch, not the newest, so a device that was away long
    /// enough still sees the trail it missed rather than starting from now.
    pub fn feed_cursor(&self, now: i64) -> i64 {
        window_start(&self.ratchet, now)
    }

    // -------------------------------------------------------------- sending

    /// The epoch to encrypt in next.
    ///
    /// Follows this device's own clock and its own last send, never the chain
    /// head: a peer that pushed the head forward must not drag this device's
    /// sends with it, or one device with a fast clock moves the whole circle.
    pub fn send_epoch(&self, now: i64) -> i64 {
        self.ratchet.send_epoch(now).max(self.sent_epoch)
    }

    /// The next timestamp to use, which strictly increases.
    pub fn next_timestamp(&mut self, now: i64) -> i64 {
        let ts = now.max(self.last_sent_ts + 1);
        self.last_sent_ts = ts;
        ts
    }

    /// Seal a circle message and return the post to send.
    pub fn seal(&mut self, message: &CircleMsg, now: i64) -> Option<Post> {
        let ts = self.next_timestamp(now);
        let body = self.with_timestamp(message, ts);
        let epoch = self.send_epoch(now);
        let json = serde_json::to_string(&body).ok()?;
        let key = self.ratchet.key_for(epoch, self.identity.member_id(), now).ok()?;
        let post =
            crate::seal::build_post(&self.identity, &self.channel, &key, epoch, ts, &json)
                .ok()?;
        self.sent_epoch = epoch;
        self.ratchet.note_sent(epoch);
        Some(post)
    }

    /// A copy of a message stamped with the timestamp actually used.
    ///
    /// The inner timestamp has to equal the header's, and the header's is chosen
    /// here, so the body is rewritten rather than the two being reconciled later.
    fn with_timestamp(&self, message: &CircleMsg, ts: i64) -> CircleMsg {
        let mut out = message.clone();
        match &mut out {
            CircleMsg::Loc { ts: t, .. }
            | CircleMsg::CheckIn { ts: t, .. }
            | CircleMsg::Sos { ts: t, .. }
            | CircleMsg::Bye { ts: t, .. }
            | CircleMsg::ReKey { ts: t, .. } => *t = ts,
        }
        out
    }

    /// Build a position post for a fix.
    pub fn location(
        &mut self,
        who: &Who,
        fix: Fix,
        mode: ShareMode,
        now: i64,
    ) -> Option<Post> {
        // Coarse rounding happens *before* encryption, so the ciphertext is the
        // coarse position. Quantising afterwards would leave the exact one inside.
        let fix = if mode == ShareMode::Coarse { fix.coarse() } else { fix };
        let mut who = who.clone();
        who.mode = mode;
        self.seal(&CircleMsg::loc(0, who, fix), now)
    }

    /// Build a check-in post.
    pub fn check_in(&mut self, who: &Who, fix: Fix, now: i64) -> Option<Post> {
        self.seal(&CircleMsg::check_in(0, who.clone(), fix), now)
    }

    /// Build an emergency post.
    pub fn sos(&mut self, who: &Who, fix: Fix, now: i64) -> Option<Post> {
        self.seal(&CircleMsg::sos(0, who.clone(), fix), now)
    }

    /// Build a signed goodbye, so the circle sees "stopped" rather than a dot
    /// frozen at wherever the device last was.
    pub fn goodbye(&mut self, who: &Who, now: i64) -> Option<Post> {
        self.seal(&CircleMsg::bye(0, who.clone()), now)
    }

    // ------------------------------------------------------------ receiving

    /// Read one post, and say what happened.
    ///
    /// `pinned_before` is the roster as it was *before* this pass, which is what
    /// decides whether a control message came from a member or a stranger. Taking
    /// it as a parameter rather than reading the live roster is the whole point:
    /// a post that admits its own author satisfies a check that consults the state
    /// the post itself changed.
    pub fn ingest(
        &mut self,
        post: &Post,
        roster_before: &Roster,
        now: i64,
    ) -> Result<Vec<Event>, Reject> {
        if post.m == self.identity.member_id() {
            return Err(Reject::OwnPost);
        }

        // --- 2. are these the pinned keys? ---
        match key_change_verdict(roster_before, &post.m, &post.pk, &post.epk) {
            KeyVerdict::Changed => return Err(Reject::KeyChanged),
            KeyVerdict::Admitted => {}
            KeyVerdict::Known => {}
        }

        // --- 3. admit a new member, or explain why not ---
        let mut admitted = false;
        if !roster_before.contains(&post.m) {
            match self.roster.admit(&post.m, &post.pk, &post.epk, now, LOCAL_CAP) {
                Ok(true) => admitted = true,
                Ok(false) => {}
                Err(e) => return Err(Reject::NotAdmissible(e)),
            }
        }

        // --- 4. the signature, under the algorithm the key length implies ---
        let pk = post.pk_bytes().ok_or(Reject::BadSignature)?;
        let alg = wire::Alg::from_pk(&pk).ok_or(Reject::BadSignature)?;
        let sig = b64::decode(&post.sig).ok_or(Reject::BadSignature)?;
        let signed =
            wire::sig_base(&self.channel, &post.m, post.e, post.ts, &post.n, &post.c);
        if !crate::identity::verify_sig(alg, &pk, &sig, signed.as_bytes()) {
            return Err(Reject::BadSignature);
        }

        // --- 5. exactly one key, chosen by the message's own epoch ---
        let key: ContentKey = self
            .ratchet
            .key_for(post.e, &post.m, now)
            .map_err(|_| Reject::Undecryptable)?;
        let opened = crate::seal::verify_and_open(post, &self.channel, &key, now)
            .ok_or(Reject::Undecryptable)?;

        // --- 6. the inner timestamp must equal the header's ---
        if !msg::inner_timestamp_matches(&opened.body, post.ts) {
            return Err(Reject::TimestampMismatch);
        }
        if post.ts > now + wire::FUTURE_SKEW_MS {
            return Err(Reject::Implausible);
        }
        let message = msg::parse_circle(&opened.body).ok_or(Reject::WrongKind)?;

        // --- 7. a control message needs a prior pin ---
        if message.requires_prior_pin() && !roster_before.contains(&post.m) {
            return Err(Reject::StrangerControl);
        }

        let mut events = Vec::new();
        if admitted {
            events.push(Event::Joined { member: post.m.clone() });
        }

        match &message {
            CircleMsg::ReKey { .. } => {
                // The receipt, checked separately from the position mark. A relay
                // that serves a later position first must not permanently suppress
                // this.
                let receipt = format!("{}|{}|{}", post.m, post.e, post.ts);
                if self.control_seen.contains(&receipt) {
                    return Err(Reject::Replay);
                }
                self.control_seen.push_back(receipt);
                while self.control_seen.len() > CONTROL_SEEN_CAP {
                    // Oldest out first. Halving rather than trimming to the limit,
                    // so this costs a fraction of a second every few hundred
                    // control messages rather than a second on every one past the
                    // limit.
                    self.control_seen.drain(..CONTROL_SEEN_CAP / 2);
                }

                let by = post.m.clone();
                match self.apply_rekey(&message, &by, now) {
                    Ok(generation) => {
                        events.push(Event::Rekeyed { generation, by });
                        // Everything older belongs to a channel that is ending.
                        self.members.retain(|_, s| !s.removed);
                        self.control_seen.clear();
                    }
                    Err(Reject::Replay) => return Err(Reject::Replay),
                    Err(e) => return Err(e),
                }
                return Ok(events);
            }

            CircleMsg::Bye { .. } => {
                if let Some(who) = message.who() {
                    self.roster.set_name(&post.m, &who.name);
                }
                if !self.accept_position(&post.m, post.e, message.clone(), now)? {
                    return Err(Reject::Replay);
                }
                if let Some(s) = self.members.get_mut(&post.m) {
                    s.removed = false;
                }
                events.push(Event::Stopped { member: post.m.clone() });
                return Ok(events);
            }

            _ => {}
        }

        // Record the name before the state is refreshed, or a map reading the
        // snapshot would show a nameless dot until the next message arrived.
        if let Some(who) = message.who() {
            self.roster.set_name(&post.m, &who.name);
        }

        // --- 8. strictly newer, per member ---
        if !self.accept_position(&post.m, post.e, message.clone(), now)? {
            return Err(Reject::Replay);
        }
        if let Some(fix) = message.fix() {
            let member_name =
                self.roster.get(&post.m).map(|m| m.name.clone()).unwrap_or_default();
            let alerts = self.places.observe(&member_name, fix.lat, fix.lon, fix.acc, now);
            for a in alerts {
                events.push(Event::Place(a));
            }
        }

        events.push(Event::Position { member: post.m.clone(), message });
        Ok(events)
    }

    /// The monotonicity check and the trail, in one place.
    ///
    /// A separate mark from the control receipts, on purpose: a re-key is older
    /// than the position that a relay may have served first, and sharing one mark
    /// would let that ordering permanently suppress the re-key.
    fn accept_position(
        &mut self,
        member: &str,
        epoch: i64,
        message: CircleMsg,
        now: i64,
    ) -> Result<bool, Reject> {
        // The epoch comes from the post header, which is the value the associated
        // data and the signature both committed to. Deriving it from the body's
        // timestamp instead would let a body and a header disagree.
        let (e, ts) = (epoch, message.timestamp());
        if let Some(mark) = self.high_water.get(member)
            && (e < mark.epoch || (e == mark.epoch && ts <= mark.ts))
        {
            return Ok(false);
        }
        self.high_water.insert(member.to_string(), HighWater { epoch: e, ts });

        let state = self.members.entry(member.to_string()).or_insert_with(|| MemberState {
            member: self.roster.get(member).cloned().unwrap_or_else(|| Member {
                member_id: member.to_string(),
                alg: wire::Alg::Ed25519,
                pk: String::new(),
                epk: String::new(),
                verified: false,
                name: String::new(),
                hue: crate::identity::hue_from_member_id(member),
                admitted_at: now,
            }),
            last: None,
            trail: Vec::new(),
            hue: crate::identity::hue_from_member_id(member),
            last_seen: 0,
            removed: false,
        });
        // Refresh the roster snapshot alongside the position. A member's name
        // arrives in their first message, after the row was created, and a map
        // reading a stale copy would show a nameless dot for ever.
        if let Some(current) = self.roster.get(member) {
            state.member = current.clone();
            state.hue = current.hue;
        }
        state.last = Some(message.clone());
        state.last_seen = now;
        state.trail.push(message);
        if state.trail.len() > TRAIL_CAP {
            let excess = state.trail.len() - TRAIL_CAP;
            state.trail.drain(..excess);
        }
        Ok(true)
    }

    /// Apply a checked re-key: adopt the new generation.
    fn apply_rekey(
        &mut self,
        message: &CircleMsg,
        by: &str,
        now: i64,
    ) -> Result<i64, Reject> {
        let CircleMsg::ReKey { g, e0, to, rm, .. } = message else {
            return Err(Reject::WrongKind);
        };
        if to != self.identity.member_id() {
            return Err(Reject::WrongKind);
        }
        if *g != self.generation + 1 {
            return Err(Reject::WrongKind);
        }
        if !self.founding.iter().any(|id| id == by) {
            return Err(Reject::StrangerControl);
        }

        // The seed is inside the wrap, which is bound to this device's key and to
        // the whole context. By the time it opens, the checks above have already
        // passed; a wrap that does not open means the sender used a different key
        // than the roster pinned, which is the same class of problem as a
        // signature failure.
        let (eph, w) = match message {
            CircleMsg::ReKey { eph, w, .. } => (eph, w),
            _ => unreachable!(),
        };
        let ctx =
            crate::rekey::context_from_message(message, by).ok_or(Reject::Undecryptable)?;
        let seed = crate::rekey::open_seed(&self.identity, eph, w, &self.channel, &ctx)
            .ok_or(Reject::Undecryptable)?;

        // A re-key is a fresh generation, and the previous one's history is
        // unreadable from here on. That is the point of it.
        self.adopt(*g, *e0, &seed, rm, now);
        Ok(self.generation)
    }

    /// Move onto a generation whose seed this device already holds.
    ///
    /// The two halves of a re-key are the same move from two directions: a
    /// recipient opens a wrap to get the seed, and the rotator derives it from its
    /// own chain key. Both end here, so neither can drift from the other — the
    /// failure mode being a rotator sitting on the channel everyone else has left.
    fn adopt(
        &mut self,
        generation: i64,
        opening_epoch: i64,
        seed: &[u8; 32],
        removed: &[String],
        now: i64,
    ) {
        let ratchet = Ratchet::restore(
            &Snapshot {
                e0: opening_epoch,
                ck0: kdf::chain0(seed),
                window: self.ratchet.window(),
            },
            now,
        );
        self.ratchet = ratchet;
        self.channel = kdf::channel_id(&kdf::anchor(seed));
        self.generation = generation;
        self.opened_epoch = opening_epoch;
        self.generation_at = now;
        self.sent_epoch = self.sent_epoch.min(opening_epoch);
        self.last_sent_ts = 0;
        self.roster_mismatch_since = None;

        // Members removed in this generation, and anyone not in the new founding
        // roster, stop being drawn.
        for removed in removed {
            if kdf::is_member_id(removed) {
                self.roster.remove(removed);
                self.high_water.remove(removed);
                self.places.forget(removed);
            }
        }
        self.founding.retain(|id| self.roster.contains(id));

        // A device that was not in the new founding roster is out. The rotator is
        // in it by construction, and this device is too, because it did not
        // receive a wrap unless it was one of the recipients.
        self.members.retain(|id, _| self.roster.contains(id));
    }

    /// End this generation and start the next one, as the device that is rotating.
    ///
    /// The seed comes from this device's own chain key, so unlike a recipient the
    /// rotator does not wrap a seed to itself. It does wrap one to everyone else
    /// still in — including a newcomer being admitted, who cannot read it and gets
    /// the seed in the welcome instead, which is exactly what the protocol's
    /// published session expects.
    ///
    /// `fresh_entropy` is mixed with the chain key, so neither a relay that
    /// observes the mix nor a device that only holds the chain key can compute the
    /// next generation on its own.
    ///
    /// Returns `None` when the ratchet will not give up a chain key for this epoch
    /// — a destroyed chain, or a clock moved backwards past the generation's start.
    pub fn rotate(
        &mut self,
        admitted: Option<(&str, &[u8])>,
        removed: &[String],
        fresh_entropy: &[u8; crate::rekey::FRESH_ENTROPY_LEN],
        now: i64,
    ) -> Option<Rotation> {
        let mix = wire::epoch_at(now);
        let ck = self.ratchet.chain_key_at(mix, now)?;
        let seed = crate::rekey::derive_next_seed(&ck, fresh_entropy);
        let generation = self.generation + 1;
        let opening_epoch = mix;
        let admitted_id = admitted.map(|(id, _)| id);

        // The hash covers the roster this generation opens with: everyone still in,
        // plus the newcomer. Not the current roster, which does not know them yet.
        let rh = kdf::roster_hash(&self.next_roster(admitted_id, removed));
        let old_channel = self.channel.clone();

        let mut rekeys = Vec::new();
        for id in self.rekey_recipients(admitted_id) {
            let epk: Vec<u8> = match admitted {
                Some((aid, epk)) if aid == id => epk.to_vec(),
                _ => b64::decode(&self.roster.get(&id)?.epk)?,
            };
            let body = crate::rekey::build_rekey(
                &self.identity,
                &epk,
                &id,
                &old_channel,
                "",
                generation,
                opening_epoch,
                mix,
                0,
                &rh,
                removed,
                fresh_entropy,
                &seed,
            )?;
            rekeys.push(self.seal(&body, now)?);
        }

        self.adopt(generation, opening_epoch, &seed, removed, now);
        Some(Rotation {
            rekeys,
            seed,
            generation,
            opening_epoch,
            channel: self.channel.clone(),
        })
    }

    /// Mark a member as confirmed in person.
    pub fn mark_verified(&mut self, member: &str) {
        self.roster.mark_verified(member);
    }

    /// Remove a member locally, without a re-key.
    ///
    /// Only ever called when this device itself is removed, which is signalled by
    /// a re-key that does not include it.
    pub fn note_removed(&mut self, member: &str) {
        if let Some(s) = self.members.get_mut(member) {
            s.removed = true;
        }
    }

    /// Read a whole feed.
    ///
    /// The roster is snapshotted first and every post is judged against that
    /// snapshot, so a post cannot admit its own author into the state that decides
    /// whether the post was from a member.
    pub fn ingest_feed(&mut self, feed: &wire::Feed, now: i64) -> Vec<Event> {
        let before = self.roster.clone();
        let mut events = Vec::new();
        for member in &feed.members {
            for point in &member.points {
                let post = point.to_post(member);
                match self.ingest(&post, &before, now) {
                    Ok(mut e) => events.append(&mut e),
                    Err(Reject::KeyChanged) => {
                        events.push(Event::KeyChanged { member: post.m.clone() })
                    }
                    Err(_) => {}
                }
            }
        }
        // The chain is brought into line with the clock *after* the backlog is
        // read, never before: trimming first can drop a key a re-key sitting in
        // the relay still needs.
        let _ = self.ratchet.sync_to_clock(now);
        events
    }

    /// The roster hash a re-key from this device would expect.
    pub fn expected_roster_hash(&self) -> String {
        self.roster.roster_hash(self.identity.member_id(), self.identity.member_id())
    }

    /// The member ids a re-key from this device should expect to be left with.
    ///
    /// Everyone currently held, minus the removals, plus the newcomer, plus *this
    /// device*. The last one is the subtle half: a device is not asked to wrap a
    /// seed to itself, so it would otherwise compute a roster that excludes the
    /// sender while every recipient's includes them, and the hashes would never
    /// agree.
    pub fn next_roster(&self, admitted: Option<&str>, removed: &[String]) -> Vec<String> {
        let mut ids: Vec<String> = self
            .roster
            .iter()
            .map(|m| m.member_id.clone())
            .filter(|id| id != self.identity.member_id())
            .collect();
        for r in removed {
            ids.retain(|id| id != r);
        }
        if let Some(a) = admitted
            && !ids.iter().any(|id| id == a)
        {
            ids.push(a.to_string());
        }
        if !ids.iter().any(|id| id == self.identity.member_id()) {
            ids.push(self.identity.member_id().to_string());
        }
        ids.sort();
        ids
    }

    /// Every member this device has to wrap a fresh seed to.
    pub fn rekey_recipients(&self, admitted: Option<&str>) -> Vec<String> {
        let mut ids: Vec<String> = self
            .roster
            .iter()
            .map(|m| m.member_id.clone())
            .filter(|id| id != self.identity.member_id())
            .collect();
        if let Some(a) = admitted
            && !ids.iter().any(|id| id == a)
        {
            ids.push(a.to_string());
        }
        ids.sort();
        ids.dedup();
        ids
    }
}

/// Convenience: build a `Who` for this device.
pub fn me(
    identity: &Identity,
    name: &str,
    emoji: &str,
    battery: f64,
    mode: ShareMode,
) -> Who {
    Who::new(name, emoji, identity.hue() as i64, battery, mode, "")
}

/// The relay's cap, re-exported so a UI can say "your circle is full" without
/// reaching into `wire`.
pub const CIRCLE_CAP: usize = MEMBER_CAP;
