//! The epoch chain: forward secrecy, bounded by a window the user chooses.
//!
//! A generation starts from a seed and produces one chain key per epoch, each
//! one a single hash forward from the last. Content keys come off that chain.
//! Advancing is cheap; going backwards is not, so a device that drops an old
//! chain key genuinely cannot read that epoch again — including an attacker who
//! has the device.
//!
//! Three things here are easy to get subtly wrong, and each has caused a real
//! bug in the reference implementation:
//!
//! * **The window is trimmed against the clock, not against the chain head.**
//!   Anchoring on the head lets a peer with a fast clock walk the head forward
//!   and destroy a short-window device's *current* epoch key.
//! * **The send epoch is tracked separately from the head.** The head is what
//!   peers can push forward; the send epoch is what this device encrypts in. If
//!   one value serves both, one device with a fast clock drags the whole circle
//!   forward.
//! * **A jump larger than the catch-up limit destroys the chain** rather than
//!   walking it. Walking thirty days of epochs to catch up is also a free denial
//!   of service.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{
    kdf,
    seal::ContentKey,
    wire::{
        DEFAULT_HISTORY_EPOCHS, EPOCH_MS, MAX_CATCHUP_EPOCHS, MAX_SKEW_EPOCHS, epoch_at,
    },
};

/// Named history-window settings. More epochs means more readable trail, and
/// more that a compromised device can still hand over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HistoryWindow {
    /// Ten minutes. Almost nothing survives a seizure.
    HighRisk,
    /// One hour.
    Default,
    /// Six hours.
    Longer,
    /// Everything the relay still holds, up to twenty-four.
    Full,
}

impl HistoryWindow {
    pub fn epochs(self) -> i64 {
        match self {
            HistoryWindow::HighRisk => 1,
            HistoryWindow::Default => DEFAULT_HISTORY_EPOCHS,
            HistoryWindow::Longer => 36,
            HistoryWindow::Full => 144,
        }
    }

    pub fn from_epochs(n: i64) -> Self {
        match n {
            0 | 1 => HistoryWindow::HighRisk,
            2..=11 => HistoryWindow::Default,
            12..=71 => HistoryWindow::Longer,
            _ => HistoryWindow::Full,
        }
    }
}

/// The persisted part of a chain: the oldest key still held.
///
/// Persisting the *oldest* rather than the newest is what lets a device that was
/// offline come back and still read the window the user asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub e0: i64,
    pub ck0: [u8; 32],
    pub window: i64,
}

/// Why a chain could not produce a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoKey {
    /// The epoch is before this generation opened.
    BeforeGeneration,
    /// The epoch is too far from this device's clock to be real.
    ImplausibleEpoch,
    /// The key for that epoch is no longer held.
    Forgotten,
    /// The chain head was pushed too far forward; the chain was destroyed.
    Destroyed,
}

/// One generation's epoch chain.
#[derive(Debug, Clone)]
pub struct Ratchet {
    /// The epoch this generation opened in. `chain` holds `ck` for it.
    e0: i64,
    /// Retained chain keys, by epoch.
    chain: std::collections::BTreeMap<i64, [u8; 32]>,
    /// The highest epoch whose key is held. Peers can advance this by sending
    /// messages from later epochs.
    head: i64,
    /// The epoch this device encrypts in. Follows this device's own clock and
    /// its own last send, never the head.
    sent_epoch: i64,
    /// How many epochs of history to keep.
    window: i64,
    /// Set when a catch-up jump was too large; the chain is unusable after this.
    destroyed: bool,
}

impl Ratchet {
    /// Start a generation from its seed.
    pub fn new(seed: &[u8; 32], now: i64) -> Self {
        Self::with_window(seed, now, DEFAULT_HISTORY_EPOCHS)
    }

    pub fn with_window(seed: &[u8; 32], now: i64, window: i64) -> Self {
        let e0 = epoch_at(now);
        let ck0 = kdf::chain0(seed);
        let mut chain = std::collections::BTreeMap::new();
        chain.insert(e0, ck0);
        Self {
            e0,
            chain,
            head: e0,
            sent_epoch: e0,
            window: window.max(1),
            destroyed: false,
        }
    }

    /// Restore from a persisted snapshot.
    pub fn restore(snapshot: &Snapshot, now: i64) -> Self {
        let mut chain = std::collections::BTreeMap::new();
        chain.insert(snapshot.e0, snapshot.ck0);
        Self {
            e0: snapshot.e0,
            chain,
            head: snapshot.e0,
            sent_epoch: epoch_at(now).max(snapshot.e0),
            window: snapshot.window.max(1),
            destroyed: false,
        }
    }

    /// The persisted form: the oldest retained key, so a reload can still read
    /// back to the start of the window.
    pub fn snapshot(&self) -> Snapshot {
        // The oldest entry is what a later reload needs; a generation that has
        // advanced keeps its earlier keys, so this is a real key and not a
        // recomputation.
        let (e0, ck0) = self
            .chain
            .iter()
            .next()
            .map(|(e, ck)| (*e, *ck))
            .unwrap_or((self.e0, kdf::chain0(&[0u8; 32])));
        Snapshot { e0, ck0, window: self.window }
    }

    pub fn generation_start(&self) -> i64 {
        self.e0
    }

    pub fn is_destroyed(&self) -> bool {
        self.destroyed
    }

    pub fn window(&self) -> i64 {
        self.window
    }

    /// The oldest epoch whose key is still held.
    pub fn oldest_retained(&self) -> i64 {
        self.chain.keys().next().copied().unwrap_or(self.e0)
    }

    /// The epoch this device should encrypt in.
    ///
    /// Follows this device's clock and never goes backwards below the last epoch
    /// it used, so a clock adjustment cannot cause a repeat.
    pub fn send_epoch(&self, now: i64) -> i64 {
        epoch_at(now).max(self.sent_epoch)
    }

    /// Note that a message was sent in `epoch`, so the next one is not older.
    pub fn note_sent(&mut self, epoch: i64) {
        if epoch > self.sent_epoch {
            self.sent_epoch = epoch;
        }
    }

    /// The content key for one (epoch, sender) pair, or why there is none.
    ///
    /// Exactly one key is ever returned. A caller that wants to try several
    /// epochs would be building a partitioning oracle, because GCM says only
    /// "this key or not this key", and a receiver that reports which would leak
    /// the chain.
    pub fn key_for(
        &mut self,
        epoch: i64,
        member: &str,
        now: i64,
    ) -> Result<ContentKey, NoKey> {
        if self.destroyed {
            return Err(NoKey::Destroyed);
        }
        if epoch < self.e0 {
            return Err(NoKey::BeforeGeneration);
        }
        // Bounded against this device's own clock. A message claiming a wildly
        // future epoch is either a bug or an attempt to walk the chain.
        if epoch > epoch_at(now) + MAX_SKEW_EPOCHS {
            return Err(NoKey::ImplausibleEpoch);
        }
        if epoch > self.head && !self.advance_to(epoch) {
            return Err(NoKey::Destroyed);
        }
        match self.chain.get(&epoch) {
            Some(ck) => Ok(ContentKey::new(kdf::msg_key(ck, member))),
            None => Err(NoKey::Forgotten),
        }
    }

    /// The chain key at `epoch`, for mixing a next generation's seed.
    pub fn chain_key_at(&mut self, epoch: i64, now: i64) -> Option<[u8; 32]> {
        if epoch < self.e0 || epoch > epoch_at(now) + MAX_SKEW_EPOCHS {
            return None;
        }
        if epoch > self.head {
            self.advance_to(epoch);
        }
        self.chain.get(&epoch).copied()
    }

    /// Walk the chain forward to `epoch`, one hash per step.
    ///
    /// Returns `false` if the jump exceeds the catch-up limit, in which case the
    /// chain is destroyed: a device that walks thirty days of epochs on request
    /// is a denial of service, and following a jump that large is far more
    /// likely to be an attack than a peer that was merely asleep.
    fn advance_to(&mut self, epoch: i64) -> bool {
        if epoch <= self.head {
            return true;
        }
        if epoch - self.head > MAX_CATCHUP_EPOCHS {
            self.destroy();
            return false;
        }
        let mut next_epoch = self.head;
        let mut ck = match self.chain.get(&self.head) {
            Some(c) => *c,
            None => {
                self.destroy();
                return false;
            }
        };
        while next_epoch < epoch {
            ck = kdf::chain_step(&ck);
            next_epoch += 1;
            self.chain.insert(next_epoch, ck);
        }
        self.head = epoch;
        // Trimming is bounded by `min(head, now)` in every call site, and
        // `advance_to` is reached both with and without a clock in hand, so the
        // caller trims once it has one. Leaving keys here is safe: a later
        // `sync_to_clock` or explicit `trim_to_window` collects them.
        true
    }

    /// Drop chain keys outside the window, and zeroize the ones dropped.
    ///
    /// The cut-off is `min(head, now) - window + 1`. Taking the minimum of the
    /// head and the clock is deliberate: trimming to the head alone would let a
    /// peer that pushed the head forward delete keys this device still needs.
    pub fn trim_to_window(&mut self, now: i64) {
        let reference = self.head.min(epoch_at(now));
        let keep_from = reference - self.window + 1;
        let drop: Vec<i64> =
            self.chain.keys().copied().filter(|e| *e < keep_from).collect();
        for e in drop {
            if let Some(mut ck) = self.chain.remove(&e) {
                ck.zeroize();
            }
        }
    }

    /// Bring the chain into line with the clock after a read, never before.
    ///
    /// Order matters. Trimming first and reading second can drop a key that a
    /// message sitting in the backlog needs.
    pub fn sync_to_clock(&mut self, now: i64) -> Result<(), NoKey> {
        if self.destroyed {
            return Err(NoKey::Destroyed);
        }
        let target = epoch_at(now);
        if target > self.head {
            if target - self.head > MAX_CATCHUP_EPOCHS {
                self.destroy();
                return Err(NoKey::Destroyed);
            }
            self.advance_to(target);
            if self.destroyed {
                return Err(NoKey::Destroyed);
            }
        }
        self.trim_to_window(now);
        Ok(())
    }

    /// Forget everything. The keys are zeroized, not just dropped.
    pub fn destroy(&mut self) {
        for ck in self.chain.values_mut() {
            ck.zeroize();
        }
        self.chain.clear();
        self.destroyed = true;
    }
}

impl Drop for Ratchet {
    fn drop(&mut self) {
        self.destroy();
    }
}

/// The start of the readable window: the oldest epoch whose key is held,
/// expressed as a timestamp for the feed cursor.
///
/// The feed cursor is the relay's receive time, so this is only a starting
/// point. It is the *oldest* retained epoch rather than the newest so a device
/// that was away long enough still sees the trail it missed.
pub fn window_start(ratchet: &Ratchet, now: i64) -> i64 {
    let oldest = ratchet.oldest_retained();
    (oldest.min(epoch_at(now)) * EPOCH_MS).max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [42u8; 32];
    const MEMBER: &str = "dc73c74c3f57c6ff0c2d9016c333507f";

    fn at(epoch: i64) -> i64 {
        epoch * EPOCH_MS
    }

    #[test]
    fn a_new_chain_opens_in_the_current_epoch() {
        let now = at(2980471);
        let r = Ratchet::new(&SEED, now);
        assert_eq!(r.generation_start(), 2980471);
        assert_eq!(r.oldest_retained(), 2980471);
        assert!(!r.is_destroyed());
    }

    #[test]
    fn chain0_matches_the_derivation() {
        let now = at(2980471);
        let mut r = Ratchet::new(&SEED, now);
        let key = r.key_for(2980471, MEMBER, now).unwrap();
        let expected = kdf::msg_key(&kdf::chain0(&SEED), MEMBER);
        assert_eq!(*key.as_bytes(), expected);
    }

    #[test]
    fn each_epoch_has_a_different_key() {
        let now = at(2980471);
        let mut r = Ratchet::new(&SEED, now);
        let a = r.key_for(2980471, MEMBER, now).unwrap();
        let b = r.key_for(2980472, MEMBER, now + EPOCH_MS).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn each_sender_has_a_different_key_in_one_epoch() {
        let now = at(2980471);
        let mut r = Ratchet::new(&SEED, now);
        let a = r.key_for(2980471, MEMBER, now).unwrap();
        let b = r.key_for(2980471, "cfeb6c3eedeab2f19faf80ee98930d20", now).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn an_epoch_before_the_generation_is_refused() {
        let now = at(2980471);
        let mut r = Ratchet::new(&SEED, now);
        assert_eq!(r.key_for(2980470, MEMBER, now), Err(NoKey::BeforeGeneration));
    }

    #[test]
    fn an_implausibly_future_epoch_is_refused() {
        let now = at(2980471);
        let mut r = Ratchet::new(&SEED, now);
        // Two ahead is allowed; three is not.
        assert!(r.key_for(2980473, MEMBER, now).is_ok());
        assert_eq!(r.key_for(2980474, MEMBER, now), Err(NoKey::ImplausibleEpoch));
    }

    #[test]
    fn a_large_catch_up_destroys_the_chain() {
        let now = at(2980471);
        let mut r = Ratchet::new(&SEED, now);
        let far = now + (MAX_CATCHUP_EPOCHS + 10) * EPOCH_MS;
        assert_eq!(r.key_for(epoch_at(far), MEMBER, far), Err(NoKey::Destroyed));
        assert!(r.is_destroyed());
        // A destroyed chain stays destroyed.
        assert_eq!(r.key_for(2980471, MEMBER, far), Err(NoKey::Destroyed));
    }

    #[test]
    fn a_modest_catch_up_is_followed() {
        let now = at(2980471);
        let mut r = Ratchet::new(&SEED, now);
        let later = now + 3 * EPOCH_MS;
        assert!(r.key_for(epoch_at(later), MEMBER, later).is_ok());
        assert!(!r.is_destroyed());
    }

    #[test]
    fn the_window_drops_old_keys_and_keeps_recent_ones() {
        let now = at(2980471);
        let mut r = Ratchet::with_window(&SEED, now, 6);
        // Advance ten epochs and trim.
        let later = now + 10 * EPOCH_MS;
        r.sync_to_clock(later).unwrap();
        assert_eq!(r.oldest_retained(), 2980471 + 10 - 6 + 1);
        // An epoch outside the window has no key.
        assert_eq!(r.key_for(2980471, MEMBER, later), Err(NoKey::Forgotten));
    }

    #[test]
    fn a_high_risk_window_keeps_almost_nothing() {
        let now = at(2980471);
        let mut r = Ratchet::with_window(&SEED, now, HistoryWindow::HighRisk.epochs());
        let later = now + 5 * EPOCH_MS;
        r.sync_to_clock(later).unwrap();
        assert_eq!(r.key_for(2980471, MEMBER, later), Err(NoKey::Forgotten));
    }

    #[test]
    fn trimming_is_anchored_to_the_clock_not_the_head() {
        // A peer pushes the head forward with a message from a later epoch. The
        // window must not follow it, or this device loses its current key.
        let now = at(2980471);
        let mut r = Ratchet::with_window(&SEED, now, 6);
        let head_pushed = at(2980471 + 5);
        r.key_for(2980471 + 5, MEMBER, head_pushed).unwrap();

        // The device's own clock has not moved. Trimming now must keep the
        // device's current epoch.
        r.trim_to_window(now);
        assert!(r.key_for(2980471, MEMBER, now).is_ok());
    }

    #[test]
    fn the_send_epoch_never_goes_backwards() {
        let now = at(2980471);
        let mut r = Ratchet::new(&SEED, now);
        assert_eq!(r.send_epoch(now), 2980471);
        r.note_sent(2980480);
        // A clock that jumps backwards must not rewind the send epoch.
        assert_eq!(r.send_epoch(at(2980470)), 2980480);
    }

    #[test]
    fn the_send_epoch_is_independent_of_a_pushed_head() {
        // A peer with a fast clock must not drag this device's send epoch with
        // it; the two are tracked separately for exactly this reason.
        let now = at(2980471);
        let mut r = Ratchet::new(&SEED, now);
        r.key_for(2980471 + 4, MEMBER, at(2980471 + 4)).unwrap();
        assert_eq!(r.send_epoch(now), 2980471);
    }

    #[test]
    fn a_snapshot_restores_readability_of_the_whole_window() {
        let now = at(2980471);
        let mut r = Ratchet::with_window(&SEED, now, 6);
        let later = now + 10 * EPOCH_MS;
        r.sync_to_clock(later).unwrap();
        let snap = r.snapshot();

        let mut restored = Ratchet::restore(&snap, later);
        // The oldest epoch the trimmed chain could read is still readable.
        assert!(restored.key_for(snap.e0, MEMBER, later).is_ok());
    }

    #[test]
    fn restoring_a_snapshot_reproduces_the_same_keys() {
        let now = at(2980471);
        let mut r = Ratchet::new(&SEED, now);
        let _ = &mut r;
        let snap = r.snapshot();
        let mut restored = Ratchet::restore(&snap, now);
        assert_eq!(
            *r.key_for(2980471, MEMBER, now).unwrap().as_bytes(),
            *restored.key_for(2980471, MEMBER, now).unwrap().as_bytes()
        );
    }

    #[test]
    fn history_window_names_map_to_epochs() {
        assert_eq!(HistoryWindow::HighRisk.epochs(), 1);
        assert_eq!(HistoryWindow::Default.epochs(), 6);
        assert_eq!(HistoryWindow::Longer.epochs(), 36);
        assert_eq!(HistoryWindow::Full.epochs(), 144);
        assert_eq!(HistoryWindow::from_epochs(1), HistoryWindow::HighRisk);
        assert_eq!(HistoryWindow::from_epochs(6), HistoryWindow::Default);
        assert_eq!(HistoryWindow::from_epochs(36), HistoryWindow::Longer);
        assert_eq!(HistoryWindow::from_epochs(144), HistoryWindow::Full);
    }

    #[test]
    fn window_start_is_the_oldest_retained_epoch_as_a_time() {
        let now = at(2980471);
        let r = Ratchet::new(&SEED, now);
        assert_eq!(window_start(&r, now), at(2980471));
    }

    #[test]
    fn destroying_zeroizes_and_stops_answering() {
        let now = at(2980471);
        let mut r = Ratchet::new(&SEED, now);
        r.destroy();
        assert!(r.is_destroyed());
        assert_eq!(r.key_for(2980471, MEMBER, now), Err(NoKey::Destroyed));
        assert_eq!(r.sync_to_clock(now), Err(NoKey::Destroyed));
    }

    #[test]
    fn chain_key_at_supports_mixing_a_next_generation() {
        let now = at(2980471);
        let mut r = Ratchet::new(&SEED, now);
        let ck = r.chain_key_at(2980472, now + EPOCH_MS).unwrap();
        let mut walker = Ratchet::new(&SEED, now);
        let _ = walker.key_for(2980472, MEMBER, now + EPOCH_MS);
        assert_eq!(ck, kdf::chain_step(&kdf::chain0(&SEED)));
    }
}
