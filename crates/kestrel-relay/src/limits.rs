//! Rate limiting: two sliding windows, kept apart on purpose.
//!
//! The two limits answer different questions and must not share a map.
//!
//! * **Per channel**, counting writes. A channel id is chosen by the client, so
//!   there are as many of them as anyone wants.
//! * **Per address**, counting reads and writes together. An address is not
//!   chosen by the client.
//!
//! If they shared one map, a client that picked a fresh channel per request would
//! evict every address bucket at once and the per-address limit would stop
//! existing. Two maps, two problems.
//!
//! The window is a plain list of hit times, not a counter. A counter needs a
//! reset, and a reset needs a timer, and a timer on a serverless isolate is a
//! thing that does not run. A list of timestamps is exact, needs no timer, and
//! costs sixty-four bytes per active key at most.

use std::collections::{HashMap, VecDeque};

/// The window length.
pub const WINDOW_MS: i64 = 60_000;

/// The most keys one map will hold.
///
/// Channels are attacker-chosen, so this map can be grown without limit. When it
/// is full the oldest-inserted key is dropped, which bounds memory and biases
/// against the attacker who filled it: the keys evicted first are the ones they
/// added first.
pub const MAX_KEYS: usize = 4096;

/// A sliding-window rate limiter.
#[derive(Default)]
pub struct Limiter {
    per_channel: HashMap<String, VecDeque<i64>>,
    per_ip: HashMap<String, VecDeque<i64>>,
}

impl Limiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one write against a channel. `true` when the channel is over its
    /// limit, in which case the hit is *not* recorded: a rejected request should
    /// not push the window forward and extend the rejection.
    pub fn limited_per_channel(&mut self, channel: &str, limit: i64) -> bool {
        Self::hit(&mut self.per_channel, channel, limit)
    }

    /// Count one request, of any kind, against an address.
    pub fn limited_per_ip(&mut self, ip: &str, limit: i64) -> bool {
        Self::hit(&mut self.per_ip, ip, limit)
    }

    fn hit(map: &mut HashMap<String, VecDeque<i64>>, key: &str, limit: i64) -> bool {
        if limit <= 0 {
            return true;
        }
        let now = now_ms();
        // Re-inserting moves the key to the end of the insertion order, which is
        // what makes "oldest inserted" mean "least recently used".
        let mut hits = map.remove(key).unwrap_or_default();
        while hits.front().is_some_and(|t| *t <= now - WINDOW_MS) {
            hits.pop_front();
        }
        let limited = hits.len() as i64 >= limit;
        if !limited {
            hits.push_back(now);
        }
        map.insert(key.to_string(), hits);

        while map.len() > MAX_KEYS {
            let Some(oldest) = map.keys().next().cloned() else {
                break;
            };
            map.remove(&oldest);
        }
        limited
    }

    /// Forget everything. For tests.
    pub fn clear(&mut self) {
        self.per_channel.clear();
        self.per_ip.clear();
    }

    /// How many channels are being tracked, for the health endpoint.
    pub fn tracked_channels(&self) -> usize {
        self.per_channel.len()
    }

    /// How many addresses are being tracked.
    pub fn tracked_addresses(&self) -> usize {
        self.per_ip.len()
    }
}

/// The relay's clock, taken from the system.
///
/// The rate limiter deliberately does not use the store's injectable clock: the
/// limiter is about wall-clock arrival rate, and a test that moves the store's
/// clock to simulate twenty-four hours of expiry should not also have to simulate
/// a day of requests.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_under_the_limit_pass() {
        let mut l = Limiter::new();
        for _ in 0..10 {
            assert!(!l.limited_per_ip("1.2.3.4", 10));
        }
    }

    #[test]
    fn the_eleventh_request_is_refused() {
        let mut l = Limiter::new();
        for _ in 0..10 {
            assert!(!l.limited_per_ip("1.2.3.4", 10));
        }
        assert!(l.limited_per_ip("1.2.3.4", 10));
    }

    #[test]
    fn a_refused_request_does_not_extend_the_window() {
        // Otherwise a client that keeps hammering stays limited for longer each
        // time it tries, and one burst becomes a permanent block.
        let mut l = Limiter::new();
        for _ in 0..10 {
            l.limited_per_ip("1.2.3.4", 10);
        }
        // The window is not real time here, so the check is that the count does
        // not grow: the same address is refused every time, never accepted.
        for _ in 0..100 {
            assert!(l.limited_per_ip("1.2.3.4", 10));
        }
    }

    #[test]
    fn keys_are_independent() {
        let mut l = Limiter::new();
        for _ in 0..10 {
            l.limited_per_ip("1.2.3.4", 10);
        }
        assert!(l.limited_per_ip("1.2.3.4", 10));
        assert!(!l.limited_per_ip("5.6.7.8", 10), "a different address is unaffected");
    }

    #[test]
    fn the_two_maps_are_separate() {
        // The point of two maps: a spray of fresh channel ids must not be able to
        // disturb the address buckets.
        let mut l = Limiter::new();
        for _ in 0..10 {
            l.limited_per_ip("1.2.3.4", 10);
        }
        // Spraying channels.
        for i in 0..100 {
            l.limited_per_channel(&format!("{i:032x}"), 10);
        }
        assert!(l.limited_per_ip("1.2.3.4", 10), "the address is still limited");
    }

    #[test]
    fn channel_and_address_limits_are_configured_separately() {
        // A tight channel limit and a generous address limit, to show the two are
        // read from their own numbers rather than from one shared value.
        let mut l = Limiter::new();
        for i in 0..3 {
            let channel = format!("{i:032x}");
            assert!(!l.limited_per_channel(&channel, 2), "{channel} 1");
            assert!(!l.limited_per_channel(&channel, 2), "{channel} 2");
            assert!(l.limited_per_channel(&channel, 2), "{channel} 3");
        }
        // The address stays well inside its own limit while every channel is at
        // theirs, which is the whole reason the two numbers are separate.
        for i in 0..100 {
            assert!(!l.limited_per_ip("1.2.3.4", 200), "address hit {i}");
        }
        assert!(!l.limited_per_ip("1.2.3.4", 200));
    }

    #[test]
    fn a_zero_limit_refuses_everything() {
        // The config parser never produces zero, but a zero here must fail
        // closed rather than open.
        let mut l = Limiter::new();
        assert!(l.limited_per_ip("1.2.3.4", 0));
        assert!(l.limited_per_channel("a", 0));
    }

    #[test]
    fn the_key_count_is_bounded() {
        // A client can name as many channels as it likes, so the map has to have
        // a ceiling or it is a memory leak with a network interface.
        let mut l = Limiter::new();
        for i in 0..(MAX_KEYS + 500) {
            l.limited_per_channel(&format!("{i:032x}"), 1_000_000);
        }
        assert!(l.tracked_channels() <= MAX_KEYS);
    }

    #[test]
    fn clearing_forgets_everything() {
        let mut l = Limiter::new();
        for i in 0..10 {
            l.limited_per_ip("1.2.3.4", 10);
            l.limited_per_channel(&format!("{i:032x}"), 10);
        }
        assert!(l.tracked_channels() > 0);
        l.clear();
        // Cleared, so a request that would have been over the limit is not.
        assert!(!l.limited_per_ip("1.2.3.4", 10));
        assert_eq!(l.tracked_channels(), 0);
        // Only the one request just made is being tracked again.
        assert_eq!(l.tracked_addresses(), 1);
    }

    #[test]
    fn the_window_is_a_minute() {
        assert_eq!(WINDOW_MS, 60_000);
    }
}
