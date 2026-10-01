//! Named places, and the arrival and departure alerts they produce.
//!
//! Places live only on the phone that made them. The relay never sees a place
//! exists, because detection runs on-device against positions that already
//! arrived. That is a deliberate consequence of the design rather than a
//! limitation: a server that knew about places would learn a great deal about
//! the people in a circle without learning a single coordinate.
//!
//! Detection is a plain radius test with a dwell requirement, and the dwell is
//! the part that matters. A fix that flickers across a boundary because the
//! phone is standing still and the radio is noisy would otherwise produce an
//! arrival and a departure several times a minute, and a notification the user
//! learns to swipe away is worse than no notification.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::geo::haversine_m;

/// Longest a place name may be.
pub const MAX_PLACE_NAME: usize = 32;

/// Smallest radius a place may have, in metres. Below this, GPS noise alone
/// moves a device in and out of the place continuously.
pub const MIN_RADIUS_M: f64 = 25.0;

/// Largest radius a place may have.
pub const MAX_RADIUS_M: f64 = 20_000.0;

/// Default radius for a new place.
pub const DEFAULT_RADIUS_M: f64 = 150.0;

/// How long a device must stay inside a place before it counts as an arrival.
///
/// Two fixes, which at a typical sharing cadence is tens of seconds. Long
/// enough to ride out a noisy fix, short enough that walking into your own home
/// is not a waiting game.
pub const DEFAULT_DWELL_MS: i64 = 40_000;

/// The first two fixes count as the initial observation, so the first fix in a
/// place is not reported as a departure from nowhere.
pub const MIN_DWELL_POINTS: usize = 2;

/// A named place.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Place {
    /// Stable local identifier. Not a key: it is a local handle, and no other
    /// device ever sees it.
    pub id: String,
    pub name: String,
    pub lat: f64,
    pub lon: f64,
    pub radius_m: f64,
    /// How long inside counts as an arrival.
    pub dwell_ms: i64,
    /// Whether this device wants to hear about this place at all.
    pub notify: bool,
}

impl Place {
    /// A new place, with the name clamped and the radius brought into range.
    pub fn new(id: impl Into<String>, name: &str, lat: f64, lon: f64) -> Self {
        Self {
            id: id.into(),
            name: clamp_name(name),
            lat,
            lon,
            radius_m: DEFAULT_RADIUS_M,
            dwell_ms: DEFAULT_DWELL_MS,
            notify: true,
        }
    }

    pub fn with_radius(mut self, metres: f64) -> Self {
        self.radius_m = metres.clamp(MIN_RADIUS_M, MAX_RADIUS_M);
        self
    }

    pub fn renamed(mut self, name: &str) -> Self {
        self.name = clamp_name(name);
        self
    }

    /// Whether a position is inside this place.
    ///
    /// The radius plus the fix's own accuracy, so a fix that is only uncertain
    /// to within its error bar does not flicker in and out of a boundary.
    pub fn contains(&self, lat: f64, lon: f64, accuracy_m: f64) -> bool {
        let slack = if accuracy_m.is_finite() && accuracy_m > 0.0 {
            accuracy_m.min(self.radius_m)
        } else {
            0.0
        };
        haversine_m(self.lat, self.lon, lat, lon) <= self.radius_m + slack
    }
}

fn clamp_name(s: &str) -> String {
    s.trim().chars().take(MAX_PLACE_NAME).collect()
}

/// Whether a member is inside or outside a place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Inside,
    Outside,
}

/// A crossing in progress: the side being moved to, when it began, and how many
/// consecutive fixes have agreed on it.
///
/// Kept apart from the concluded [`Watch::side`] so a flicker across a boundary
/// cannot be mistaken for a completed move, and a completed move cannot be
/// confused with a crossing that started before the last one settled.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Crossing {
    to: Side,
    since: i64,
    points: usize,
}

/// What one member is doing in one place.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Watch {
    /// The side last concluded, once there is one to conclude from.
    side: Option<Side>,
    /// A crossing not yet held long enough to conclude.
    crossing: Option<Crossing>,
}

impl Watch {
    const UNSEEN: Self = Self { side: None, crossing: None };
}

/// The places on this device, and the alerts they have produced.
///
/// State is per (member, place) rather than per place. A place holds one shared
/// watch per member, so two people at the same place are tracked independently
/// and a dwell measured for one is never mistaken for the other's.
#[derive(Debug, Clone, Default)]
pub struct Places {
    places: BTreeMap<String, Place>,
    /// Keyed by member, then by place.
    watches: BTreeMap<String, BTreeMap<String, Watch>>,
    /// The place a member was last announced as being in, so a departure is only
    /// announced from a place they were actually announced into.
    last_reported: BTreeMap<String, Option<Place>>,
}

/// What a place did, for the UI and for a notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Alert {
    Arrived { member: String, place: String },
    Left { member: String, place: String },
}

impl Alert {
    pub fn member(&self) -> &str {
        match self {
            Alert::Arrived { member, .. } | Alert::Left { member, .. } => member,
        }
    }
}

impl Places {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace a place. Replacing keeps any existing watch state, so
    /// renaming a place does not re-announce the member who is standing in it.
    pub fn put(&mut self, place: Place) {
        // A different radius is a different question, so every pending crossing
        // for this place is discarded rather than inherited.
        if self.places.get(&place.id).is_some_and(|old| old.radius_m != place.radius_m) {
            for watches in self.watches.values_mut() {
                watches.insert(place.id.clone(), Watch::UNSEEN);
            }
        }
        self.places.insert(place.id.clone(), place);
    }

    pub fn remove(&mut self, id: &str) -> bool {
        if self.places.remove(id).is_none() {
            return false;
        }
        for watches in self.watches.values_mut() {
            watches.remove(id);
        }
        true
    }

    pub fn get(&self, id: &str) -> Option<&Place> {
        self.places.get(id)
    }

    /// Every place, in name order so a list does not reshuffle between launches.
    pub fn all(&self) -> Vec<&Place> {
        let mut v: Vec<&Place> = self.places.values().collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    pub fn len(&self) -> usize {
        self.places.len()
    }

    pub fn is_empty(&self) -> bool {
        self.places.is_empty()
    }

    /// Feed one member's position, and get back any arrival or departure.
    ///
    /// This is the whole of the detection logic. It runs on the device that
    /// received the position, so a place is never announced by anyone who does
    /// not already have the position.
    pub fn observe(
        &mut self,
        member: &str,
        lat: f64,
        lon: f64,
        accuracy_m: f64,
        now: i64,
    ) -> Vec<Alert> {
        if self.places.is_empty() {
            return Vec::new();
        }
        let mut alerts = Vec::new();
        let ids: Vec<String> = self.places.keys().cloned().collect();

        for id in ids {
            let place = self.places[&id].clone();
            let side = if place.contains(lat, lon, accuracy_m) {
                Side::Inside
            } else {
                Side::Outside
            };

            let watch = self
                .watches
                .entry(member.to_string())
                .or_default()
                .entry(id.clone())
                .or_insert(Watch::UNSEEN);

            // The dwell is measured from the start of the crossing, not from the
            // most recent fix: a side that keeps flipping keeps restarting its own
            // clock and so never concludes.
            match watch.side {
                None => {
                    // The first observation of this member at this place, or the
                    // first after a radius change. Recorded silently: a member
                    // already standing in a place when the app opened has not just
                    // arrived.
                    watch.side = Some(side);
                    watch.crossing = None;
                    if side == Side::Inside {
                        self.last_reported.insert(member.to_string(), Some(place.clone()));
                    }
                }
                Some(current) if current == side => {
                    // Steady. Any crossing was resolved by the arm that concluded
                    // it.
                    watch.crossing = None;
                }
                Some(_) => {
                    let c = match watch.crossing {
                        Some(c) if c.to == side => Crossing { points: c.points + 1, ..c },
                        _ => Crossing { to: side, since: now, points: 1 },
                    };
                    let held = now.saturating_sub(c.since) >= place.dwell_ms;
                    if c.points >= MIN_DWELL_POINTS && held {
                        watch.side = Some(side);
                        watch.crossing = None;
                        match side {
                            Side::Inside => {
                                if place.notify {
                                    alerts.push(Alert::Arrived {
                                        member: member.to_string(),
                                        place: place.name.clone(),
                                    });
                                }
                                self.last_reported
                                    .insert(member.to_string(), Some(place.clone()));
                            }
                            Side::Outside => {
                                // Only announce a departure from a place this
                                // member was actually announced as being in.
                                let previous = self
                                    .last_reported
                                    .get(member)
                                    .cloned()
                                    .flatten()
                                    .filter(|pl| pl.id == place.id);
                                if let Some(previous) = previous {
                                    if previous.notify {
                                        alerts.push(Alert::Left {
                                            member: member.to_string(),
                                            place: previous.name,
                                        });
                                    }
                                    self.last_reported.insert(member.to_string(), None);
                                }
                            }
                        }
                    } else {
                        watch.crossing = Some(c);
                    }
                }
            }
        }

        alerts
    }

    /// Forget a member's state, when they are removed from the circle.
    pub fn forget(&mut self, member: &str) {
        self.last_reported.remove(member);
        self.watches.remove(member);
    }

    /// The place a member was last announced as being in, if any.
    pub fn reported_place(&self, member: &str) -> Option<&Place> {
        self.last_reported.get(member).and_then(|p| p.as_ref())
    }

    /// Stop watching every place, keeping the definitions.
    ///
    /// Used by a panic wipe, and by the app lock: the definitions are not
    /// secret, but their presence should not outlive a deliberate reset.
    pub fn clear_state(&mut self) {
        self.watches.clear();
        self.last_reported.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: (f64, f64) = (44.98, -93.27);

    fn places() -> Places {
        let mut p = Places::new();
        p.put(Place::new("home", "Home", HOME.0, HOME.1).with_radius(150.0));
        p
    }

    #[test]
    fn a_place_clamps_its_name() {
        let p = Place::new("x", &"n".repeat(100), 0.0, 0.0);
        assert_eq!(p.name.chars().count(), MAX_PLACE_NAME);
        assert_eq!(p.radius_m, DEFAULT_RADIUS_M);
        assert_eq!(p.dwell_ms, DEFAULT_DWELL_MS);
        assert!(p.notify);
    }

    #[test]
    fn a_name_is_trimmed_and_may_be_empty() {
        assert_eq!(Place::new("x", "  School  ", 0.0, 0.0).name, "School");
        assert_eq!(Place::new("x", "", 0.0, 0.0).name, "");
    }

    #[test]
    fn a_radius_is_brought_into_a_sane_range() {
        assert_eq!(Place::new("x", "a", 0.0, 0.0).with_radius(1.0).radius_m, MIN_RADIUS_M);
        assert_eq!(Place::new("x", "a", 0.0, 0.0).with_radius(1e9).radius_m, MAX_RADIUS_M);
        assert_eq!(Place::new("x", "a", 0.0, 0.0).with_radius(300.0).radius_m, 300.0);
    }

    #[test]
    fn a_position_inside_the_radius_is_contained() {
        let p = Place::new("home", "Home", HOME.0, HOME.1).with_radius(150.0);
        assert!(p.contains(HOME.0, HOME.1, 0.0));
        assert!(p.contains(HOME.0 + 0.0005, HOME.1, 0.0), "about 55 m away");
        assert!(!p.contains(HOME.0 + 0.01, HOME.1, 0.0), "about 1.1 km away");
    }

    #[test]
    fn an_uncertain_fix_is_given_the_slack_its_accuracy_claims() {
        // A fix that is only accurate to 200 m should not be judged against a
        // 150 m boundary as if it were exact.
        let p = Place::new("home", "Home", HOME.0, HOME.1).with_radius(150.0);
        let near = HOME.0 + 0.002; // about 220 m
        assert!(!p.contains(near, HOME.1, 10.0), "an accurate fix is outside");
        assert!(p.contains(near, HOME.1, 200.0), "an uncertain one is inside");
    }

    #[test]
    fn the_slack_never_exceeds_the_radius() {
        // A wildly inaccurate fix must not turn every place into a match.
        let p = Place::new("home", "Home", HOME.0, HOME.1).with_radius(150.0);
        let far = HOME.0 + 1.0;
        assert!(!p.contains(far, HOME.1, 100_000.0));
    }

    #[test]
    fn a_bad_accuracy_does_not_widen_the_test() {
        let p = Place::new("home", "Home", HOME.0, HOME.1).with_radius(150.0);
        assert!(!p.contains(HOME.0 + 0.01, HOME.1, f64::NAN));
        assert!(!p.contains(HOME.0 + 0.01, HOME.1, -5.0));
    }

    #[test]
    fn the_first_observation_of_a_member_is_not_an_arrival() {
        let mut p = places();
        // Someone already standing in Home when the app opened has not arrived.
        assert!(p.observe("A", HOME.0, HOME.1, 5.0, 1_000).is_empty());
        assert!(p.reported_place("A").is_some(), "but the state is known");
    }

    #[test]
    fn crossing_in_and_holding_is_an_arrival() {
        let mut p = places();
        p.observe("A", HOME.0 + 0.01, HOME.1, 5.0, 1_000); // outside
        // One fix inside is not enough: the dwell requirement.
        assert!(p.observe("A", HOME.0, HOME.1, 5.0, 2_000).is_empty());
        let alerts = p.observe("A", HOME.0, HOME.1, 5.0, 2_000 + DEFAULT_DWELL_MS);
        assert_eq!(
            alerts,
            vec![Alert::Arrived { member: "A".into(), place: "Home".into() }]
        );
    }

    #[test]
    fn a_single_noisy_fix_at_the_boundary_is_neither_arrival_nor_departure() {
        // The case the dwell requirement exists for: a phone standing still with
        // a noisy radio, flickering across a boundary.
        let mut p = places();
        p.observe("A", HOME.0, HOME.1, 5.0, 1_000); // inside
        for i in 1..20 {
            // Alternate across the boundary, but each time for less than the
            // dwell period.
            let lat = if i % 2 == 0 { HOME.0 } else { HOME.0 + 0.01 };
            assert!(
                p.observe("A", lat, HOME.1, 5.0, 2_000 + i * 1_000).is_empty(),
                "flicker at step {i} produced an alert"
            );
        }
    }

    #[test]
    fn crossing_out_and_holding_is_a_departure() {
        let mut p = places();
        p.observe("A", HOME.0, HOME.1, 5.0, 1_000);
        p.observe("A", HOME.0, HOME.1, 5.0, 1_000 + DEFAULT_DWELL_MS);
        assert!(
            p.observe("A", HOME.0 + 0.01, HOME.1, 5.0, 2_000 + DEFAULT_DWELL_MS).is_empty()
        );
        let alerts =
            p.observe("A", HOME.0 + 0.01, HOME.1, 5.0, 2_000 + 2 * DEFAULT_DWELL_MS);
        assert_eq!(alerts, vec![Alert::Left { member: "A".into(), place: "Home".into() }]);
    }

    #[test]
    fn staying_put_produces_nothing() {
        let mut p = places();
        p.observe("A", HOME.0, HOME.1, 5.0, 1_000);
        p.observe("A", HOME.0, HOME.1, 5.0, 2_000);
        for i in 3..50 {
            assert!(p.observe("A", HOME.0, HOME.1, 5.0, i * 1_000).is_empty());
        }
    }

    #[test]
    fn a_silent_place_produces_no_alert_but_tracks_state() {
        let mut p = places();
        let mut quiet = Place::new("work", "Work", HOME.0, HOME.1).with_radius(150.0);
        quiet.notify = false;
        p.put(quiet);
        p.observe("A", HOME.0, HOME.1, 5.0, 1_000);
        p.observe("A", HOME.0, HOME.1, 5.0, 2_000);
        assert!(
            p.observe("A", HOME.0, HOME.1, 5.0, 2_000 + DEFAULT_DWELL_MS).is_empty(),
            "a place with notifications off stays quiet"
        );
    }

    #[test]
    fn places_are_independent() {
        // A member established at Home, who then moves to Work, produces a
        // departure and an arrival as separate events. Each place reaches its own
        // conclusion on its own schedule, so both alerts need more than one dwell
        // period to appear.
        let mut p = places();
        p.put(Place::new("work", "Work", HOME.0 + 0.05, HOME.1).with_radius(100.0));

        p.observe("A", HOME.0, HOME.1, 5.0, 1_000); // at Home, established
        let work = HOME.0 + 0.05;
        let cross = 2_000i64;
        let mut all = Vec::new();
        // Four settles: two dwell periods for each of the two places.
        for step in 1..=4 {
            all.extend(p.observe("A", work, HOME.1, 5.0, cross + step * DEFAULT_DWELL_MS));
        }
        assert!(
            all.contains(&Alert::Left { member: "A".into(), place: "Home".into() }),
            "a departure from Home, got {all:?}"
        );
        assert!(
            all.contains(&Alert::Arrived { member: "A".into(), place: "Work".into() }),
            "an arrival at Work, got {all:?}"
        );
    }

    #[test]
    fn leaving_a_place_you_were_never_announced_in_is_silent() {
        let mut p = places();
        p.observe("A", HOME.0 + 0.01, HOME.1, 5.0, 1_000); // outside, established
        for step in 1..=4 {
            assert!(
                p.observe("A", HOME.0 + 0.05, HOME.1, 5.0, 1_000 + step * DEFAULT_DWELL_MS)
                    .is_empty()
            );
        }
    }

    #[test]
    fn members_are_tracked_separately() {
        // State is per (member, place), so A's steady presence at Home never
        // advances or concludes B's own arrival. The dwell also needs two
        // agreeing fixes, one of them a full dwell period after the crossing.
        let mut p = places();
        p.observe("A", HOME.0, HOME.1, 5.0, 1_000);
        p.observe("B", HOME.0 + 0.01, HOME.1, 5.0, 1_000);

        // A is already established inside, so further fixes are silent.
        assert!(p.observe("A", HOME.0, HOME.1, 5.0, 2_000).is_empty());
        assert!(p.observe("A", HOME.0, HOME.1, 5.0, 3_000).is_empty());

        // B crosses in. The fix at 4s starts the dwell; the next one, a full
        // dwell period later, is the second agreeing fix and concludes it.
        assert!(p.observe("B", HOME.0, HOME.1, 5.0, 4_000).is_empty());
        let alerts = p.observe("B", HOME.0, HOME.1, 5.0, 4_000 + DEFAULT_DWELL_MS);
        assert_eq!(
            alerts,
            vec![Alert::Arrived { member: "B".into(), place: "Home".into() }]
        );
        // And having arrived, B is silent.
        assert!(
            p.observe("B", HOME.0, HOME.1, 5.0, 4_000 + 2 * DEFAULT_DWELL_MS).is_empty()
        );

        // And A's steady state is unaffected by B's arrival.
        assert!(
            p.observe("A", HOME.0, HOME.1, 5.0, 5_000 + 3 * DEFAULT_DWELL_MS).is_empty()
        );
    }

    #[test]
    fn renaming_a_place_does_not_re_announce_anybody() {
        let mut p = places();
        p.observe("A", HOME.0, HOME.1, 5.0, 1_000);
        p.observe("A", HOME.0, HOME.1, 5.0, 1_000 + DEFAULT_DWELL_MS);
        // Rename it while they are standing in it.
        let home = p.get("home").unwrap().clone().renamed("Home, really");
        p.put(home);
        assert_eq!(p.get("home").unwrap().name, "Home, really");
        assert!(p.observe("A", HOME.0, HOME.1, 5.0, 2_000 + DEFAULT_DWELL_MS).is_empty());
    }

    #[test]
    fn changing_a_radius_restarts_the_dwell() {
        // A different radius is a different question, so the pending arrival
        // does not carry over and fire on stale evidence.
        let mut p = places();
        p.observe("A", HOME.0 + 0.01, HOME.1, 5.0, 1_000);
        p.observe("A", HOME.0, HOME.1, 5.0, 2_000);
        let home = p.get("home").unwrap().clone().with_radius(400.0);
        p.put(home);
        assert!(p.observe("A", HOME.0, HOME.1, 5.0, 2_000 + DEFAULT_DWELL_MS).is_empty());
    }

    #[test]
    fn a_place_can_be_removed() {
        let mut p = places();
        assert!(p.remove("home"));
        assert!(!p.remove("home"));
        assert!(p.is_empty());
        // And a removed place stops producing alerts.
        p.observe("A", HOME.0, HOME.1, 5.0, 1_000);
        assert!(p.observe("A", HOME.0, HOME.1, 5.0, 2_000).is_empty());
    }

    #[test]
    fn places_are_listed_in_name_order() {
        let mut p = Places::new();
        p.put(Place::new("z", "Zoo", 0.0, 0.0));
        p.put(Place::new("a", "Apartment", 0.0, 0.0));
        p.put(Place::new("h", "Home", 0.0, 0.0));
        let names: Vec<&str> = p.all().iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec!["Apartment", "Home", "Zoo"]);
    }

    #[test]
    fn no_places_means_no_alerts_and_no_work() {
        let mut p = Places::new();
        for i in 0..10 {
            assert!(p.observe("A", HOME.0, HOME.1, 5.0, i * 1_000).is_empty());
        }
    }

    #[test]
    fn a_removed_member_is_forgotten() {
        let mut p = places();
        p.observe("A", HOME.0, HOME.1, 5.0, 1_000);
        assert!(p.reported_place("A").is_some());
        p.forget("A");
        assert!(p.reported_place("A").is_none());
    }

    #[test]
    fn clearing_state_keeps_the_definitions_but_forgets_the_positions() {
        let mut p = places();
        p.observe("A", HOME.0, HOME.1, 5.0, 1_000);
        p.clear_state();
        assert_eq!(p.len(), 1, "the place itself is still defined");
        assert!(p.reported_place("A").is_none());
        // And the next fix is treated as a first observation, not an arrival.
        assert!(p.observe("A", HOME.0, HOME.1, 5.0, 2_000).is_empty());
    }

    #[test]
    fn a_place_survives_a_save_and_load() {
        let mut p = places();
        p.put(Place::new("school", "School", 44.9, -93.1).with_radius(250.0));
        let json = serde_json::to_string(p.get("school").unwrap()).unwrap();
        let back: Place = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "School");
        assert_eq!(back.radius_m, 250.0);
        assert!(back.notify);
    }
}
