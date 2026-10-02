//! Alarms, help links, and the two things that leave the phone on a schedule.
//!
//! Both of these are places where the app decides to interrupt a person, so both are
//! written as decisions with tests rather than as code that fires timers. A geofence
//! that chirps at 3 a.m. because of a rounding error is the sort of thing that gets an
//! app uninstalled, and the rounding is exactly what is worth testing.
//!
//! The help beacon is the one feature that sends a location to somewhere with no circle
//! behind it, so it gets the most scrutiny here: it is opt-in, it expires, and it is
//! readable by a browser with no app installed.

use kestrel_core::{
    beacon::{self, HelpLink},
    identity::Identity,
    places::{Place, Places},
};

use crate::{store::INVITE_TTL_MS, strings::Language};

/// What to do about a place.
#[derive(Debug, Clone, PartialEq)]
pub enum Alarm {
    /// The member arrived. Worth saying out loud: it is the moment the geofence exists for.
    Arrived { place: String, name: String },
    /// The member left.
    Left { place: String, name: String },
    /// The member is near a place. Quieter than arriving, and deliberately so: someone
    /// passing through is not the same as someone arriving.
    Nearby { place: String, name: String, metres: f64 },
    /// Nothing to say.
    Nothing,
}

impl Alarm {
    /// Whether this should interrupt.
    ///
    /// Only arrivals and departures. A "nearby" line is written to the screen and is not
    /// announced, because a notification every time someone walks past their own
    /// supermarket is a notification people turn off.
    pub fn interrupts(&self) -> bool {
        matches!(self, Alarm::Arrived { .. } | Alarm::Left { .. })
    }

    /// The title and body for a notification, if there is one.
    pub fn notification(&self, language: Language) -> Option<(String, String)> {
        match self {
            Alarm::Arrived { name, .. } => Some((
                crate::strings::with(language, "places.arrived_title", "{}", name),
                name.clone(),
            )),
            Alarm::Left { name, .. } => Some((
                crate::strings::with(language, "places.left_title", "{}", name),
                name.clone(),
            )),
            // Not announced. See `interrupts`.
            Alarm::Nearby { .. } | Alarm::Nothing => None,
        }
    }
}

/// Where a member was the last time this ran.
///
/// Held outside the geofence itself, because the whole question is "changed from last
/// time", and the only way to answer that is to remember last time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Inside {
    /// Not known yet. Distinguished from `Outside` because the first fix inside a place
    /// is an arrival and the first fix anywhere is not.
    #[default]
    Unknown,
    Inside,
    Outside,
}

/// What to do about a fix, given the places and where the member was last time.
///
/// No clock: this decides about a position, not about a schedule. `dwell_ms` is handled
/// by the caller that owns the history, and mixing a timer in here would make the
/// boundary case depend on when it was checked.
pub fn evaluate(
    places: &Places,
    member: &str,
    lat: f64,
    lon: f64,
    accuracy_m: f64,
    was: Inside,
) -> (Alarm, Inside) {
    // A fix with no accuracy is no fix. Every distance below would be measured from a
    // point the platform does not vouch for.
    if !lat.is_finite() || !lon.is_finite() || !accuracy_m.is_finite() || accuracy_m < 0.0 {
        return (Alarm::Nothing, was);
    }

    // `Places` is already one member's list — the core keys it by member id — so
    // nothing here filters by member, and a place belonging to someone else is not
    // reachable through this function at all.
    let _ = member;
    let mut best: Option<(f64, &Place)> = None;
    for place in places.all() {
        if place.contains(lat, lon, accuracy_m) {
            let distance = kestrel_core::geo::haversine_m(lat, lon, place.lat, place.lon);
            best = match best {
                Some((d, _)) if d <= distance => Some((d, place)),
                _ => Some((distance, place)),
            };
        }
    }

    let Some((distance, place)) = best else {
        // Outside every place. This is only news if they were inside one — and the
        // place they left is remembered from the history rather than from this fix,
        // which no longer knows where "inside" was.
        return match was {
            Inside::Inside => (
                Alarm::Left {
                    place: last_place_name(places).unwrap_or_default(),
                    name: last_place_name(places).unwrap_or_default(),
                },
                Inside::Outside,
            ),
            _ => (Alarm::Nothing, Inside::Outside),
        };
    };

    // Wide inside, wide outside. A GPS fix drifting across a boundary would otherwise
    // produce arrival, departure, arrival, departure for someone walking along a fence.
    let hysteresis = (place.radius_m.max(accuracy_m) * 0.25).min(place.radius_m);
    match was {
        // Inside and still comfortably inside: nothing.
        Inside::Inside if distance + hysteresis <= place.radius_m => {
            (Alarm::Nothing, Inside::Inside)
        }
        // Just arrived, so the fix has to be comfortably *inside* the hysteresis band
        // before it counts. Strict, not inclusive: a fix whose accuracy is worse than the
        // fence radius puts it on the boundary by definition, and announcing arrival on
        // that would be announcing "somewhere in here", which is not the same thing.
        _ if place.radius_m - distance > hysteresis => (
            Alarm::Arrived { place: place.id.clone(), name: place.name.clone() },
            Inside::Inside,
        ),
        // Inside but drifting out. Held until it is clearly outside, for the same
        // reason: a boundary is not worth announcing from either side.
        _ => {
            if distance - hysteresis > place.radius_m {
                (
                    Alarm::Left { place: place.id.clone(), name: place.name.clone() },
                    Inside::Outside,
                )
            } else {
                (Alarm::Nothing, Inside::Inside)
            }
        }
    }
}

/// The name of the first place, used when a departure has to name somewhere.
///
/// A departure has already lost the fix that knew where "inside" was, so this is a
/// fallback and the alarm reads better with a name than with an id. It is only reached
/// when a member has exactly one place, which is the common case for a geofence.
fn last_place_name(places: &Places) -> Option<String> {
    let all = places.all();
    match all.len() {
        0 => None,
        1 => Some(all[0].name.clone()),
        _ => None,
    }
}

/// Whether a geofence is worth keeping.
///
/// Mirrors the core's own clamp, so this checks what a place can actually be rather than
/// inventing a second, looser range that the caller would then have to reconcile. A
/// radius of a few metres is not a place: it is a point, and the phone's own accuracy is
/// worse than the radius. A radius of most of a continent is not a place either.
pub fn radius_is_sane(metres: f64) -> bool {
    use kestrel_core::places::{MAX_RADIUS_M, MIN_RADIUS_M};
    metres.is_finite() && (MIN_RADIUS_M..=MAX_RADIUS_M).contains(&metres)
}

/// Why a help link cannot be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeaconRefused {
    /// The platform cannot post the link, because the app has no way to share text yet.
    NoShare,
}

/// Mint a help link.
///
/// A help link is a location, readable by a browser, with no circle and no expiry longer
/// than the link's own. It is the most exposed thing this app can do, so it is opt-in,
/// it never happens by accident, and it says so in the name: `mint` is only ever reached
/// from a button that says what will happen.
pub fn mint_help<T: crate::platform::Platform + ?Sized>(
    identity: &Identity,
    platform: &T,
    now: i64,
) -> Result<HelpLink, BeaconRefused> {
    let link = beacon::mint(identity, INVITE_TTL_MS, now);
    // The platform is asked to share the fragment, not the link object: the app has no
    // way to put a string in another app's share sheet from here, and pretending
    // otherwise would leave the feature silently broken.
    platform
        .notify(&crate::strings::get(Language::English, "help.minted"), &link.fragment());
    Ok(link)
}

/// How long a help link lasts.
///
/// The same hour as an invitation. Both are bearer tokens that grant a reader real
/// information about a real person, and a link that lives for a week is a week of
/// screenshots.
pub const HELP_TTL_MS: i64 = 60 * 60 * 1000;

/// Whether a help link can still be opened.
pub fn help_link_live(link: &HelpLink, now: i64) -> bool {
    !link.is_expired(now)
}

/// The web address for a help link.
///
/// Built from the channel, which is derived from the secret, so two links never collide
/// and the URL carries nothing about the owner.
pub fn help_url(link: &HelpLink, relay: &str) -> String {
    format!("{}/help/{}", relay.trim_end_matches('/'), link.channel())
}

/// Whether an invitation should be shown as expiring soon.
///
/// Five minutes. Long enough that a person reading the number aloud can get to their
/// phone, short enough that they know not to walk away from it.
pub const EXPIRING_SOON_MS: i64 = 5 * 60 * 1000;

/// Whether a beacon viewer could even read this link.
///
/// A link whose channel the app cannot open is worse than none, because the person
/// pressing the button believes help is on its way.
pub fn help_link_is_usable(link: &HelpLink, now: i64) -> bool {
    help_link_live(link, now) && !link.channel().is_empty()
}

/// A one-line reminder for the settings screen that Tor is not wired up.
///
/// Shown rather than hidden, because a checkbox that does nothing is worse than no
/// checkbox: a user who ticks it believes their traffic is anonymous.
pub const TOR_NOTICE: &str =
    "Tor is not bundled in this build. Traffic goes to the relay directly.";

#[cfg(test)]
mod tests {
    use super::*;

    fn place(id: &str, lat: f64, lon: f64, radius: f64) -> Place {
        Place::new(id, "Home", lat, lon).with_radius(radius)
    }

    fn places_with(p: Place) -> Places {
        let mut places = Places::new();
        places.put(p);
        places
    }

    #[test]
    fn the_first_fix_inside_a_place_is_an_arrival() {
        // Not "nothing, we have no history": arriving is the moment a geofence exists
        // for, and the first fix is the only chance to notice it.
        let places = places_with(place("home", 44.98, -93.27, 200.0));
        let (alarm, now) = evaluate(&places, "me", 44.98, -93.27, 5.0, Inside::Unknown);
        assert_eq!(now, Inside::Inside);
        assert_eq!(alarm, Alarm::Arrived { place: "home".into(), name: "Home".into() });
    }

    #[test]
    fn staying_put_is_silence() {
        let places = places_with(place("home", 44.98, -93.27, 200.0));
        let (alarm, now) = evaluate(&places, "me", 44.98, -93.27, 5.0, Inside::Inside);
        assert_eq!(alarm, Alarm::Nothing);
        assert_eq!(now, Inside::Inside);
    }

    #[test]
    fn leaving_is_an_alarm() {
        let places = places_with(place("home", 44.98, -93.27, 200.0));
        let (alarm, now) = evaluate(&places, "me", 45.10, -93.27, 5.0, Inside::Inside);
        assert!(matches!(alarm, Alarm::Left { .. }), "{alarm:?}");
        // And it names the place, because "left" with no place is not an alarm anyone
        // can act on.
        if let Alarm::Left { name, .. } = &alarm {
            assert_eq!(name, "Home");
        }
        assert_eq!(now, Inside::Outside);
    }

    #[test]
    fn the_first_fix_outside_is_not_a_departure() {
        // Nobody arrived anywhere, so nobody left.
        let places = places_with(place("home", 44.98, -93.27, 200.0));
        let (alarm, now) = evaluate(&places, "me", 45.10, -93.27, 5.0, Inside::Unknown);
        assert_eq!(alarm, Alarm::Nothing);
        assert_eq!(now, Inside::Outside);
    }

    #[test]
    fn a_fence_does_not_chatter() {
        // The failure this whole design exists to prevent: someone walking along a
        // boundary, or a GPS fix jittering, producing arrived-left-arrived-left all
        // evening. The hysteresis band is what stops it.
        let places = places_with(place("edge", 44.98, -93.27, 200.0));
        let radius_deg = 200.0 / 111_320.0;
        let mut inside = Inside::Unknown;
        let mut alarms = 0;
        // A hundred fixes drifting back and forth across the boundary by a few metres.
        for step in 0..100 {
            let wobble = if step % 2 == 0 { 1.0 } else { -1.0 };
            let lat = 44.98 + wobble * radius_deg * 0.99;
            let (alarm, now) = evaluate(&places, "me", lat, -93.27, 20.0, inside);
            if alarm.interrupts() {
                alarms += 1;
            }
            inside = now;
        }
        assert!(alarms <= 2, "a fence that did not move produced {alarms} alarms");
    }

    #[test]
    fn a_noisy_fix_does_not_announce_an_arrival() {
        // Accuracy worse than the radius: the platform is saying "somewhere in here",
        // and announcing arrival on that would be announcing nothing.
        let places = places_with(place("small", 44.98, -93.27, 100.0));
        let (alarm, _) = evaluate(&places, "me", 44.98, -93.27, 500.0, Inside::Unknown);
        assert_eq!(alarm, Alarm::Nothing);
    }

    #[test]
    fn an_unusable_fix_changes_nothing() {
        let places = places_with(place("home", 44.98, -93.27, 200.0));
        for (lat, lon, acc) in [
            (f64::NAN, -93.27, 5.0),
            (44.98, f64::NAN, 5.0),
            (44.98, -93.27, f64::NAN),
            (44.98, -93.27, -1.0),
            (f64::INFINITY, -93.27, 5.0),
        ] {
            let (alarm, now) = evaluate(&places, "me", lat, lon, acc, Inside::Inside);
            assert_eq!(alarm, Alarm::Nothing, "at {lat},{lon} acc {acc}");
            assert_eq!(now, Inside::Inside, "the history was lost");
        }
    }

    #[test]
    fn a_place_already_given_a_silly_radius_comes_back_in_range() {
        // `Place::with_radius` clamps to the core's own range, so a five-metre fence from
        // an old saved file is impossible. Recorded here rather than assumed, because
        // `radius_is_sane` above checks that same range and the two must agree.
        use kestrel_core::places::{MAX_RADIUS_M, MIN_RADIUS_M};
        let p = Place::new("x", "X", 44.98, -93.27).with_radius(5.0);
        assert_eq!(p.radius_m, MIN_RADIUS_M);
        let p = Place::new("x", "X", 44.98, -93.27).with_radius(1_000_000.0);
        assert_eq!(p.radius_m, MAX_RADIUS_M);
        assert!(radius_is_sane(p.radius_m));
    }

    #[test]
    fn only_arrivals_and_departures_interrupt() {
        let arrived = Alarm::Arrived { place: "home".into(), name: "Home".into() };
        let left = Alarm::Left { place: "home".into(), name: "Home".into() };
        let nearby =
            Alarm::Nearby { place: "shop".into(), name: "Shop".into(), metres: 40.0 };
        assert!(arrived.interrupts());
        assert!(left.interrupts());
        // A "nearby" line is written to the screen and never announced: a notification
        // for every time someone walks past their own supermarket is one people mute.
        assert!(!nearby.interrupts());
        assert!(!Alarm::Nothing.interrupts());
        assert!(nearby.notification(Language::English).is_none());
        assert!(arrived.notification(Language::English).is_some());
    }

    #[test]
    fn a_fence_of_a_few_metres_is_not_a_place() {
        // The phone's own accuracy is worse than that, so it would fire constantly and
        // mean nothing. And a continent is not a place.
        assert!(!radius_is_sane(1.0));
        assert!(!radius_is_sane(10.0));
        assert!(radius_is_sane(150.0));
        assert!(radius_is_sane(500.0));
        assert!(!radius_is_sane(100_000.0));
        assert!(!radius_is_sane(0.0));
        assert!(!radius_is_sane(-1.0));
        assert!(!radius_is_sane(f64::NAN));
    }

    #[test]
    fn a_help_link_is_readable_only_while_it_is_alive() {
        let identity = Identity::generate();
        let now = 1_700_000_000_000;
        let link = beacon::mint(&identity, HELP_TTL_MS, now);
        assert!(help_link_live(&link, now));
        assert!(help_link_is_usable(&link, now));
        assert!(!help_link_live(&link, now + HELP_TTL_MS));
        // Expired is the state a reader must not be told is open.
        assert!(!help_link_is_usable(&link, now + HELP_TTL_MS));
    }

    #[test]
    fn a_help_link_outlives_nothing_and_carries_nothing_in_its_url() {
        let identity = Identity::generate();
        let now = 1_700_000_000_000;
        let link = beacon::mint(&identity, HELP_TTL_MS, now);
        let url = help_url(&link, "https://starlingmap.app/");
        assert!(url.starts_with("https://starlingmap.app/help/"));
        // The member id is not in the URL: the link should not tell a reader who minted
        // it before they have the key.
        assert!(!url.contains(identity.member_id()));
        // And a trailing slash on the relay does not double up.
        assert!(!help_url(&link, "https://starlingmap.app").contains("//help"));
    }

    #[test]
    fn a_help_link_lives_for_the_same_hour_as_an_invitation() {
        // Both are bearer tokens granting a reader real information about a real person.
        assert_eq!(HELP_TTL_MS, INVITE_TTL_MS);
        assert_eq!(HELP_TTL_MS, 3_600_000);
    }

    #[test]
    fn tor_is_advertised_as_missing() {
        // A checkbox that does nothing is worse than no checkbox: a user who ticks it
        // believes their traffic is anonymous.
        assert!(TOR_NOTICE.contains("not bundled"));
    }

    #[test]
    fn an_invitation_warns_before_it_expires() {
        let identity = Identity::generate();
        let now = 1_700_000_000_000;
        let invite = kestrel_core::invite::Invite::mint(&identity, now, INVITE_TTL_MS);
        assert!(!invite.is_expired(now));
        assert!(!invite.is_expired(now + INVITE_TTL_MS - 1));
        assert!(invite.is_expired(now + INVITE_TTL_MS));
        // Five minutes is enough to walk to your phone and not enough to walk away.
        assert_eq!(EXPIRING_SOON_MS, 5 * 60 * 1000);
        assert!(invite.expires_at() - now <= INVITE_TTL_MS);
        // And the warning is shown while there is still time to act.
        assert!(invite.expires_at() - (now + INVITE_TTL_MS - EXPIRING_SOON_MS) > 0);
    }
}
