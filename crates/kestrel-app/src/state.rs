//! What the app knows and where it is, in one place.
//!
//! Deliberately not in the Android module. The app's state, the screen it is on
//! and the permission queue are all worth testing, and none of them needs a
//! phone — so they live here where the test suite can reach them, and the
//! Android module is left with the boundary crossing and nothing else.
//!
//! One shared instance for the whole process, because the activity and the
//! foreground service are separate Android components that must agree. A service
//! with its own copy of the circle would be a second source of truth, and that is
//! how a share ends up posting from a generation the user has already left.

use std::sync::{Arc, Mutex};

use crate::{handshake::Handshake, permissions::Permissions};

/// A position, as the platform reports it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Fix {
    pub lat: f64,
    pub lon: f64,
    pub acc: f64,
    pub ts: i64,
    pub battery: f64,
}

impl Fix {
    /// Whether this fix is usable.
    ///
    /// A zero fix is what the platform reports before it has one, and drawing it
    /// would put a marker in the Gulf of Guinea.
    pub fn is_usable(&self) -> bool {
        self.lat.is_finite()
            && self.lon.is_finite()
            && (self.lat != 0.0 || self.lon != 0.0)
            && (-90.0..=90.0).contains(&self.lat)
            && (-180.0..=180.0).contains(&self.lon)
    }
}

/// Which screen is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Screen {
    /// No circle yet: create one or join one.
    #[default]
    Welcome,
    /// The map.
    Map,
    /// Joining, with an invite code.
    Join,
    /// A pending join request, with a safety number to compare.
    Review,
    /// Settings.
    Settings,
    /// The app is locked and wants a passcode.
    Locked,
    /// The app lock was wiped by a duress passcode.
    Wiped,
}

impl Screen {
    /// The title, in the app's own words.
    pub fn title(self) -> &'static str {
        match self {
            Screen::Welcome => "Kestrel",
            Screen::Map => "Map",
            Screen::Join => "Join a circle",
            Screen::Review => "Someone is asking to join",
            Screen::Settings => "Settings",
            Screen::Locked => "Locked",
            Screen::Wiped => "Nothing here",
        }
    }

    /// Whether the back gesture should close the screen rather than leave the app.
    pub fn is_overlay(self) -> bool {
        matches!(self, Screen::Join | Screen::Review | Screen::Settings)
    }
}

impl Default for crate::map::Basemap {
    /// Dark, because this is opened at night by people who are not looking for a
    /// white screen.
    fn default() -> Self {
        crate::map::Basemap::Dark
    }
}

/// What the UI reads.
#[derive(Default)]
pub struct AppState {
    /// Which screen is showing.
    pub screen: Screen,
    /// The display name this device shares.
    pub name: String,
    /// Whether the device is sharing.
    pub sharing: bool,
    /// The last line of status text.
    pub status: String,
    /// A message for the user, cleared when acknowledged.
    pub notice: Option<String>,
    /// The basemap in use.
    pub basemap: crate::map::Basemap,
    /// Whether the device is sharing coarsely.
    pub coarse: bool,
    /// Whether the app is in the background, which is when sharing has to be a
    /// service rather than a foreground task.
    pub background: bool,
    /// An invite code being typed in.
    pub invite: Option<String>,
    /// An invite code scanned from a QR code.
    pub scanned: Option<String>,
    /// The safety number of a pending join request, and the name beside it.
    pub pending_name: Option<(String, String)>,
    /// Where the map is looking. Restored between runs so the app opens where the user
    /// left it rather than in the middle of the ocean.
    pub camera: crate::map::Camera,
    /// The language the app is in.
    pub language: crate::strings::Language,
    /// Which share screen is up, if any.
    pub share_sheet: Option<ShareSheet>,
    /// A field the user is typing into. Kept in the state rather than a widget's memory
    /// so a rotation does not lose it.
    pub typing: String,
    /// egui's zoom factor for the pinch in progress last frame. Zero when there is not a
    /// pinch, which is what makes the next frame's ratio the whole gesture.
    pub pinch_spread: f32,
    /// The join handshake in progress, if any.
    ///
    /// Here rather than in the engine because it *is* UI state: the review screen
    /// exists because of it, and a handshake the screens cannot see would be one
    /// that changes the screen from a thread nobody can follow.
    pub handshake: Handshake,
}

/// The sheet at the bottom of the map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareSheet {
    /// Invite someone, with the user's own code.
    Invite,
    /// Join someone, with their code.
    Join,
    /// Settings.
    Settings,
    /// The places this device watches.
    Places,
    /// Create the help beacon.
    Help,
    /// Turn the app lock on or off.
    Lock,
}

impl AppState {
    /// Set the screen, and say so, so a caller cannot change it silently.
    pub fn go(&mut self, screen: Screen) {
        self.screen = screen;
    }

    /// Show a message.
    pub fn tell(&mut self, message: impl Into<String>) {
        self.notice = Some(message.into());
    }

    /// Take the pending message, if there is one.
    pub fn read_notice(&mut self) -> Option<String> {
        self.notice.take()
    }
}

/// Everything the UI and the service share.
pub struct Shared {
    /// What the UI reads.
    pub state: Mutex<AppState>,
    /// The circles this device holds.
    pub circles: Mutex<Vec<kestrel_core::session::Circle>>,
    /// What this device knows about its own permissions.
    pub permissions: Mutex<Permissions>,
    /// The activity, when one exists. `None` while the service runs with the app
    /// closed, which is the whole reason the service does not depend on it.
    pub activity: Mutex<i64>,
    /// A scanned code waiting for the UI to read.
    pub scan: Mutex<Option<String>>,
    /// The newest fix, from the service.
    pub fix: Mutex<Option<Fix>>,
}

impl Default for Shared {
    fn default() -> Self {
        Self {
            state: Mutex::new(AppState::default()),
            circles: Mutex::new(Vec::new()),
            permissions: Mutex::new(Permissions::default()),
            activity: Mutex::new(0),
            scan: Mutex::new(None),
            fix: Mutex::new(None),
        }
    }
}

impl Shared {
    /// Whether a circle is held.
    ///
    /// A `Circle` holds the device's key material, so it is not clonable and is
    /// never handed out. Everything that needs one locks the field for the length
    /// of its work, which is short and never spans a frame.
    pub fn has_circle(&self) -> bool {
        self.circles.lock().map(|c| !c.is_empty()).unwrap_or(false)
    }

    /// How many circles are held.
    pub fn circle_count(&self) -> usize {
        self.circles.lock().map(|c| c.len()).unwrap_or(0)
    }

    /// Record a position, and say whether it was any use.
    pub fn record_fix(&self, fix: Fix) -> bool {
        if !fix.is_usable() {
            return false;
        }
        match self.fix.lock() {
            Ok(mut slot) => {
                // Older fixes are dropped rather than kept: a service that is
                // delivering fixes out of order must not rewind the map.
                if slot.map(|f| fix.ts < f.ts).unwrap_or(false) {
                    return false;
                }
                *slot = Some(fix);
                true
            }
            Err(_) => false,
        }
    }

    /// The newest position, if there is one.
    pub fn newest_fix(&self) -> Option<Fix> {
        self.fix.lock().ok().and_then(|f| *f)
    }

    /// Build this frame's map, holding the circle's lock for the duration.
    ///
    /// A `Circle` holds key material and is deliberately not `Clone`, so a caller that
    /// needs to read it locks the field for the length of its work instead of taking a
    /// copy. This is that, in one place, so no screen has to be trusted to remember.
    pub fn map_frame(
        &self,
        camera: crate::map::Camera,
        basemap: crate::map::Basemap,
        viewport_px: (f64, f64),
        now: i64,
        self_id: &str,
    ) -> Option<crate::map::Frame> {
        let circles = self.circles.lock().ok()?;
        let circle = circles.first()?;
        Some(crate::map::frame(circle, &camera, basemap, viewport_px, now, self_id))
    }

    /// This device's channel, read out under the lock.
    pub fn channel(&self) -> Option<String> {
        let circles = self.circles.lock().ok()?;
        circles.first().map(|c| c.channel().to_string())
    }

    /// Run a closure over the active circle, under the lock.
    ///
    /// The only way to reach a `Circle` at all. `f` is short and must not block: it is on
    /// the frame path.
    pub fn with_circle<T>(
        &self,
        f: impl FnOnce(&mut kestrel_core::session::Circle) -> T,
    ) -> Option<T> {
        let mut circles = self.circles.lock().ok()?;
        circles.first_mut().map(f)
    }

    /// Hand a scanned code to the UI.
    pub fn offer_scan(&self, text: String) {
        if let Ok(mut slot) = self.scan.lock() {
            *slot = Some(text);
        }
    }

    /// Take a scanned code, if one is waiting.
    pub fn take_scan(&self) -> Option<String> {
        self.scan.lock().ok().and_then(|mut s| s.take())
    }
}

static SHARED: std::sync::OnceLock<Arc<Shared>> = std::sync::OnceLock::new();

/// Install the shared state, once, before the first frame.
pub fn install(shared: Arc<Shared>) {
    let _ = SHARED.set(shared);
}

/// The shared state.
///
/// A `OnceLock` rather than a handle threaded through every JNI entry point: the
/// Java side has one activity and one service, and threading it through both
/// would mean a second global anyway, only harder to see.
///
/// If nothing has been installed yet this makes one, rather than a throwaway per
/// call. Handing out a fresh instance would be worse than useless: a service that
/// started before the activity would write its circle into a copy that the UI then
/// never sees, and the symptom would be an app that shares nothing and says it is
/// sharing.
pub fn shared() -> Arc<Shared> {
    SHARED.get_or_init(Arc::default).clone()
}

/// The wall clock, in milliseconds.
///
/// Behind a function so a test can reason about time without a test-only field
/// on the state.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_fix_is_not_a_position_in_the_gulf_of_guinea() {
        // What the platform reports before it has a location. Drawing it would
        // put a marker in the ocean and claim someone was there.
        let zero = Fix { lat: 0.0, lon: 0.0, acc: 0.0, ts: 1_000, battery: 0.5 };
        assert!(!zero.is_usable());
        let real = Fix { lat: 44.98, ..zero };
        assert!(real.is_usable());
    }

    #[test]
    fn a_fix_outside_the_world_is_refused() {
        let base = Fix { lat: 91.0, lon: 0.0, acc: 5.0, ts: 1_000, battery: 0.5 };
        assert!(!base.is_usable());
        let bad_lon = Fix { lon: 181.0, ..base };
        assert!(!bad_lon.is_usable());
        let nan = Fix { lat: f64::NAN, ..base };
        assert!(!nan.is_usable());
    }

    #[test]
    fn a_newer_fix_replaces_an_older_one_and_never_rewinds() {
        let s = Shared::default();
        let now = 10_000;
        assert!(s.record_fix(Fix { lat: 1.0, lon: 1.0, acc: 5.0, ts: now, battery: 0.5 }));
        assert_eq!(s.newest_fix().unwrap().ts, now);

        // Older: dropped. A service delivering out of order must not rewind the
        // map to where someone was an hour ago.
        assert!(!s.record_fix(Fix {
            lat: 2.0,
            lon: 2.0,
            acc: 5.0,
            ts: now - 1,
            battery: 0.5
        }));
        assert_eq!(s.newest_fix().unwrap().ts, now);

        // Newer: taken.
        assert!(s.record_fix(Fix {
            lat: 3.0,
            lon: 3.0,
            acc: 5.0,
            ts: now + 1,
            battery: 0.4
        }));
        assert_eq!(s.newest_fix().unwrap().ts, now + 1);
        assert_eq!(s.newest_fix().unwrap().battery, 0.4);
    }

    #[test]
    fn an_unusable_fix_is_not_recorded() {
        let s = Shared::default();
        assert!(!s.record_fix(Fix { lat: 0.0, lon: 0.0, acc: 0.0, ts: 1, battery: 0.0 }));
        assert!(s.newest_fix().is_none());
    }

    #[test]
    fn a_scanned_code_is_handed_over_once() {
        let s = Shared::default();
        assert!(s.take_scan().is_none());
        s.offer_scan("#j=abc".to_string());
        assert_eq!(s.take_scan().as_deref(), Some("#j=abc"));
        // A second read is empty, so a code is not joined twice by one scan.
        assert!(s.take_scan().is_none());
    }

    #[test]
    fn a_new_device_holds_no_circle() {
        let s = Shared::default();
        assert!(!s.has_circle());
        assert_eq!(s.circle_count(), 0);
    }

    #[test]
    fn an_overlay_screen_is_closed_by_the_back_gesture() {
        assert!(Screen::Settings.is_overlay());
        assert!(Screen::Join.is_overlay());
        // The map is not an overlay: backing out of it should leave, not close a
        // screen the user cannot get back to.
        assert!(!Screen::Map.is_overlay());
        assert!(!Screen::Welcome.is_overlay());
    }

    #[test]
    fn a_notice_is_read_once() {
        let mut s = AppState::default();
        s.tell("Location is off");
        assert_eq!(s.read_notice().as_deref(), Some("Location is off"));
        assert!(s.read_notice().is_none());
    }

    #[test]
    fn the_clock_is_a_sane_approximation_of_the_wall() {
        // The app's epoch maths needs a plausible value, and a zero clock would
        // make every position look like it was from 1970.
        assert!(now_ms() > 1_700_000_000_000);
    }
}
