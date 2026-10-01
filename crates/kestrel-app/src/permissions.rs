//! What the device knows about its own permissions, and what it should do about
//! it.
//!
//! The model is a small state machine rather than a set of booleans, because the
//! booleans are not the question. The question is: *can this device share right
//! now, and if not, what should the user be told?* A permission that is
//! "granted" and one that is "granted but approximate" are both `true` and mean
//! very different things for what a circle can see.

/// What the platform reports about one permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Grant {
    /// Not asked for yet.
    #[default]
    Unknown,
    /// Asked for, and refused.
    ///
    /// Not asked again on its own. Re-prompting for something the user has just
    /// declined is nagging, and on Android the prompt is not even shown again, so
    /// the user would tap a button and see nothing happen. The fix is offered in
    /// its place: a way to the settings app.
    Denied,
    /// Refused in a way that will not prompt again. Only the settings app can
    /// change it, so the UI has to send the user there.
    PermanentlyDenied,
    /// Granted, and precise.
    Precise,
    /// Granted, but only approximate. Android 12 lets a user pick "approximate",
    /// which is a real answer and not a lesser one: the circle sees about a
    /// kilometre, and the app must say so rather than pretending otherwise.
    Approximate,
    /// Not applicable on this version of Android.
    Unavailable,
}

impl Grant {
    /// Whether to put this in front of the user as a prompt.
    ///
    /// Only before it has ever been asked. A refusal and a block both leave the
    /// user in charge of the next step, and the app's job then is to get out of the
    /// way with a settings link rather than to ask again.
    pub fn can_ask(self) -> bool {
        self == Grant::Unknown
    }

    /// Whether the user has to be sent to the settings app to fix this.
    ///
    /// Either because the platform will not prompt again, or because the app has
    /// decided not to nag. Both cases want the same thing offered.
    pub fn can_only_be_fixed_in_settings(self) -> bool {
        self.needs_settings() || self == Grant::Denied
    }

    /// Whether the user has to go to the settings app.
    pub fn needs_settings(self) -> bool {
        matches!(self, Grant::PermanentlyDenied | Grant::Unavailable)
    }

    /// Whether sharing can work with this.
    pub fn is_usable(self) -> bool {
        matches!(self, Grant::Precise | Grant::Approximate)
    }

    /// A name for the UI.
    pub fn label(self) -> &'static str {
        match self {
            Grant::Unknown => "not asked",
            Grant::Denied => "not allowed",
            Grant::PermanentlyDenied => "blocked",
            Grant::Precise => "allowed",
            Grant::Approximate => "approximate only",
            Grant::Unavailable => "not available",
        }
    }

    /// Read the platform's report.
    ///
    /// The Java side sends a string rather than a set of booleans, because a
    /// bundle of mixed types across JNI is more code than a parse and a table.
    pub fn parse(s: &str) -> Grant {
        match s {
            "granted" => Grant::Precise,
            "approximate" => Grant::Approximate,
            "denied" => Grant::Denied,
            "permanently-denied" | "blocked" => Grant::PermanentlyDenied,
            "unavailable" => Grant::Unavailable,
            _ => Grant::Unknown,
        }
    }
}

/// The report from the platform, as a whole.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// Fine location.
    pub fine: String,
    /// Coarse location.
    pub coarse: String,
    /// Background location.
    pub background: String,
    /// Notifications.
    pub notifications: String,
    /// The camera.
    pub camera: String,
}

/// What this device holds, resolved into the questions the UI asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Permissions {
    /// Location, at whatever precision was granted.
    pub location: Grant,
    /// Location while the app is closed.
    pub background: Grant,
    /// Notifications, which the foreground service's notification needs.
    pub notifications: Grant,
    /// The camera, for scanning a code.
    pub camera: Grant,
    /// Whether the user has asked for continuous sharing.
    ///
    /// Held here rather than read from the UI, so what the app is told does not
    /// depend on which screen happens to be open, and so the answer survives the
    /// activity going away while the service keeps running.
    pub sharing: bool,
}

impl Permissions {
    /// Whether this device can share its position at all.
    pub fn can_share(&self) -> bool {
        self.location.is_usable()
    }

    /// Whether the position it can share is coarse.
    ///
    /// Separate from [`Permissions::can_share`] because the app should *offer*
    /// coarse sharing on an approximate grant rather than refuse to share at all.
    pub fn is_coarse(&self) -> bool {
        self.location == Grant::Approximate
    }

    /// Whether sharing will survive the app being closed.
    pub fn survives_background(&self) -> bool {
        self.can_share() && self.background == Grant::Precise
    }

    /// Whether the foreground service's notification will be visible.
    ///
    /// Android 13 and later will start a foreground service without showing its
    /// notification if the permission is refused, and the user would have no way
    /// to know they were being tracked. So this is a real blocker, not a cosmetic
    /// one.
    pub fn service_is_visible(&self) -> bool {
        self.notifications.is_usable()
    }

    /// The next permission to ask for, if any.
    ///
    /// Location first, because nothing works without it. Then notifications,
    /// because a share that cannot be seen is a share the user cannot stop.
    /// Then the camera, which is only needed for joining. Background location is
    /// asked for last, and on its own, because Android 11 and later ignore a
    /// request that bundles it with the foreground one.
    pub fn next_to_ask(&self) -> Option<Permission> {
        use Permission;
        if self.location.can_ask() {
            return Some(Permission::Location);
        }
        if !self.location.is_usable() {
            // Nothing else is worth asking for until this is fixed.
            return None;
        }
        if self.notifications.can_ask() {
            return Some(Permission::Notifications);
        }
        // Background before the camera: keeping a share alive with the screen off
        // is the reason the app exists, and the camera is only a convenience for
        // joining. And only once the app is already sharing — a user who has not
        // turned sharing on has not been asked whether it should keep running.
        if self.sharing() && self.background.can_ask() {
            return Some(Permission::BackgroundLocation);
        }
        if self.camera.can_ask() {
            return Some(Permission::Camera);
        }
        None
    }

    /// Whether the user has asked for continuous sharing.
    fn sharing(&self) -> bool {
        self.sharing
    }

    /// Start or stop sharing, and say whether anything changed.
    ///
    /// Separate from the platform report because this is the user's decision and
    /// not the platform's: turning sharing on has to be recorded whether or not
    /// the runtime permission changed.
    pub fn set_sharing(&mut self, sharing: bool) -> bool {
        let changed = self.sharing != sharing;
        self.sharing = sharing;
        changed
    }

    /// The one line to show under the share button.
    ///
    /// Phrased as what the user will and will not get, because "location
    /// permission denied" is not something anyone can act on.
    pub fn summary(&self) -> String {
        if !self.can_share() {
            return match self.location {
                Grant::Unknown => {
                    "Kestrel needs your location to show you on the map".to_string()
                }
                Grant::Denied | Grant::PermanentlyDenied => {
                    "Without location, nobody can see where you are".to_string()
                }
                Grant::Unavailable => "This device does not report a location".to_string(),
                _ => "Location is off".to_string(),
            };
        }
        if !self.service_is_visible() {
            return "Allow notifications, or the share cannot be shown or stopped"
                .to_string();
        }
        if self.is_coarse() {
            return "Sharing about a kilometre at a time, because that is what was allowed"
                .to_string();
        }
        if !self.survives_background() {
            return "Sharing stops when the app is closed. Allow background location to keep it going"
                .to_string();
        }
        "Sharing precisely, and keeping it on with the screen off".to_string()
    }
}

/// Fold the platform's report into this device's state.
///
/// Returns whether anything changed, so the caller can redraw once rather than on
/// every field.
pub fn apply_report(report: &Report, permissions: &mut Permissions) -> bool {
    // Fine and coarse are one permission to the user, and only the *fine* one
    // distinguishes precise from approximate: the platform reports a coarse grant
    // as "granted" too, so "coarse is granted" means approximate, not precise.
    //
    // Getting this backwards is how an app ends up telling everyone a member's
    // position is precise when it is a kilometre wide, which is the one mistake
    // this app cannot afford.
    let fine = Grant::parse(&report.fine);
    let coarse = Grant::parse(&report.coarse);
    let location = match fine {
        Grant::Precise => Grant::Precise,
        // Fine refused, coarse held: the user chose approximate, which is a real
        // answer and means sharing still works.
        _ if coarse.is_usable() => Grant::Approximate,
        // Nothing asked yet.
        Grant::Unknown if coarse == Grant::Unknown => Grant::Unknown,
        // Nothing held at all. A blocked fine grant is the interesting one, so it
        // wins over a coarse denial.
        Grant::PermanentlyDenied | Grant::Unavailable => fine,
        other => other,
    };
    let next = Permissions {
        location,
        background: Grant::parse(&report.background),
        notifications: Grant::parse(&report.notifications),
        camera: Grant::parse(&report.camera),
        // Carried over. A platform report says what the user has allowed; it does
        // not say what they asked for. Rebuilding the struct without this would
        // silently stop an active share the moment a permission report arrived.
        sharing: permissions.sharing,
    };
    if next == *permissions {
        return false;
    }
    *permissions = next;
    true
}

/// One of the permissions the app asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    Location,
    BackgroundLocation,
    Notifications,
    Camera,
}

impl Permission {
    /// The name the platform uses.
    pub fn name(self) -> &'static str {
        match self {
            Permission::Location => "location",
            Permission::BackgroundLocation => "background-location",
            Permission::Notifications => "notifications",
            Permission::Camera => "camera",
        }
    }

    /// Every permission, in the order they are asked for.
    ///
    /// Location first, then notifications, then background location, then the
    /// camera. Background is asked for on its own and never bundled with the
    /// foreground request: Android 11 and later ignore a combined request, so
    /// asking together would silently drop the one that matters most.
    pub const ALL: [Permission; 4] = [
        Permission::Location,
        Permission::Notifications,
        Permission::BackgroundLocation,
        Permission::Camera,
    ];
}

/// The last report the Java side sent.
///
/// The bridge is a C entry point with no handle on the app, so the report goes
/// through a process-wide slot. Kept as text for the same reason the Java side
/// sends text: one parse table instead of a JNI call per permission.
static REPORT: std::sync::Mutex<Option<Report>> = std::sync::Mutex::new(None);

/// Record a single permission's state, as the bridge receives it.
pub fn apply_report_one(name: &str, value: &str) {
    let Ok(mut slot) = REPORT.lock() else { return };
    let mut report = slot.take().unwrap_or_default();
    match name {
        "location-fine" | "fine" => report.fine = value.to_string(),
        "location-coarse" | "coarse" => report.coarse = value.to_string(),
        "background" => report.background = value.to_string(),
        "notifications" => report.notifications = value.to_string(),
        "camera" => report.camera = value.to_string(),
        _ => return,
    }
    *slot = Some(report);
}

/// Fold whatever the bridge has reported into the shared state.
///
/// Separate from the per-field entry point because a platform reports several
/// permissions at once, and folding them one at a time would redraw between each.
pub fn apply_pending() {
    let Some(report) = REPORT.lock().ok().and_then(|s| s.clone()) else {
        return;
    };
    let shared_state = crate::state::shared();
    let Ok(mut shared) = shared_state.permissions.lock() else {
        return;
    };
    if !apply_report(&report, &mut shared) {
        return;
    }
    // A change in permissions is worth saying out loud, because the difference
    // between "sharing precisely" and "sharing a kilometre at a time" is the whole
    // privacy question this app asks about.
    let summary = shared.summary();
    drop(shared);
    if let Ok(mut state) = shared_state.state.lock() {
        state.status = summary;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_report(fine: &str, coarse: &str, background: &str, notifications: &str) -> Report {
        a_report_with_camera(fine, coarse, background, notifications, "unknown")
    }

    /// The camera is a parameter because it is the one permission the app can do
    /// without: a caller that cares about the queue needs to say whether it is
    /// still unasked or already answered.
    fn a_report_with_camera(
        fine: &str,
        coarse: &str,
        background: &str,
        notifications: &str,
        camera: &str,
    ) -> Report {
        Report {
            fine: fine.to_string(),
            coarse: coarse.to_string(),
            background: background.to_string(),
            notifications: notifications.to_string(),
            camera: camera.to_string(),
        }
    }

    #[test]
    fn a_precise_grant_beats_an_approximate_one() {
        let mut p = Permissions::default();
        apply_report(&a_report("granted", "granted", "granted", "granted"), &mut p);
        assert_eq!(p.location, Grant::Precise);
        assert!(p.can_share());
        assert!(!p.is_coarse());
    }

    #[test]
    fn an_approximate_grant_still_allows_sharing_at_a_kilometre() {
        // Refusing to share at all because the user picked "approximate" would be
        // treating a real answer as no answer.
        let mut p = Permissions::default();
        apply_report(&a_report("denied", "granted", "granted", "granted"), &mut p);
        assert_eq!(p.location, Grant::Approximate);
        assert!(p.can_share());
        assert!(p.is_coarse());
        assert!(p.summary().contains("kilometre"), "{}", p.summary());
    }

    #[test]
    fn a_camera_refusal_does_not_block_anything() {
        // The camera is only for joining. A user who will not give it must still be
        // able to type an invite code in, and must not be pestered about it.
        let mut p = Permissions::default();
        apply_report(
            &a_report_with_camera("granted", "granted", "granted", "granted", "denied"),
            &mut p,
        );
        assert!(p.can_share());
        p.set_sharing(true);
        // A refusal takes it out of the queue for good, and blocks nothing else.
        assert_eq!(p.next_to_ask(), None);
    }

    #[test]
    fn a_denied_location_stops_everything() {
        let mut p = Permissions::default();
        apply_report(&a_report("denied", "denied", "granted", "granted"), &mut p);
        assert!(!p.can_share());
        assert!(!p.survives_background());
        assert!(
            p.summary().contains("nobody can see"),
            "the line has to say what the user loses: {}",
            p.summary()
        );
    }

    #[test]
    fn a_permanent_denial_can_only_be_fixed_in_settings() {
        let mut p = Permissions::default();
        apply_report(&a_report("blocked", "blocked", "denied", "granted"), &mut p);
        assert!(!p.location.can_ask(), "asking again would do nothing");
        assert!(p.location.needs_settings());
        // And the app does not offer to ask, because the prompt would not appear.
        assert_eq!(p.next_to_ask(), None);
    }

    #[test]
    fn without_notifications_a_share_cannot_be_shown_or_stopped() {
        // Android will start a foreground service whose notification the user
        // cannot see, and then the user has no way to know they are being tracked.
        let mut p = Permissions::default();
        apply_report(&a_report("granted", "granted", "granted", "denied"), &mut p);
        assert!(p.can_share());
        assert!(!p.service_is_visible());
        assert!(p.summary().contains("notifications"), "{}", p.summary());
    }

    #[test]
    fn background_is_only_asked_for_once_sharing_is_on() {
        let mut p = Permissions::default();
        // Sharing is off, so background is not offered; the camera is.
        apply_report(
            &a_report_with_camera("granted", "granted", "unknown", "granted", "unknown"),
            &mut p,
        );
        assert_eq!(p.next_to_ask(), Some(Permission::Camera));

        // Turn sharing on, and it is offered.
        assert!(p.set_sharing(true), "the first change is a change");
        assert_eq!(p.next_to_ask(), Some(Permission::BackgroundLocation));
        // And with it held, sharing survives the app being closed.
        p.background = Grant::Precise;
        assert!(p.survives_background());
        // Every permission is now either held or answered, so the queue is empty.
        p.notifications = Grant::Precise;
        p.camera = Grant::Precise;
        assert_eq!(p.next_to_ask(), None);

        // Turning sharing off is a change, and turning it off again is not.
        assert!(p.set_sharing(false));
        assert!(!p.set_sharing(false), "an unchanged toggle is not a change");
    }

    #[test]
    fn permissions_are_asked_for_in_a_sensible_order() {
        let mut p = Permissions::default();
        // Nothing held yet: location is the only thing worth asking for.
        apply_report(&a_report("unknown", "unknown", "unknown", "unknown"), &mut p);
        assert_eq!(p.next_to_ask(), Some(Permission::Location));

        apply_report(&a_report("granted", "granted", "unknown", "unknown"), &mut p);
        assert_eq!(p.next_to_ask(), Some(Permission::Notifications));

        // Background is not offered yet, because sharing is off. The camera is.
        apply_report(
            &a_report_with_camera("granted", "granted", "unknown", "granted", "unknown"),
            &mut p,
        );
        assert_eq!(p.next_to_ask(), Some(Permission::Camera));

        // Sharing is off, so background stays out of the queue even though
        // everything in front of it has been answered. Offering to keep sharing
        // with the screen off to a user who has not turned sharing on is asking
        // for something they did not want.
        apply_report(
            &a_report_with_camera("granted", "granted", "unknown", "granted", "granted"),
            &mut p,
        );
        assert_eq!(p.next_to_ask(), None);

        // Turn sharing on, and it is offered immediately.
        p.set_sharing(true);
        assert_eq!(p.next_to_ask(), Some(Permission::BackgroundLocation));
    }

    #[test]
    fn a_refused_location_is_not_asked_again_and_nothing_after_it_either() {
        // Re-prompting for something just declined is nagging, and Android will
        // not show the dialog again anyway, so the button would do nothing.
        let mut p = Permissions::default();
        apply_report(&a_report("denied", "denied", "unknown", "unknown"), &mut p);
        assert_eq!(p.next_to_ask(), None);
        // The user still gets a way through: the settings app.
        assert!(p.location.can_only_be_fixed_in_settings());

        // And when location is not held, nothing else is worth offering, whatever
        // else has been refused.
        apply_report(&a_report("denied", "denied", "denied", "denied"), &mut p);
        assert_eq!(p.next_to_ask(), None);
    }

    #[test]
    fn a_blocked_fine_grant_wins_over_a_coarse_denial() {
        // The interesting state: the user chose approximate, then later blocked
        // location entirely. Approximate is still the better answer, because it is
        // the one they are currently getting.
        let mut p = Permissions::default();
        apply_report(&a_report("blocked", "denied", "unknown", "unknown"), &mut p);
        assert!(!p.can_share());
        assert!(p.location.needs_settings());
    }

    #[test]
    fn a_platform_report_does_not_stop_an_active_share() {
        // The report carries permissions, not intent. Losing the user's decision
        // because a permission result arrived would stop a share with no way to
        // notice: the map would keep saying it was sharing.
        let mut p = Permissions::default();
        apply_report(
            &a_report_with_camera("granted", "granted", "granted", "granted", "granted"),
            &mut p,
        );
        p.set_sharing(true);
        apply_report(
            &a_report_with_camera("granted", "granted", "granted", "denied", "granted"),
            &mut p,
        );
        assert!(p.sharing, "sharing must survive a permission report");
        // And a report that changes nothing about the permissions is not reported
        // as a change, so the caller redraws once rather than on every field.
        let before = p;
        assert!(!apply_report(
            &a_report_with_camera("granted", "granted", "granted", "denied", "granted"),
            &mut p
        ));
        assert_eq!(p, before);
    }

    #[test]
    fn a_report_that_changes_nothing_says_so() {
        // So the caller redraws once rather than on every field.
        let mut p = Permissions::default();
        let report =
            a_report_with_camera("granted", "granted", "granted", "granted", "granted");
        assert!(apply_report(&report, &mut p));
        assert!(!apply_report(&report, &mut p), "an identical report changes nothing");
    }

    #[test]
    fn grant_words_are_read_from_what_the_platform_sends() {
        assert_eq!(Grant::parse("granted"), Grant::Precise);
        assert_eq!(Grant::parse("approximate"), Grant::Approximate);
        assert_eq!(Grant::parse("denied"), Grant::Denied);
        assert_eq!(Grant::parse("permanently-denied"), Grant::PermanentlyDenied);
        assert_eq!(Grant::parse("blocked"), Grant::PermanentlyDenied);
        assert_eq!(Grant::parse("unavailable"), Grant::Unavailable);
        assert_eq!(Grant::parse("anything else"), Grant::Unknown);
    }

    #[test]
    fn an_unavailable_permission_is_not_the_users_fault() {
        // A camera that does not exist should not be described as blocked.
        assert!(Grant::Unavailable.needs_settings());
        assert!(!Grant::Unavailable.can_ask());
        assert!(!Grant::Unavailable.is_usable());
    }
}
