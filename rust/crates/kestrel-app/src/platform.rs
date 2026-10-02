//! What the app needs from the phone, as a trait.
//!
//! The trait exists so the decisions can be tested off-device. Every method is one
//! thing the app cannot do for itself — ask for a permission, post a notification,
//! show a camera — and every one of them is a platform API rather than an
//! algorithm. On Android each is a call into a small Java shim; on the host it is a
//! recorder that writes down what would have been asked for.
//!
//! The split is what makes the rest of the app testable. Nothing in `map`,
//! `permissions` or `state` knows about Android, and a test that needs to know
//! "would the app have asked for the camera?" can just ask [`Host`].

use std::sync::Mutex;

use crate::permissions::Permission;

/// What a call to the platform was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// Ask for a runtime permission.
    Request(Permission),
    /// Send the user to the settings app, for a permission the user has to fix
    /// there.
    OpenSettings(Permission),
    /// Start or stop continuous sharing.
    SetSharing(bool),
    /// Post a notification.
    Notify(String, String),
    /// Open the camera to scan a code.
    StartScan,
    /// Route traffic through a proxy.
    SetProxy(String),
}

/// Where the app may keep files.
///
/// The platform's own answer, so there is one place that knows how to ask. On Android
/// it is the app's private storage, which is already scoped to this app and needs no
/// permission; anywhere else it is a directory beside the executable.
pub fn data_dir() -> std::path::PathBuf {
    #[cfg(target_os = "android")]
    if let Some(dir) = crate::android::data_dir() {
        return dir;
    }
    // Nowhere sensible to put files on a desktop, and this function is only reached by
    // the host preview and by tests. A temp directory that the OS reclaims is the right
    // amount of pretending.
    std::env::temp_dir().join("kestrel")
}

/// What the app asks of the platform.
///
/// Methods take `&self` and return nothing: a platform call that fails leaves the
/// app in the state it was already in, which is the safe direction. A failed
/// permission request means the user declined; a failed notification means one
/// message was not seen. Neither should stop the share.
pub trait Platform {
    /// Ask for a permission.
    fn request(&self, permission: Permission);

    /// Send the user to the settings app, for something only they can fix.
    fn open_settings(&self, for_permission: Permission);

    /// Turn continuous sharing on or off.
    fn set_sharing(&self, on: bool);

    /// Post a notification.
    fn notify(&self, title: &str, body: &str);

    /// Open the camera to scan a code.
    fn start_scan(&self);

    /// Route traffic through a proxy, or clear it with an empty string.
    fn set_proxy(&self, proxy: &str);

    /// The wall clock, in milliseconds.
    ///
    /// Taken from the platform rather than the system clock alone so a test can
    /// put it anywhere, and so a time-dependent decision can be checked.
    fn now_ms(&self) -> i64;
}

/// A platform that records instead of acting.
///
/// For tests and for the host preview, where there is no phone to ask. Also the
/// honest answer for a build running anywhere but Android: the app is fully
/// usable, it simply cannot share from a desktop.
#[derive(Debug, Default)]
pub struct Host {
    calls: Mutex<Vec<Call>>,
    /// The clock to report, so a test can pin time.
    clock: Mutex<i64>,
}

impl Host {
    /// A host with a clock pinned to `now`.
    pub fn at(now: i64) -> Self {
        Self { calls: Mutex::new(Vec::new()), clock: Mutex::new(now) }
    }

    /// Everything asked of the platform so far.
    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }

    /// The last thing asked, if there is one.
    pub fn last(&self) -> Option<Call> {
        self.calls.lock().ok()?.last().cloned()
    }

    /// Whether a particular call was ever made.
    pub fn was_called(&self, call: &Call) -> bool {
        self.calls().contains(call)
    }

    /// Move the clock.
    pub fn set_now(&self, now: i64) {
        if let Ok(mut clock) = self.clock.lock() {
            *clock = now;
        }
    }

    /// Forget everything, so a test can start again mid-run.
    pub fn clear(&self) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.clear();
        }
    }

    fn record(&self, call: Call) {
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(call);
        }
    }
}

impl Platform for Host {
    fn request(&self, permission: Permission) {
        self.record(Call::Request(permission));
    }

    fn open_settings(&self, for_permission: Permission) {
        self.record(Call::OpenSettings(for_permission));
    }

    fn set_sharing(&self, on: bool) {
        self.record(Call::SetSharing(on));
    }

    fn notify(&self, title: &str, body: &str) {
        self.record(Call::Notify(title.to_string(), body.to_string()));
    }

    fn start_scan(&self) {
        self.record(Call::StartScan);
    }

    fn set_proxy(&self, proxy: &str) {
        self.record(Call::SetProxy(proxy.to_string()));
    }

    fn now_ms(&self) -> i64 {
        self.clock.lock().map(|c| *c).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_host_records_what_it_was_asked() {
        let host = Host::default();
        host.request(Permission::Location);
        host.set_sharing(true);
        assert_eq!(
            host.calls(),
            vec![Call::Request(Permission::Location), Call::SetSharing(true),]
        );
        assert_eq!(host.last(), Some(Call::SetSharing(true)));
        assert!(host.was_called(&Call::Request(Permission::Location)));
        assert!(!host.was_called(&Call::Request(Permission::Camera)));
    }

    #[test]
    fn a_notification_keeps_its_text() {
        // The share notification is the only thing telling the user they are being
        // tracked, so its wording must survive the trip to the platform.
        let host = Host::default();
        host.notify("Sharing with Ada", "sent 2 min ago");
        assert_eq!(
            host.last(),
            Some(Call::Notify("Sharing with Ada".into(), "sent 2 min ago".into()))
        );
    }

    #[test]
    fn a_cleared_host_forgets_so_a_test_can_start_again() {
        let host = Host::default();
        host.start_scan();
        assert_eq!(host.calls().len(), 1);
        host.clear();
        assert!(host.calls().is_empty());
    }

    #[test]
    fn a_host_clock_can_be_pinned() {
        // Time-dependent decisions cannot be tested against a moving clock, so the
        // host takes one and the tests set it.
        let host = Host::at(1_700_000_000_000);
        assert_eq!(host.now_ms(), 1_700_000_000_000);
        host.set_now(1_700_000_060_000);
        assert_eq!(host.now_ms(), 1_700_000_060_000);
    }

    #[test]
    fn an_empty_proxy_means_no_proxy() {
        // Not a special case in the app: the platform decides what an empty string
        // means, and clearing a proxy is the same call as setting one.
        let host = Host::default();
        host.set_proxy("");
        assert_eq!(host.last(), Some(Call::SetProxy(String::new())));
    }
}
