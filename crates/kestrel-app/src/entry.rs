//! The Android entry point: start egui, hand it the state, and wire the callbacks.
//!
//! Everything here is plumbing. The decisions live in [`crate::map`],
//! [`crate::permissions`] and [`crate::platform`]; this module's whole job is to exist
//! at the right time with the right objects, and to keep them in step.
//!
//! ### How the two halves meet
//!
//! Java owns the activity, the permissions and the camera; Rust owns the circle, the
//! keys and every pixel. The boundary is [`crate::platform::Platform`], which Java
//! implements by calling back into [`crate::android::Android`] and Rust implements by
//! calling out to `Bridge`. Neither side holds a reference to the other beyond that.

use android_activity::AndroidApp;
use eframe::egui;
use std::sync::Arc;

use crate::{
    android::Android,
    engine::{Engine, NetSink},
    logic, map,
    permissions::{self, Permission},
    platform::Platform,
    screens::{self, Ctx},
    state::{self, Fix, Screen, Shared},
    store,
};

/// The relay the app talks to.
///
/// The reference deployment's. Not configurable yet: a settings field that does nothing
/// would be worse than no field, and a person running their own relay needs a decision
/// made about how the app trusts it first.
const DEFAULT_RELAY: &str = "https://starlingmap.app";

/// The entry point `NativeActivity` calls, on its own thread.
///
/// `android-activity` spawns this once the library is loaded and the activity exists,
/// and expects it to return promptly when the window closes. `eframe::run_native`
/// drives that loop, so this is a call and a log.
///
/// Not `std::process::exit` on the way out, deliberately: the share service is another
/// component in this same process, and exiting would take a running share with it.
#[unsafe(no_mangle)]
pub fn android_main(app: AndroidApp) {
    let shared = shared();

    // The activity's jobject, kept so permission dialogs have somewhere to appear. Zero
    // means "none", which is the normal state for the service.
    if let Ok(mut slot) = shared.activity.lock() {
        *slot = app.activity_as_ptr() as i64;
    }

    let platform: Arc<dyn Platform> = Arc::new(Android::new(shared.clone()));

    // Restore the circle before the first frame, so the app opens on the map rather than
    // on a welcome screen the user dismissed yesterday.
    let settings = store::load_settings();
    let channel = match logic::restore_circle(None) {
        Some(circle) => {
            let channel = circle.channel().to_string();
            if let Ok(mut circles) = shared.circles.lock() {
                *circles = vec![circle];
            }
            Some(channel)
        }
        // No circle, or one whose keys will not parse. The app is fully usable and starts
        // on the welcome screen.
        None => None,
    };
    if let Ok(mut state) = shared.state.lock() {
        state.name = settings.name;
        state.language =
            crate::strings::Language::from_index(settings.language).unwrap_or_default();
        if let Some(camera) = store::load_camera() {
            state.camera = map::Camera::new(camera.lat, camera.lon, camera.zoom);
        }
        if channel.is_some() {
            state.go(Screen::Map);
        }
    }

    // The engine, pointed at whatever circle was restored. A relay that will not
    // resolve leaves the app fully usable with no sharing, which is better than
    // refusing to start.
    let engine = match NetSink::new(DEFAULT_RELAY) {
        Ok(sink) => {
            let engine = Arc::new(Engine::new(shared.clone(), Arc::new(sink)));
            engine.attach(channel.as_deref().unwrap_or_default());
            Some(engine)
        }
        Err(e) => {
            log::warn!("no relay configured: {e}");
            None
        }
    };

    let shared = shared.clone();

    let result = eframe::run_native(
        "Kestrel",
        eframe::NativeOptions {
            android_app: Some(app),
            viewport: egui::ViewportBuilder::default()
                .with_app_id("app.kestrel.map")
                // Whatever shape the phone is. A fixed size would letterbox it and waste
                // the pixels the map needs. The scale factor is left to eframe, which
                // reads it from the window: a wrong one makes every touch target the
                // wrong size, which on Android is the difference between usable and not.
                .with_inner_size([400.0, 800.0])
                // No title bar or decorations: the platform draws a status bar and
                // egui draws the app, and a second title bar between them looks like a
                // bug.
                .with_decorations(false),
            ..Default::default()
        },
        Box::new(move |_cc| Ok(Box::new(build(shared.clone(), platform.clone(), engine)))),
    );

    if let Err(e) = result {
        log::error!("eframe stopped: {e}");
    }

    // The activity is going away, so the handle is no longer valid. Left set, every
    // later call would reach a destroyed window.
    if let Ok(mut slot) = state::shared().activity.lock() {
        *slot = 0;
    }
}

/// The shared state, created once and shared by every thread.
///
/// Not a global by choice so much as by necessity: the activity, the service and the
/// decoder thread are three entry points into one app, and threading a handle through
/// all three would mean a global somewhere anyway, only harder to see.
fn shared() -> Arc<Shared> {
    state::shared()
}

/// What the egui side owns.
///
/// Small on purpose: the state is in [`crate::state`] because the service and the
/// decoder thread need it too, and this struct only holds what the UI alone needs.
struct App {
    /// The platform, for the things only a phone can do.
    platform: Arc<dyn Platform>,
    /// What every screen reads and writes.
    shared: Arc<Shared>,
    /// The share loop. `None` when no relay could be reached, which leaves the app fully
    /// usable and simply not sharing.
    engine: Option<Arc<Engine>>,
}

/// Build the egui application.
fn build(
    shared: Arc<Shared>,
    platform: Arc<dyn Platform>,
    engine: Option<Arc<Engine>>,
) -> App {
    App { platform, shared, engine }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // The area being laid out into, in points. The map's projection needs it, and the
        // drawing needs the scale factor so a marker is the same physical size on a dense
        // screen and a sparse one.
        let viewport = ui.available_size_before_wrap();
        // The platform's pixels-per-point, falling back to 1. A fallback of 1 makes
        // everything slightly small on a device that does report one, which is a better
        // failure than a fallback of 0, which makes nothing draw at all.
        let dpr =
            ui.ctx().input(|i| i.viewport().native_pixels_per_point).unwrap_or(1.0) as f32;
        let ctx = Ctx {
            shared: self.shared.clone(),
            platform: self.platform.clone(),
            engine: self.engine.clone(),
            viewport,
            dpr,
        };
        egui::CentralPanel::default().frame(egui::Frame::NONE).show(ui, |ui| {
            screens::draw(ui, &ctx);
        });
    }
}

/// A platform for a build with no phone.
///
/// The host preview, and the answer for a desktop build: the app runs, draws and
/// explains itself, and simply cannot ask a phone for anything.
pub fn host_platform() -> Arc<dyn Platform> {
    Arc::new(crate::platform::Host::at(state::now_ms()))
}

/// The activity came to the foreground.
///
/// Re-reads the permissions, because they can be revoked from the shade or from
/// settings without the app being reopened.
pub fn on_resume() {
    permissions::apply_pending();
}

/// The activity is going away. The share carries on in the service.
pub fn on_pause() {
    if let Ok(mut state) = shared().state.lock() {
        state.background = true;
    }
}

/// The activity is gone.
pub fn on_destroy() {
    if let Ok(mut slot) = state::shared().activity.lock() {
        *slot = 0;
    }
}

/// The back gesture. Decides here because only this side knows which screen is up.
///
/// Returns true when the gesture was consumed and the app should stay put.
pub fn on_back() -> bool {
    let shared = shared();
    let Ok(mut state) = shared.state.lock() else {
        return false;
    };
    if state.screen.is_overlay() {
        // Back closes an overlay. Anything else would drop the user out of a screen they
        // opened deliberately, losing whatever they had typed.
        state.go(Screen::Map);
        return true;
    }
    if state.screen != Screen::Welcome {
        state.go(Screen::Welcome);
        return true;
    }
    false
}

/// A permission question the platform raised.
pub fn on_permission(which: Permission, value: &str) {
    permissions::apply_report_one(which.name(), value);
    permissions::apply_pending();
}

/// A location fix from the service.
pub fn on_fix(fix: Fix) {
    shared().record_fix(fix);
}

/// A scanned code, or the empty string for a scan that failed.
pub fn on_scan(text: &str) {
    if text.is_empty() {
        shared().state.lock().ok().map(|mut s| s.tell("The code could not be read"));
        return;
    }
    shared().offer_scan(text.to_string());
}

/// A one-line note for the platform, used when nothing is wired up.
#[allow(dead_code)]
fn unused_placeholder() {}
