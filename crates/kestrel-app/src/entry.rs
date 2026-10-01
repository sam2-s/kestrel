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
    permissions::{self, Permission},
    platform::{Host, Platform},
    state::{self, Fix, Screen, Shared},
};

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
        Box::new(move |_cc| Ok(Box::new(build(shared, platform)))),
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

/// What the app is doing, and what it should show about that.
///
/// A struct rather than a set of statics, so the screens are functions of it and can be
/// reasoned about in a test.
struct App {
    /// The platform, for the things only a phone can do.
    platform: Arc<dyn Platform>,
    /// What every screen reads and writes.
    shared: Arc<Shared>,
}

/// The egui application, built by eframe and handed to us once.
///
/// egui is re-exported by eframe, so this file names it `egui` rather than depending on
/// a second copy of the same crate at a possibly different version.
fn build(shared: Arc<Shared>, platform: Arc<dyn Platform>) -> App {
    App { platform, shared }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let shared = self.shared.clone();
        let platform = self.platform.clone();
        draw(ui, &shared, platform);
    }
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

/// The drawing. One function, because everything here is a screen.
fn draw(ui: &mut egui::Ui, shared: &Arc<Shared>, platform: Arc<dyn Platform>) {
    let screen = shared.state.lock().map(|s| s.screen).unwrap_or_default();

    let platform_for = platform.clone();
    let shared_for = shared.clone();
    egui::CentralPanel::default().show(ui, |ui| match screen {
        Screen::Welcome => welcome(ui, shared, platform),
        Screen::Map => map(ui, shared, platform),
        Screen::Join => join(ui, shared, platform),
        Screen::Review => review(ui, shared),
        Screen::Settings => settings(ui, shared, platform),
        Screen::Locked => locked(ui, shared),
        Screen::Wiped => wiped(ui, shared),
    });

    // Any permission worth asking for, asked once the current screen has drawn. Asking
    // from inside a draw would pop a dialog over a half-built frame.
    if let Ok(p) = shared_for.permissions.lock() {
        if let Some(wanted) = p.next_to_ask() {
            platform_for.request(wanted);
        }
    }
}

fn welcome(ui: &mut egui::Ui, shared: &Arc<Shared>, platform: Arc<dyn Platform>) {
    ui.add_space(40.0);
    ui.heading("Kestrel");
    ui.label("Share your location with a small circle, and nobody else.");
    ui.add_space(20.0);

    if !shared.has_circle() {
        if ui.button("Create a circle").clicked() {
            // Not wired to key creation yet: a circle needs a seed, and choosing where
            // that seed comes from is a decision about how much this app trusts the
            // device it runs on. Deliberately a dead button until that is settled rather
            // than a plausible-looking one.
            tell(ui, shared, "Coming next: circle creation");
        }
        if ui.button("Join a circle").clicked() {
            if let Ok(mut state) = shared.state.lock() {
                state.go(Screen::Join);
            }
        }
    } else if ui.button("Open the map").clicked() {
        if let Ok(mut state) = shared.state.lock() {
            state.go(Screen::Map);
        }
    }

    ui.add_space(20.0);
    // The permission line comes first on purpose. Everything this app does depends on
    // location, and finding that out after tapping "create" is worse than being told up
    // front.
    if let Ok(p) = shared.permissions.lock() {
        ui.label(p.summary());
        if let Some(needed) = p.next_to_ask() {
            if ui.button(ask_label(needed)).clicked() {
                platform.request(needed);
            }
        }
    }
}

fn map(ui: &mut egui::Ui, shared: &Arc<Shared>, platform: Arc<dyn Platform>) {
    ui.heading("Map");
    let sharing = shared.state.lock().map(|s| s.sharing).unwrap_or(false);
    ui.label(if sharing { "Sharing" } else { "Not sharing" });

    if sharing {
        if ui.button("Stop sharing").clicked() {
            platform.set_sharing(false);
            if let Ok(mut p) = shared.permissions.lock() {
                p.set_sharing(false);
            }
        }
    } else if ui.button("Share my location").clicked() {
        platform.set_sharing(true);
        if let Ok(mut p) = shared.permissions.lock() {
            p.set_sharing(true);
        }
    }

    ui.add_space(12.0);
    if ui.button("Scan a code").clicked() {
        platform.start_scan();
    }
    if ui.button("Settings").clicked() {
        if let Ok(mut state) = shared.state.lock() {
            state.go(Screen::Settings);
        }
    }
}

fn join(ui: &mut egui::Ui, shared: &Arc<Shared>, platform: Arc<dyn Platform>) {
    ui.heading("Join a circle");
    ui.label("Ask someone in the circle for their code, then scan or type it.");
    ui.add_space(8.0);

    // Held in the shared state rather than a local, because a rotation rebuilds this
    // whole frame and a local would lose whatever had been typed.
    let mut typed =
        shared.state.lock().ok().and_then(|s| s.invite.clone()).unwrap_or_default();
    ui.horizontal(|ui| {
        ui.text_edit_singleline(&mut typed);
        if ui.button("Join").clicked() && !typed.is_empty() {
            tell(ui, shared, "Joining is coming next");
        }
    });
    if let Ok(mut state) = shared.state.lock() {
        state.invite = Some(typed);
    }

    ui.add_space(8.0);
    if ui.button("Scan instead").clicked() {
        // Through the platform, not through the state, so this screen works the same
        // whether the code was scanned or typed.
        platform.start_scan();
    }
    if ui.button("Back").clicked() {
        if let Ok(mut state) = shared.state.lock() {
            state.go(Screen::Welcome);
        }
    }
}

fn review(ui: &mut egui::Ui, shared: &Arc<Shared>) {
    ui.heading("Someone is asking to join");
    // The safety number is the whole point of this screen: it is what the two people
    // compare out loud, and it is the only thing standing between a real member and
    // someone who found the code.
    if let Ok(state) = shared.state.lock() {
        if let Some((number, name)) = &state.pending_name {
            ui.label(format!("{name} says their number is"));
            ui.heading(number);
        }
    }
    ui.label("Read it out. If it does not match, they are not who they say they are.");
    ui.add_space(8.0);
    if ui.button("Accept").clicked() {
        tell(ui, shared, "Accepting is coming next");
    }
    if ui.button("Decline").clicked() {
        if let Ok(mut state) = shared.state.lock() {
            state.go(Screen::Map);
            state.pending_name = None;
        }
    }
}

fn settings(ui: &mut egui::Ui, shared: &Arc<Shared>, platform: Arc<dyn Platform>) {
    ui.heading("Settings");

    if let Ok(p) = shared.permissions.lock() {
        for (name, grant) in [
            ("Location", p.location),
            ("Background location", p.background),
            ("Notifications", p.notifications),
            ("Camera", p.camera),
        ] {
            ui.horizontal(|ui| {
                ui.label(format!("{name}: {}", grant.label()));
                if grant.can_only_be_fixed_in_settings() {
                    if ui.small_button("Settings").clicked() {
                        platform.open_settings(permission_of(name));
                    }
                }
            });
        }
    }

    ui.add_space(12.0);
    ui.label("Version 0.1.0 · GPL-3.0-or-later");
    if ui.button("Close").clicked() {
        if let Ok(mut state) = shared.state.lock() {
            state.go(Screen::Map);
        }
    }
}

fn locked(ui: &mut egui::Ui, shared: &Arc<Shared>) {
    ui.heading("Locked");
    ui.label("Enter your passcode.");
    // Not implemented. A passcode screen that accepts anything is worse than none: it
    // would tell the user the app is protected when it is not.
    if ui.button("Not now").clicked() {
        tell(ui, shared, "The app lock is not wired up yet");
    }
}

fn wiped(ui: &mut egui::Ui, shared: &Arc<Shared>) {
    ui.heading("Nothing here");
    ui.label("The keys were destroyed. Nothing that was shared can be recovered.");
    if ui.button("Close").clicked() {
        if let Ok(mut state) = shared.state.lock() {
            state.go(Screen::Welcome);
        }
    }
}

fn tell(ui: &mut egui::Ui, shared: &Arc<Shared>, message: &str) {
    ui.colored_label(egui::Color32::YELLOW, message);
    if let Ok(mut state) = shared.state.lock() {
        state.tell(message);
    }
}

fn ask_label(p: Permission) -> &'static str {
    match p {
        Permission::Location => "Allow location",
        Permission::BackgroundLocation => "Allow background location",
        Permission::Notifications => "Allow notifications",
        Permission::Camera => "Allow the camera",
    }
}

fn permission_of(name: &str) -> Permission {
    match name {
        "Location" => Permission::Location,
        "Background location" => Permission::BackgroundLocation,
        "Notifications" => Permission::Notifications,
        _ => Permission::Camera,
    }
}

/// A platform for a build with no phone.
///
/// The host preview, and the answer for a desktop build: the app runs, draws and
/// explains itself, and simply cannot ask a phone for anything.
pub fn host_platform() -> Arc<dyn Platform> {
    Arc::new(Host::at(state::now_ms()))
}
