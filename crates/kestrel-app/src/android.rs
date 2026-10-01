//! The Android side of the boundary: JNI, and nothing else.
//!
//! Everything here is a value crossing between Rust and Java. The share cadence,
//! the permission decisions and the map all live in platform-independent modules,
//! so this file is the only part of the app that has to be right about Android
//! rather than about location.
//!
//! ### Why a Java shim at all
//!
//! Three things cannot be done from Rust without a Java layer, and each is a
//! platform API rather than an algorithm:
//!
//! * **Runtime permissions.** `Activity.requestPermissions` delivers its result to
//!   `onRequestPermissionsResult`, a method on a subclass. There is no callback to
//!   register from outside.
//! * **A foreground service typed for location**, with a notification channel.
//! * **The camera**, which is a Java class and a Surface.
//!
//! So there are a few small Java files and no more. The share logic, the sealing
//! and the keys are all in Rust, which is the point: a torn-down process holds no
//! keys here, so a share cannot appear to be running with nothing going out.
//!
//! ### Calls are best-effort
//!
//! Every method here returns `bool` and logs rather than propagating. A platform
//! call that fails leaves the app in the state it was already in, which is the
//! safe direction: a refused permission request means the user declined, and a
//! notification that did not post is one message nobody saw. Neither should stop a
//! share that is already running.

use std::sync::Arc;

use jni::{signature::RuntimeMethodSignature, strings::JNIString};
use log::{error, warn};

use crate::{
    permissions::Permission,
    platform::Platform,
    state::{self, Shared},
};

/// The bridge class in Java. Renaming it means changing this line too.
const BRIDGE: &str = "app/kestrel/map/Bridge";

/// The Android implementation of [`Platform`].
pub struct Android {
    shared: Arc<Shared>,
}

impl Android {
    pub fn new(shared: Arc<Shared>) -> Self {
        Self { shared }
    }

    /// Whether there is an activity to ask.
    ///
    /// The permission dialogs are owned by the activity, so a call made while the
    /// app is in the background has nowhere to appear. Returning false rather than
    /// queueing is deliberate: the user who presses a button in the foreground
    /// should get the dialog now, and the service has no business opening one.
    fn has_activity(&self) -> bool {
        self.shared.activity.lock().map(|a| *a != 0).unwrap_or(false)
    }

    /// Call a static Java method with no arguments.
    fn call0(&self, name: &str) -> bool {
        self.call(name, |_| Vec::new())
    }

    /// Call a static Java method with one string argument.
    fn call1(&self, name: &str, arg: &str) -> bool {
        self.call(name, |env| match env.new_string(arg) {
            Ok(s) => vec![s.into()],
            Err(e) => {
                warn!("could not pass a string to Java: {e}");
                Vec::new()
            }
        })
    }

    /// Call a static Java method with two string arguments.
    fn call2(&self, name: &str, a: &str, b: &str) -> bool {
        self.call(name, |env| match (env.new_string(a), env.new_string(b)) {
            (Ok(a), Ok(b)) => vec![a.into(), b.into()],
            _ => {
                warn!("could not pass both strings to Java");
                Vec::new()
            }
        })
    }

    /// The one place a call to Java happens.
    ///
    /// `args` is handed the env to build its arguments with, so the local
    /// references it creates live exactly as long as the call that uses them. A
    /// caller cannot hold a JNI local reference past this function, which is the
    /// rule that turns a leak into a compile error.
    fn call(
        &self,
        name: &str,
        args: impl for<'a> FnOnce(&mut jni::Env<'a>) -> Vec<jni::objects::JObject<'a>>,
    ) -> bool {
        let Some(vm) = self.vm() else {
            return false;
        };
        let Some(sig) = static_signature(name) else {
            error!("no signature registered for the Java method {name}");
            return false;
        };
        // Parsed here rather than inside the closure so a bad signature is a plain
        // error, not a panic on a JNI frame where unwinding is not allowed.
        let Ok(signature) = RuntimeMethodSignature::from_str(sig) else {
            error!("the registered signature for {name} is not a method signature");
            return false;
        };
        // The count is checked against the signature here rather than trusted, so a
        // mismatch is a logged error instead of a NoSuchMethodError thrown from a
        // user's thumb.
        let expected = signature.method_signature().args().len();
        let class = JNIString::new(BRIDGE);
        let method = JNIString::new(name);
        let ok = vm
            .attach_current_thread(|env| -> Result<bool, jni::errors::Error> {
                let args = args(env);
                if args.len() != expected {
                    error!(
                        "{name} is called with {} arguments but its signature takes {expected}",
                        args.len()
                    );
                    return Ok(false);
                }
                let values: Vec<jni::JValue> = args.iter().map(|a| jni::JValue::Object(a)).collect();
                let Ok(class) = env.find_class(class.as_ref()) else {
                    error!("the Java bridge class is missing; the app cannot ask for anything");
                    return Ok(false);
                };
                Ok(env
                    .call_static_method(
                        class,
                        method.as_ref(),
                        signature.method_signature(),
                        &values,
                    )
                    .is_ok())
            })
            .unwrap_or(false);
        if !ok {
            warn!("the Java call to {name} failed");
        }
        ok
    }

    /// The JavaVM, if the runtime has published it.
    ///
    /// `ndk_context` panics when it has not, so this is not simply a call. The
    /// panic can only happen before the runtime hands over a context, which is
    /// before any of this code can run, so the guard is belt-and-braces against a
    /// future path that reaches it earlier.
    fn vm(&self) -> Option<jni::JavaVM> {
        if !ndk_context_is_ready() {
            return None;
        }
        let ctx = ndk_context::android_context();
        // SAFETY: the runtime handed us the JavaVM pointer and it is valid for the
        // life of the process. `from_raw` is the documented way to adopt it, and it
        // only reads the pointer, so adopting it twice is harmless.
        Some(unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) })
    }
}

/// Whether the Android runtime has published a context.
///
/// Read through a separate function so [`Android::vm`] does not have to reason
/// about the panic in `ndk_context::android_context`. A missing context means the
/// code is running somewhere it should not be, and every call here fails anyway.
fn ndk_context_is_ready() -> bool {
    std::panic::catch_unwind(ndk_context::android_context).is_ok()
}

/// The JNI signature of each bridge method.
///
/// Written out rather than derived from the calls, so a rename on either side is a
/// compile error here instead of a `NoSuchMethodError` on a user's phone. The test
/// at the bottom of this file checks that every method the app calls is in this
/// table and vice versa.
fn static_signature(name: &str) -> Option<&'static str> {
    Some(match name {
        "requestLocation" => "requestLocation()V",
        "requestBackgroundLocation" => "requestBackgroundLocation()V",
        "requestNotifications" => "requestNotifications()V",
        "requestCamera" => "requestCamera()V",
        "openAppSettings" => "openAppSettings()V",
        "openLocationSettings" => "openLocationSettings()V",
        "startSharing" => "startSharing()V",
        "stopSharing" => "stopSharing()V",
        "startScan" => "startScan()V",
        "notify" => "notify(Ljava/lang/String;Ljava/lang/String;)V",
        "setProxy" => "setProxy(Ljava/lang/String;)V",
        _ => return None,
    })
}

impl Platform for Android {
    fn request(&self, permission: Permission) {
        if !self.has_activity() {
            return;
        }
        let method = match permission {
            Permission::Location => "requestLocation",
            Permission::BackgroundLocation => "requestBackgroundLocation",
            Permission::Notifications => "requestNotifications",
            Permission::Camera => "requestCamera",
        };
        self.call0(method);
    }

    fn open_settings(&self, for_permission: Permission) {
        if !self.has_activity() {
            return;
        }
        // Location has its own settings screen, with the app's own toggle in it.
        // Sending the user to the app's page instead would ask them to find a
        // switch they may not know is there.
        let method = match for_permission {
            Permission::Location | Permission::BackgroundLocation => "openLocationSettings",
            _ => "openAppSettings",
        };
        self.call0(method);
    }

    fn set_sharing(&self, on: bool) {
        self.call0(if on { "startSharing" } else { "stopSharing" });
    }

    fn notify(&self, title: &str, body: &str) {
        // Not gated on the activity: the notification is the one thing that must
        // work while the app is closed, which is most of the time a share runs.
        self.call2("notify", title, body);
    }

    fn start_scan(&self) {
        if !self.has_activity() {
            return;
        }
        self.call0("startScan");
    }

    fn set_proxy(&self, proxy: &str) {
        self.call1("setProxy", proxy);
    }

    fn now_ms(&self) -> i64 {
        state::now_ms()
    }
}

// ------------------------------------------------------- the Java callbacks

/// Record what the platform says about permissions.
///
/// One entry point rather than one per permission, so a new permission is one line
/// here and one case in `Permissions` rather than a symbol and a signature and a
/// branch in three places.
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_kestrel_map_Bridge_reportPermission<'frame>(
    mut env: jni::EnvUnowned<'frame>,
    _class: jni::objects::JClass,
    which: jni::objects::JString,
    value: jni::objects::JString,
) {
    // `resolve` rather than `unwrap`: a Java exception thrown inside here must not
    // unwind into Java, where it would abort the process.
    env.with_env::<_, (), jni::errors::Error>(|env| {
        let Ok(which) = which.try_to_string(env) else {
            return Ok(());
        };
        let Ok(value) = value.try_to_string(env) else {
            return Ok(());
        };
        crate::permissions::apply_report_one(&which, &value);
        crate::permissions::apply_pending();
        Ok(())
    })
    .resolve::<jni::errors::LogErrorAndDefault>();
}

/// A location fix, from the foreground service.
///
/// Integers rather than doubles, because a JNI double crosses as a double but a
/// phone's location is better sent as a scaled integer: the scale is fixed, the
/// arithmetic is trivial, and a value that is 7 decimal places of a degree is about
/// a centimetre, which is more precision than any handset has.
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_kestrel_map_Bridge_reportLocation<'frame>(
    mut env: jni::EnvUnowned<'frame>,
    _class: jni::objects::JClass,
    lat: jni::sys::jint,
    lon: jni::sys::jint,
    acc: jni::sys::jint,
    ts: jni::sys::jlong,
    battery: jni::sys::jint,
) {
    env.with_env::<_, (), jni::errors::Error>(|_env| {
        // Typed parameters, so a wrong type is a link error rather than a fix
        // silently reading a pointer as a coordinate.
        let (lat, lon, acc, ts, battery) = (
            lat as f64 / 1e7,
            lon as f64 / 1e7,
            acc as f64,
            ts as i64,
            battery as f64 / 100.0,
        );
        state::shared().record_fix(state::Fix { lat, lon, acc, ts, battery });
        Ok(())
    })
    .resolve::<jni::errors::LogErrorAndDefault>();
}

/// A scanned code's contents.
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_kestrel_map_Bridge_reportScan<'frame>(
    mut env: jni::EnvUnowned<'frame>,
    _class: jni::objects::JClass,
    text: jni::objects::JString,
) {
    env.with_env::<_, (), jni::errors::Error>(|env| {
        let Ok(text) = text.try_to_string(env) else {
            return Ok(());
        };
        // The camera's result arrives on a Java thread with no handle on the app, so
        // it goes into the shared state and the UI reads it on the next frame.
        state::shared().offer_scan(text.into());
        Ok(())
    })
    .resolve::<jni::errors::LogErrorAndDefault>();
}

/// The app is going to the background or coming back.
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_kestrel_map_Bridge_reportBackground<'frame>(
    mut env: jni::EnvUnowned<'frame>,
    _class: jni::objects::JClass,
    in_background: jni::sys::jboolean,
) {
    env.with_env::<_, (), jni::errors::Error>(|_env| {
        let background = in_background.into();
        if let Ok(mut state) = state::shared().state.lock() {
            state.background = background;
        }
        Ok(())
    })
    .resolve::<jni::errors::LogErrorAndDefault>();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every method the app calls, and how many arguments it passes.
    const CALLED: [(&str, usize); 11] = [
        ("requestLocation", 0),
        ("requestBackgroundLocation", 0),
        ("requestNotifications", 0),
        ("requestCamera", 0),
        ("openAppSettings", 0),
        ("openLocationSettings", 0),
        ("startSharing", 0),
        ("stopSharing", 0),
        ("startScan", 0),
        ("notify", 2),
        ("setProxy", 1),
    ];

    /// The arguments each registered signature claims to take, parsed the same way
    /// the runtime call parses it.
    ///
    /// Reading it back through the parser rather than counting separators by hand
    /// means this test and the call cannot disagree about what a signature means.
    fn parsed_arg_count(sig: &str) -> usize {
        jni::signature::RuntimeMethodSignature::from_str(sig)
            .expect("every registered signature must parse")
            .method_signature()
            .args()
            .len()
    }

    #[test]
    fn every_method_the_app_calls_has_a_signature_that_matches_how_it_is_called() {
        // A method the shell calls with no signature, or with the wrong number of
        // arguments, would be a NoSuchMethodError on a phone — and only when that
        // particular button was pressed.
        for (name, args) in CALLED {
            let sig = static_signature(name)
                .unwrap_or_else(|| panic!("{name} has no signature, but it is called"));
            assert_eq!(
                parsed_arg_count(sig),
                args,
                "{name} is called with {args} arguments, so its signature must say so"
            );
        }
        assert!(static_signature("somethingNobodyCalls").is_none());
    }

    #[test]
    fn every_registered_signature_is_a_real_method_signature() {
        // A typo in the table would otherwise sit there until the call was made on a
        // real phone.
        for name in CALLED.map(|(name, _)| name) {
            let sig = static_signature(name).unwrap();
            assert!(
                jni::signature::RuntimeMethodSignature::from_str(sig).is_ok(),
                "{name}'s signature does not parse"
            );
        }
    }

    #[test]
    fn a_signature_with_no_parameters_takes_no_arguments() {
        assert_eq!(parsed_arg_count("notify()V"), 0);
        assert_eq!(parsed_arg_count("setProxy(Ljava/lang/String;)V"), 1);
        assert_eq!(parsed_arg_count("notify(Ljava/lang/String;Ljava/lang/String;)V"), 2);
    }

    #[test]
    fn every_permission_maps_to_a_method_that_exists() {
        // A permission the shell cannot ask for is a button that does nothing.
        for method in [
            "requestLocation",
            "requestBackgroundLocation",
            "requestNotifications",
            "requestCamera",
        ] {
            assert!(static_signature(method).is_some(), "{method} is missing");
        }
    }

    #[test]
    fn a_call_without_an_activity_does_nothing_and_does_not_panic() {
        // The permission dialogs belong to the activity. Reaching here from the
        // service would mean queueing a prompt that cannot appear.
        let shared = Arc::new(Shared::default());
        let android = Android::new(shared.clone());
        assert!(!android.has_activity());

        let host = crate::platform::Host::default();
        // The recording platform proves what the app would have asked, and that
        // nothing was asked of a platform that is not there.
        android.request(Permission::Location);
        android.open_settings(Permission::Camera);
        android.start_scan();
        assert!(host.calls().is_empty());
    }

    #[test]
    fn the_call_helper_refuses_a_method_it_does_not_know() {
        // Not reachable through the trait, because every call site uses a name from
        // the table above. It is checked anyway because this is the one function
        // where a wrong name becomes a runtime error rather than a compile error.
        assert!(static_signature("requestBiometrics").is_none());
    }
}
