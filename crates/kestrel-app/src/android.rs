//! The Android shell: the JNI bridge and the egui entry point.
//!
//! Almost nothing here is Android-specific logic. The share cadence, the
//! permission decisions and the map all live in platform-independent modules, and
//! this file's job is to move values across the boundary.
//!
//! ### Why a Java shim at all
//!
//! Three things cannot be done from Rust without a Java layer, and each is a
//! platform API rather than an algorithm:
//!
//! * **Runtime permissions.** `Activity.requestPermissions` delivers its result to
//!   `onRequestPermissionsResult`, a method on a subclass. There is no callback
//!   to register from outside.
//! * **A foreground service typed for location**, with a notification channel.
//! * **The camera and the biometric prompt**, which are both Java classes.
//!
//! So there are four small Java files and no more. The share logic, the sealing
//! and the keys are all in Rust, which is the point: a torn-down process holds no
//! keys here, so a share cannot appear to be running with nothing going out.

use std::sync::Arc;

use log::{error, warn};

use crate::{
    permissions::Permission,
    state::{self, Shared},
};

/// The Android implementation. Every method is one call into Java.
pub struct Android {
    shared: Arc<Shared>,
}

impl Android {
    pub fn new(shared: Arc<Shared>) -> Self {
        Self { shared }
    }

    /// Attach to the JVM and call a static void method on the bridge.
    fn call(&self, name: &str, build: impl FnOnce(&mut jni::JNIEnv) -> bool) -> bool {
        let Ok(raw) = self.shared.activity.lock().ok().and_then(|a| *a) else {
            return false;
        };
        if raw == 0 {
            // The app is in the background and the service is doing the work.
            // Not worth logging on every call.
            return false;
        }
        let Ok(vm) = ndk_context::android_context() else {
            return false;
        };
        let Ok(env) = vm.attach_current_thread().map_err(|e| e.to_string()) else {
            return false;
        };
        let mut env = env;
        if !build(&mut env) {
            return false;
        }
        let Ok(class) = env.find_class("app/kestrel/map/Bridge") else {
            error!("the Java bridge class is missing; the app cannot ask for anything");
            return false;
        };
        let Ok(sig) = static_signature(name) else {
            error!(method = name, "no signature registered for this Java method");
            return false;
        };
        let result = unsafe {
            env.call_static_method_unchecked(
                class,
                jni::JNISignature::from_static(sig),
                &[],
            )
        };
        match result {
            Ok(_) => true,
            Err(e) => {
                warn!(method = name, error = %e, "a Java call failed");
                false
            }
        }
    }
}

/// The JNI signature of each bridge method.
///
/// Written out rather than derived, so a rename on either side is a compile error
/// here instead of a `NoSuchMethodError` on a user's phone.
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

/// A string argument, built through the closure the caller is given.
fn with_string(
    env: &mut jni::JNIEnv,
    value: &str,
    f: impl FnOnce(&mut jni::JNIEnv, &jni::objects::JString) -> bool,
) -> bool {
    match env.new_string(value) {
        Ok(s) => {
            let s = s.into_raw();
            let out = f(env, unsafe { jni::objects::JString::from_raw(s) });
            unsafe {
                let _ = env.delete_local_ref(s);
            }
            out
        }
        Err(e) => {
            warn!(error = %e, "could not pass a string to Java");
            false
        }
    }
}

impl Platform for Android {
    fn request(&self, permission: Permission) {
        let method = match permission {
            Permission::Location => "requestLocation",
            Permission::BackgroundLocation => "requestBackgroundLocation",
            Permission::Notifications => "requestNotifications",
            Permission::Camera => "requestCamera",
        };
        let _ = self.call(method, |_| true);
    }

    fn open_settings(&self, for_permission: Permission) {
        let method = match for_permission {
            Permission::Location | Permission::BackgroundLocation => "openLocationSettings",
            _ => "openAppSettings",
        };
        let _ = self.call(method, |_| true);
    }

    fn set_sharing(&self, on: bool) {
        let method = if on { "startSharing" } else { "stopSharing" };
        let _ = self.call(method, |_| true);
    }

    fn notify(&self, title: &str, body: &str) {
        let t = title.to_string();
        let b = body.to_string();
        let _ = self.call("notify", move |env| {
            with_string(env, &t, |env, t| {
                with_string(env, &b, |env, b| {
                    let Ok(class) = env.find_class("app/kestrel/map/Bridge") else {
                        return false;
                    };
                    unsafe {
                        env.call_static_method_unchecked(
                            class,
                            jni::JNISignature::from_static(
                                "notify(Ljava/lang/String;Ljava/lang/String;)V",
                            ),
                            &[t.into(), b.into()],
                        )
                    }
                    .is_ok()
                })
            })
        });
    }

    fn start_scan(&self) {
        let _ = self.call("startScan", |_| true);
    }

    fn set_proxy(&self, proxy: &str) {
        let p = proxy.to_string();
        let _ = self.call("setProxy", move |env| {
            with_string(env, &p, |env, p| {
                let Ok(class) = env.find_class("app/kestrel/map/Bridge") else {
                    return false;
                };
                unsafe {
                    env.call_static_method_unchecked(
                        class,
                        jni::JNISignature::from_static("setProxy(Ljava/lang/String;)V"),
                        &[p.into()],
                    )
                }
                .is_ok()
            })
        });
    }

    fn now_ms(&self) -> i64 {
        state::now_ms()
    }
}

// ------------------------------------------------------- the Java callbacks

/// Record what the platform says about permissions.
///
/// One entry point rather than one per permission, so a new permission is one
/// line here and one case in `Permissions` rather than a symbol and a signature
/// and a branch in three places.
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_kestrel_map_Bridge_reportPermission(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    which: jni::objects::JString,
    value: jni::objects::JString,
) {
    let Ok(which) = env.get_string(&which) else { return };
    let Ok(value) = env.get_string(&value) else { return };
    crate::permissions::apply_report_one(&which, &value);
    crate::permissions::apply_pending();
}

/// A location fix, from the foreground service.
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_kestrel_map_Bridge_reportLocation(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
    lat: jni::objects::JObject,
    lon: jni::objects::JObject,
    acc: jni::objects::JObject,
    ts: jni::objects::JObject,
    battery: jni::objects::JObject,
) {
    let (Ok(lat), Ok(lon), Ok(acc), Ok(ts), Ok(battery)) =
        (lat.i32(), lon.i32(), acc.i32(), ts.i64(), battery.i32())
    else {
        warn!("a location fix arrived with the wrong types; ignoring it");
        return;
    };
    state::shared().record_fix(state::Fix {
        lat: lat as f64 / 1e7,
        lon: lon as f64 / 1e7,
        acc: acc as f64,
        ts,
        battery: battery as f64 / 100.0,
    });
}

/// A scanned code's contents.
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_kestrel_map_Bridge_reportScan(
    mut env: jni::JNIEnv,
    _class: jni::objects::JClass,
    text: jni::objects::JString,
) {
    let Ok(text) = env.get_string(&text) else { return };
    // The camera's result arrives on a Java thread with no handle on the app, so
    // it goes into the shared state and the UI reads it on the next frame.
    state::shared().offer_scan(text.into());
}

/// The app is going to the background or coming back.
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_kestrel_map_Bridge_reportBackground(
    _env: jni::JNIEnv,
    _class: jni::objects::JClass,
    in_background: jni::objects::JObject,
) {
    let background = in_background.z().unwrap_or(false) != 0;
    if let Ok(mut state) = state::shared().state.lock() {
        state.background = background;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_bridge_method_has_a_signature() {
        // A method the shell calls with no signature would be a NoSuchMethodError
        // on a phone, and only when that particular button was pressed.
        for name in [
            "requestLocation",
            "requestBackgroundLocation",
            "requestNotifications",
            "requestCamera",
            "openAppSettings",
            "openLocationSettings",
            "startSharing",
            "stopSharing",
            "startScan",
            "notify",
            "setProxy",
        ] {
            assert!(static_signature(name).is_some(), "{name} has no signature");
        }
        assert!(static_signature("somethingNobodyCalls").is_none());
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
}
