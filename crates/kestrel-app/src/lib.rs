//! The Kestrel app.
//!
//! The platform-independent half lives here: the map's decisions, the strings, and
//! the permission model. The Android half is a thin shell over it, and the
//! difference is deliberate — a permission state machine and a tile request are
//! both worth testing, and neither needs a phone.

pub mod i18n;
pub mod map;
pub mod permissions;
pub mod settings;
pub mod strings;

#[cfg(target_os = "android")]
pub mod android;
