//! The relay, as a library.
//!
//! `main.rs` is the binary; this is the same code as a library so the test suite
//! can drive the real router rather than a stand-in for it. A test that used a
//! reimplementation of the routing would pass while the deployed relay failed.

pub mod help;
pub mod http;
pub mod limits;
pub mod store;

/// The Android package this relay vouches for in its asset links.
pub const PACKAGE_NAME: &str = "app.kestrel.map";
