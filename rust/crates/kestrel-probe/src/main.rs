//! A scratch pad for looking at one thing at a time.
//!
//! Not a test and not part of the app. Everything that matters is a test in the
//! crate it belongs to; this exists so a question that does not deserve a whole
//! test — "what does this actually print?" — can be asked without inventing a
//! test that will outlive the question.
//!
//!     cargo run -p kestrel-probe
//!
//! Nothing here is asserted against, so anything printed can change without a
//! failing build. If a fact in here is worth keeping, it belongs in a test.

use kestrel_app::{map::TileRequest, permissions::Grant, state::Fix};

fn main() {
    // Tile coverage: which tiles a zoom level needs, and how duplicates collapse.
    let r = TileRequest { z: 2, xs: vec![-3, -1, 0, 1, 4, 7], ys: vec![-2, 0, 1, 9] };
    let keys = r.keys();
    println!("tiles len={} keys={keys:?}", keys.len());

    // A position that must not reach the map: the platform reports this before it
    // has a location, and drawing it would put a marker in the Gulf of Guinea.
    let zero = Fix { lat: 0.0, lon: 0.0, acc: 0.0, ts: 1_000, battery: 0.5 };
    println!("zero fix usable={}", zero.is_usable());

    // The word the platform sends, against what the app makes of it.
    for word in ["granted", "approximate", "denied", "blocked"] {
        let g = Grant::parse(word);
        println!("{word:>12} -> {g:?} ({} / usable={})", g.label(), g.is_usable());
    }
}
