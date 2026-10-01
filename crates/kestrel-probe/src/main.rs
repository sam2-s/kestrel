use kestrel_core::places::{Place, Places};
fn main() {
    const HOME: (f64, f64) = (44.98, -93.27);
    let mut p = Places::new();
    p.put(Place::new("home", "Home", HOME.0, HOME.1).with_radius(150.0));
    for (t, lat, label) in [
        (1000i64, HOME.0 + 0.01, "B out"),
        (4000, HOME.0, "B in 1"),
        (44000, HOME.0, "B in 2"),
        (84000, HOME.0, "B in 3"),
    ] {
        let a = p.observe("B", lat, HOME.1, 5.0, t);
        println!("{t:6} {label:8} -> {a:?}");
    }
}
