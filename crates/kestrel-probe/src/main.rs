use kestrel_app::map::TileRequest;
fn main() {
    let r = TileRequest { z: 2, xs: vec![-3, -1, 0, 1, 4, 7], ys: vec![-2, 0, 1, 9] };
    let keys = r.keys();
    println!("len={} keys={:?}", keys.len(), keys);
    let r2 = TileRequest { z: 2, xs: vec![0, 4, -4, 8], ys: vec![0, 8, -8] };
    println!("len={} keys={:?}", r2.keys().len(), r2.keys());
}
