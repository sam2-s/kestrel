//! Map geometry: the Web Mercator projection, distances, and bearing.
//!
//! The projection is implemented here rather than pulled from a map library,
//! and that is worth justifying. The map view needs exactly three operations —
//! world coordinates to screen, screen back to coordinates, and a distance — and
//! all three are a few dozen lines. A library would bring a tile cache, a layer
//! tree, gesture handling and a plugin system to do arithmetic that is fixed by
//! a published formula.
//!
//! The formula is the standard spherical Mercator used by every slippy-map tile
//! scheme: Web Mercator (EPSG:3857) with 256-pixel tiles. The projection is
//! defined only between 85.05112878 degrees north and south, which is where the
//! world becomes square; clamping there is what stops a marker near the pole
//! from projecting to infinity.

/// Maximum latitude the projection is defined for. Beyond this the world is
/// square, and beyond *this* it is not a function at all.
pub const MAX_LATITUDE: f64 = 85.051_128_78;

/// Tile size in pixels, fixed by the tile scheme.
pub const TILE_SIZE: f64 = 256.0;

/// The world is this many tiles across at zoom 0, so 256 pixels.
pub const WORLD_TILES_ZOOM0: f64 = 1.0;

/// A point in normalised world coordinates: the origin at the top left, x
/// increasing east, y increasing *south*, each in the range 0 to 1.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WorldPoint {
    pub x: f64,
    pub y: f64,
}

/// Project latitude and longitude to normalised world coordinates at `zoom`.
///
/// Latitude is clamped to the projection's limit rather than allowed to diverge,
/// so a bad fix cannot produce a NaN that quietly poisons the whole map.
pub fn project(lat: f64, lon: f64, zoom: f64) -> WorldPoint {
    let _ = zoom;
    let lat = lat.clamp(-MAX_LATITUDE, MAX_LATITUDE);
    WorldPoint {
        x: (lon + 180.0) / 360.0,
        // The inverse Gudermannian: the Mercator y for a latitude. The
        // half-angle is what keeps the tangent in the first quadrant for every
        // projected latitude, so the logarithm never sees a negative argument.
        y: 0.5
            - ((std::f64::consts::FRAC_PI_4 + lat.to_radians() / 2.0).tan()).ln()
                / (2.0 * std::f64::consts::PI),
    }
}

/// The world pixel coordinate of a latitude and longitude at `zoom`, where the
/// origin is the top left of the world and one unit is one pixel.
pub fn world_pixels(lat: f64, lon: f64, zoom: f64) -> (f64, f64) {
    let p = project(lat, lon, zoom);
    let n = TILE_SIZE * 2f64.powf(zoom);
    (p.x * n, p.y * n)
}

/// The inverse of [`project`]: normalised world coordinates back to a latitude
/// and longitude.
pub fn unproject(x: f64, y: f64, zoom: f64) -> (f64, f64) {
    let _ = zoom;
    let lon = x * 360.0 - 180.0;
    // The Gudermannian inverse: exponentiate y shifted by half a turn and scaled
    // by a full turn, take the arctangent, double it, and remove the
    // quarter-turn offset.
    let lat_rad = 2.0 * ((0.5 - y) * 2.0 * std::f64::consts::PI).exp().atan()
        - std::f64::consts::FRAC_PI_2;
    (lat_rad.to_degrees(), lon)
}

/// The tile coordinate covering a latitude and longitude at an integer zoom.
pub fn tile_xy(lat: f64, lon: f64, zoom: u32) -> (i64, i64) {
    let p = project(lat, lon, zoom as f64);
    let n: f64 = 2f64.powi(zoom as i32);
    // `n - epsilon` rather than `n`, so a coordinate landing exactly on the
    // antimeridian or the projection limit yields the last tile and not one past
    // it. Longitude is wrapped first for the same reason.
    let x = wrap01(p.x);
    // Clamp both axes into range. Floating point puts the projection limit a few
    // billionths outside 0 and 1, and `floor` would turn that into a tile index
    // of -1 or one past the end.
    let tx = (x * n).floor().clamp(0.0, n - 1.0) as i64;
    let ty = (p.y * n).floor().clamp(0.0, n - 1.0) as i64;
    (tx, ty)
}

/// Fold a world fraction into the half-open range 0 to 1, so a longitude past
/// the antimeridian names the first copy rather than an out-of-range tile.
fn wrap01(x: f64) -> f64 {
    let w = x - x.floor();
    if w >= 1.0 { 0.0 } else { w }
}

/// Wrap a tile x coordinate into range, so panning east or west past the prime
/// meridian shows the world repeating rather than blank space.
pub fn wrap_tile_x(x: i64, zoom: u32) -> i64 {
    x.rem_euclid(2i64.pow(zoom))
}

/// The ground resolution in metres per pixel at a latitude and zoom, used to
/// scale the accuracy circle a member's fix deserves.
pub fn metres_per_pixel(lat: f64, zoom: f64) -> f64 {
    let lat = lat.clamp(-MAX_LATITUDE, MAX_LATITUDE);
    156_543.033_92 * lat.cos().to_radians() / 2f64.powf(zoom)
}

/// Great-circle distance in metres between two positions.
///
/// Uses the haversine form, which is numerically stable for the short distances
/// this app deals with. The radius is the mean Earth radius, the same constant
/// every mapping library uses, so distances agree with what a user expects from
/// any other map.
pub fn haversine_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const EARTH_RADIUS_M: f64 = 6_371_008.8;
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS_M * a.sqrt().asin()
}

/// Initial bearing in degrees from one position to another, 0 being north and
/// increasing clockwise.
pub fn bearing_deg(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let p1 = lat1.to_radians();
    let p2 = lat2.to_radians();
    let dl = (lon2 - lon1).to_radians();
    let y = dl.sin() * p2.cos();
    let x = p1.cos() * p2.sin() - p1.sin() * p2.cos() * dl.cos();
    y.atan2(x).to_degrees().rem_euclid(360.0)
}

/// The default zoom that fits a set of positions into a viewport.
///
/// Fit to the bounds with a margin, capped so a single member does not zoom to
/// the maximum and show a house, and floored so a circle spread across a
/// continent does not zoom out to the whole world.
pub fn zoom_to_fit(
    positions: &[(f64, f64)],
    viewport_px: (f64, f64),
    padding_px: (f64, f64),
) -> f64 {
    if positions.is_empty() {
        return 12.0;
    }
    if positions.len() == 1 {
        return 15.0;
    }

    let mut min_lat = f64::INFINITY;
    let mut max_lat = f64::NEG_INFINITY;
    let mut min_lon = f64::INFINITY;
    let mut max_lon = f64::NEG_INFINITY;
    for &(lat, lon) in positions {
        min_lat = min_lat.min(lat);
        max_lat = max_lat.max(lat);
        min_lon = min_lon.min(lon);
        max_lon = max_lon.max(lon);
    }

    let usable_w = (viewport_px.0 - padding_px.0 * 2.0).max(1.0);
    let usable_h = (viewport_px.1 - padding_px.1 * 2.0).max(1.0);

    // The span in world fractions at zoom 0 is the bound we must fit into.
    let span_x = project(max_lat, max_lon, 0.0).x - project(min_lat, min_lon, 0.0).x;
    let span_y = project(max_lat, max_lon, 0.0).y - project(min_lat, min_lon, 0.0).y;

    let zoom_x = (usable_w / TILE_SIZE / span_x.max(f64::MIN_POSITIVE)).log2();
    let zoom_y = (usable_h / TILE_SIZE / span_y.max(f64::MIN_POSITIVE)).log2();
    (zoom_x.min(zoom_y)).clamp(2.0, 17.0)
}

/// Which world copy a longitude falls in, for drawing the world repeating across
/// the antimeridian.
///
/// Zero for the copy containing the prime meridian, one for the copy starting at
/// 180 degrees east, and so on; negative going west.
pub fn world_wrap_index(lon: f64) -> i64 {
    ((lon + 180.0) / 360.0).floor() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_origin_projects_to_the_centre_of_the_world() {
        let p = project(0.0, 0.0, 0.0);
        assert!((p.x - 0.5).abs() < 1e-9, "x was {}", p.x);
        assert!((p.y - 0.5).abs() < 1e-9, "y was {}", p.y);
    }

    #[test]
    fn the_projection_limit_is_the_top_and_bottom_of_the_world() {
        assert!((project(MAX_LATITUDE, 0.0, 0.0).y).abs() < 1e-6);
        assert!((project(-MAX_LATITUDE, 0.0, 0.0).y - 1.0).abs() < 1e-6);
    }

    #[test]
    fn latitude_is_clamped_rather_than_diverging() {
        // A bad fix must not produce a NaN that quietly poisons the map.
        let north = project(90.0, 0.0, 10.0);
        let beyond = project(1e9, 0.0, 10.0);
        assert_eq!(north.y, beyond.y);
        assert!(north.y.is_finite());
        assert!(project(-90.0, 0.0, 0.0).y.is_finite());
    }

    #[test]
    fn longitude_increases_eastward() {
        assert!(project(0.0, -180.0, 0.0).x < project(0.0, 0.0, 0.0).x);
        assert!(project(0.0, 0.0, 0.0).x < project(0.0, 180.0, 0.0).x);
        assert!((project(0.0, -180.0, 0.0).x).abs() < 1e-9);
        assert!((project(0.0, 180.0, 0.0).x - 1.0).abs() < 1e-9);
    }

    #[test]
    fn projection_and_unprojection_are_inverses() {
        for (lat, lon) in [
            (0.0, 0.0),
            (44.98, -93.27),
            (-33.87, 151.21),
            (64.15, -21.94),
            (MAX_LATITUDE, 179.0),
        ] {
            for zoom in [0.0, 5.0, 12.0, 19.0] {
                let p = project(lat, lon, zoom);
                let (lat2, lon2) = unproject(p.x, p.y, zoom);
                assert!((lat - lat2).abs() < 1e-6, "lat {lat} -> {lat2} at z{zoom}");
                assert!((lon - lon2).abs() < 1e-6, "lon {lon} -> {lon2} at z{zoom}");
            }
        }
    }

    #[test]
    fn each_zoom_doubles_the_world_size() {
        let (x0, y0) = world_pixels(44.98, -93.27, 0.0);
        let (x1, y1) = world_pixels(44.98, -93.27, 1.0);
        assert!((x1 - x0 * 2.0).abs() < 1e-6);
        assert!((y1 - y0 * 2.0).abs() < 1e-6);
        // At zoom 0 the world is one 256-pixel tile, so a point at 24% of the
        // way east is at 61.7 pixels.
        assert!((x0 - 61.674_666_666_666_7).abs() < 1e-6, "x0 was {x0}");
    }

    #[test]
    fn a_known_place_lands_on_a_known_tile() {
        // Minneapolis, to catch a transposed or flipped axis. The value is
        // checked against the standard formula independently of this crate.
        let (x, y) = tile_xy(44.98, -93.27, 12);
        assert_eq!((x, y), (986, 1473));
        // London at the same zoom, as a second point so an error cannot be
        // hidden by an offset in one axis.
        assert_eq!(tile_xy(51.5, -0.12, 12), (2046, 1362));
    }

    #[test]
    fn tile_coordinates_stay_in_range() {
        for zoom in 0..20u32 {
            let n = 2i64.pow(zoom);
            let (x, y) = tile_xy(MAX_LATITUDE, 179.999, zoom);
            assert!(x >= 0 && x < n, "x out of range at z{zoom}");
            assert!(y >= 0 && y < n, "y out of range at z{zoom}");
            let (x, y) = tile_xy(-MAX_LATITUDE, -180.0, zoom);
            assert!(x >= 0 && x < n);
            assert!(y >= 0 && y < n);
        }
    }

    #[test]
    fn tiles_wrap_across_the_antimeridian() {
        assert_eq!(wrap_tile_x(-1, 2), 3);
        assert_eq!(wrap_tile_x(4, 2), 0);
        assert_eq!(wrap_tile_x(5, 2), 1);
    }

    #[test]
    fn ground_resolution_shrinks_with_zoom_and_toward_the_poles() {
        let equator = metres_per_pixel(0.0, 10.0);
        let north = metres_per_pixel(50.0, 10.0);
        assert!(north < equator, "fewer metres per pixel at higher latitude");
        let closer = metres_per_pixel(0.0, 11.0);
        assert!((closer * 2.0 - equator).abs() < 1e-6, "halves per zoom level");
    }

    #[test]
    fn distance_to_self_is_zero() {
        assert!(haversine_m(44.98, -93.27, 44.98, -93.27).abs() < 1e-6);
    }

    #[test]
    fn distance_matches_a_known_distance() {
        // Minneapolis to Saint Paul, about 12 km.
        let d = haversine_m(44.98, -93.265, 44.95, -93.09);
        assert!((d - 13_300.0).abs() < 1_500.0, "got {d} m");

        // One degree of latitude is about 111 km everywhere.
        let d = haversine_m(0.0, 0.0, 1.0, 0.0);
        assert!((d - 111_195.0).abs() < 100.0, "got {d} m");
    }

    #[test]
    fn distance_is_symmetric() {
        let a = haversine_m(44.98, -93.27, 51.5, -0.12);
        let b = haversine_m(51.5, -0.12, 44.98, -93.27);
        assert!((a - b).abs() < 1e-6);
    }

    #[test]
    fn short_distances_are_accurate() {
        // The haversine form is chosen for precision here; a naive spherical law
        // of cosines loses digits at 25 m.
        let d = haversine_m(44.98, -93.27, 44.980_225, -93.27);
        assert!((d - 25.0).abs() < 0.5, "got {d} m for a 25 m step");
    }

    #[test]
    fn bearing_is_cardinal_when_it_should_be() {
        assert!(bearing_deg(0.0, 0.0, 1.0, 0.0).abs() < 0.01, "due north");
        assert!((bearing_deg(0.0, 0.0, 0.0, 1.0) - 90.0).abs() < 0.01, "due east");
        assert!((bearing_deg(1.0, 0.0, 0.0, 0.0) - 180.0).abs() < 0.01, "due south");
        assert!((bearing_deg(0.0, 1.0, 0.0, 0.0) - 270.0).abs() < 0.01, "due west");
    }

    #[test]
    fn bearing_is_always_in_range() {
        for (lat1, lon1, lat2, lon2) in
            [(0.0, 0.0, 1.0, 1.0), (80.0, 170.0, -80.0, -170.0), (-45.0, 20.0, 45.0, 200.0)]
        {
            let b = bearing_deg(lat1, lon1, lat2, lon2);
            assert!((0.0..360.0).contains(&b), "bearing {b} out of range");
        }
    }

    #[test]
    fn zoom_to_fit_handles_the_degenerate_cases() {
        assert_eq!(zoom_to_fit(&[], (400.0, 800.0), (10.0, 10.0)), 12.0);
        assert_eq!(zoom_to_fit(&[(44.98, -93.27)], (400.0, 800.0), (10.0, 10.0)), 15.0);
    }

    #[test]
    fn zoom_to_fit_is_tighter_for_a_nearer_pair() {
        let near = zoom_to_fit(
            &[(44.98, -93.27), (44.981, -93.271)],
            (400.0, 800.0),
            (10.0, 10.0),
        );
        let far =
            zoom_to_fit(&[(44.98, -93.27), (51.5, -0.12)], (400.0, 800.0), (10.0, 10.0));
        assert!(near > far, "a closer pair must fit at a higher zoom");
    }

    #[test]
    fn zoom_to_fit_stays_within_bounds() {
        let same =
            zoom_to_fit(&[(44.98, -93.27), (44.98, -93.27)], (400.0, 800.0), (10.0, 10.0));
        assert!((2.0..=17.0).contains(&same));
        let tiny_viewport =
            zoom_to_fit(&[(0.0, 0.0), (80.0, 170.0)], (1.0, 1.0), (0.5, 0.5));
        assert!((2.0..=17.0).contains(&tiny_viewport), "a degenerate viewport is clamped");
    }

    #[test]
    fn the_world_wrap_index_identifies_the_copy() {
        assert_eq!(world_wrap_index(0.0), 0);
        assert_eq!(world_wrap_index(179.0), 0);
        assert_eq!(world_wrap_index(180.0), 1, "the copy starting at 180 east");
        assert_eq!(world_wrap_index(200.0), 1);
        // -180 is the left edge of the first copy, so it is still copy zero; one
        // degree further west is the copy before it.
        assert_eq!(world_wrap_index(-180.0), 0);
        assert_eq!(world_wrap_index(-181.0), -1);
        assert_eq!(world_wrap_index(-190.0), -1);
    }

    #[test]
    fn a_longitude_past_the_antimeridian_names_the_first_tile_again() {
        // 190 degrees east is 10 degrees west, in the copy that starts at 180.
        let (a, _) = tile_xy(0.0, 190.0, 4);
        let (b, _) = tile_xy(0.0, -170.0, 4);
        assert_eq!(a, b);
        // And it is the tile -170 degrees west occupies, not one past the end.
        let n = 16i64;
        assert!((0..n).contains(&a));
    }
}
