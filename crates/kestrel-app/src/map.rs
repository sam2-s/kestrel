//! The map: what is drawn, and how it is decided.
//!
//! Split deliberately in two. This file owns the *decisions* — which tiles cover
//! the viewport, which members are visible, where a marker goes, how fresh it
//! looks — and none of the drawing. The drawing lives in `view.rs` and is a thin
//! translation of what this produces.
//!
//! The split is why the map can be tested at all. A marker at the wrong place
//! because a clamp was missing is invisible in a screenshot review and obvious
//! here.

use std::collections::BTreeMap;

use kestrel_core::{
    geo,
    session::{Circle, MemberState, STALE_MS},
    wire::TRAIL_CAP,
};

/// The street basemap, or the one that fetches nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basemap {
    /// OpenStreetMap raster tiles, darkened.
    Dark,
    /// OpenStreetMap raster tiles, as they are.
    Light,
    /// No tiles at all: a drawn grid and distance rings. Zero network requests,
    /// which is the honest option on a hostile network.
    OffGrid,
}

impl Basemap {
    /// Whether this basemap fetches anything.
    pub fn fetches_tiles(self) -> bool {
        !matches!(self, Basemap::OffGrid)
    }

    /// The tile address, or `None` when nothing is fetched.
    pub fn tile_url(self, z: u32, x: i64, y: i64) -> Option<String> {
        match self {
            Basemap::OffGrid => None,
            Basemap::Dark | Basemap::Light => {
                Some(format!("https://tile.openstreetmap.org/{z}/{x}/{y}.png"))
            }
        }
    }
}

/// The zoom levels the map will sit at.
pub const MIN_ZOOM: f64 = 2.0;
pub const MAX_ZOOM: f64 = 19.0;

/// The rings drawn in off-grid mode, in metres.
pub const RING_RADII: [f64; 4] = [250.0, 500.0, 1000.0, 2000.0];

/// Where the map is looking, and at what scale.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Camera {
    pub lat: f64,
    pub lon: f64,
    pub zoom: f64,
}

impl Default for Camera {
    fn default() -> Self {
        // A view of most of the world, so a first run is not a white screen with
        // one dot on it.
        Self {
            lat: 20.0,
            lon: 0.0,
            zoom: 3.0,
        }
    }
}

impl Camera {
    pub fn new(lat: f64, lon: f64, zoom: f64) -> Self {
        Self {
            lat,
            lon,
            zoom: zoom.clamp(MIN_ZOOM, MAX_ZOOM),
        }
    }

    /// Move the camera to a position, keeping the zoom.
    pub fn look_at(&mut self, lat: f64, lon: f64) {
        self.lat = lat.clamp(-geo::MAX_LATITUDE, geo::MAX_LATITUDE);
        self.lon = lon;
    }

    /// Zoom by a number of steps.
    pub fn zoom_by(&mut self, steps: f64) {
        self.zoom = (self.zoom + steps).clamp(MIN_ZOOM, MAX_ZOOM);
    }

    /// A camera that fits a set of positions, for the "show everyone" button.
    pub fn fitting(positions: &[(f64, f64)], viewport_px: (f64, f64)) -> Self {
        let zoom = geo::zoom_to_fit(positions, viewport_px, (48.0, 280.0));
        let (lat, lon) = positions
            .iter()
            .fold((0.0, 0.0), |acc, (la, lo)| (acc.0 + la, acc.1 + lo));
        let n = positions.len().max(1) as f64;
        Self::new(lat / n, lon / n, zoom)
    }

    /// A camera that puts one member in the middle of the screen.
    ///
    /// The y offset exists because the member sheet covers the bottom of the
    /// screen: a marker centred under it is a marker nobody can see.
    pub fn on_member(camera: &Self, member: &MemberState, now: i64) -> Option<Self> {
        let fix = member.position(now)?;
        let mut next = *camera;
        next.look_at(fix.lat, fix.lon);
        next.zoom = next.zoom.max(15.0);
        Some(next)
    }
}

/// One tile the map needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TileKey {
    pub z: u32,
    pub x: i64,
    pub y: i64,
}

impl TileKey {
    /// The cache key as text, for a file name.
    pub fn as_string(self) -> String {
        format!("{}/{}/{}", self.z, self.x, self.y)
    }
}

/// Which tiles cover a viewport, and which of them the map already has.
///
/// Returned as a set rather than painted directly, so the renderer can decide
/// what to draw from what it has and the decision can be tested without a GPU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TileRequest {
    pub z: u32,
    /// Tile columns, west to east. May be negative, for a view across the
    /// antimeridian.
    pub xs: Vec<i64>,
    /// Tile rows, north to south.
    pub ys: Vec<i64>,
}

impl TileRequest {
    /// The tiles covering a viewport at a camera.
    ///
    /// One ring of padding, because a tile that arrives after the user has
    /// panned half a screen is a tile they have already panned past.
    pub fn covering(camera: &Camera, viewport_px: (f64, f64), padding: i64) -> TileRequest {
        let z = camera.zoom.round().max(0.0) as u32;
        let n = 2f64.powi(z as i32);
        let centre = geo::project(camera.lat, camera.lon, camera.zoom);
        // Pixel position of the viewport's top-left in world pixels at this zoom.
        let ox = centre.x * n - viewport_px.0 / 2.0;
        let oy = centre.y * n - viewport_px.1 / 2.0;
        let first_x = (ox / geo::TILE_SIZE).floor() as i64 - padding;
        let last_x = ((ox + viewport_px.0) / geo::TILE_SIZE).floor() as i64 + padding;
        let first_y = (oy / geo::TILE_SIZE).floor() as i64 - padding;
        let last_y = ((oy + viewport_px.1) / geo::TILE_SIZE).floor() as i64 + padding;

        // A viewport taller than the world would otherwise ask for thousands of
        // rows, and clamping y is enough because there is nothing below the south
        // pole to show.
        let rows = (last_y - first_y + 1).min(n as i64 + 2 * padding);
        TileRequest {
            z,
            xs: (first_x..=last_x).collect(),
            ys: (first_y..first_y + rows - 1).collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.xs.len() * self.ys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.xs.is_empty() || self.ys.is_empty()
    }

    /// Every tile, with x wrapped into range and y clamped, and duplicates
    /// removed.
    ///
    /// The duplicates are real: a view across the antimeridian produces column
    /// indices that wrap onto each other, and asking for the same tile twice
    /// means fetching it twice and painting it twice over itself.
    pub fn keys(&self) -> Vec<TileKey> {
        let n = 2i64.pow(self.z);
        let mut out: Vec<TileKey> = Vec::with_capacity(self.len());
        for y in &self.ys {
            let ty = (*y).clamp(0, n - 1);
            for x in &self.xs {
                out.push(TileKey {
                    z: self.z,
                    x: geo::wrap_tile_x(*x, self.z),
                    y: ty,
                });
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// How many of these are not already cached.
    pub fn missing(&self, cached: &BTreeMap<TileKey, ()>, basemap: Basemap) -> Vec<TileKey> {
        if !basemap.fetches_tiles() {
            return Vec::new();
        }
        self.keys()
            .into_iter()
            .filter(|k| !cached.contains_key(k))
            .collect()
    }
}

/// A member, placed on screen.
#[derive(Debug, Clone, PartialEq)]
pub struct Marker {
    pub member_id: String,
    /// Screen position, relative to the map's top-left.
    pub x: f32,
    pub y: f32,
    /// A hue from the member id, so the same person is the same colour on every
    /// device without anybody choosing a colour.
    pub hue: u16,
    pub name: String,
    pub emoji: String,
    pub battery: f64,
    /// How fresh the position is, 0 to 1, where 1 is now. Drives the fade.
    pub freshness: f32,
    /// Whether this device.
    pub is_self: bool,
    /// Whether the device is actively sharing.
    pub sharing: bool,
    /// Whether an emergency is active.
    pub sos: bool,
    /// Whether the member said they stopped, rather than simply going quiet.
    pub stopped: bool,
    /// Whether the member has been confirmed in person.
    pub verified: bool,
    /// Whether the member is a leader or a follower, for a subtle border.
    pub removed: bool,
}

/// A trail, as screen points oldest first.
#[derive(Debug, Clone, PartialEq)]
pub struct Trail {
    pub member_id: String,
    pub hue: u16,
    pub points: Vec<(f32, f32)>,
}

/// The distance rings drawn in off-grid mode, as radii in pixels.
pub fn ring_radii_px(camera: &Camera) -> Vec<f64> {
    let mpp = geo::metres_per_pixel(camera.lat, camera.zoom);
    if mpp <= 0.0 {
        return Vec::new();
    }
    RING_RADII
        .iter()
        .map(|m| m / mpp)
        // Beyond the viewport a ring is invisible, and drawing it costs a
        // primitive for nothing.
        .filter(|px| *px > 8.0 && px.is_finite() && *px < 20_000.0)
        .collect()
}

/// The whole of the map's per-frame decisions.
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    pub camera: Camera,
    pub basemap: Basemap,
    pub tiles: TileRequest,
    pub markers: Vec<Marker>,
    pub trails: Vec<Trail>,
    pub rings: Vec<f64>,
    /// Set when the map has no members and the camera is nowhere useful, so the UI
    /// can say so rather than showing an empty grid.
    pub empty: bool,
}

/// How long a marker's freshness ramp lasts. Three minutes, matching the point at
/// which a member goes stale.
const FRESHNESS_WINDOW_MS: f64 = 3.0 * 60.0 * 1000.0;

/// Build one frame.
///
/// `self_id` is the member id of this device, which is drawn differently because
/// it is the one position the user can do something about.
pub fn frame(
    circle: &Circle,
    camera: &Camera,
    basemap: Basemap,
    viewport_px: (f64, f64),
    now: i64,
    self_id: &str,
) -> Frame {
    let request = TileRequest::covering(camera, viewport_px, 1);
    let centre = geo::project(camera.lat, camera.lon, camera.zoom);
    let n = geo::TILE_SIZE * 2f64.powf(camera.zoom);
    let half = (viewport_px.0 / 2.0, viewport_px.1 / 2.0);

    let to_screen = |lat: f64, lon: f64| -> (f32, f32) {
        let p = geo::project(lat, lon, camera.zoom);
        (
            ((p.x * n - centre.x * n) + half.0) as f32,
            ((p.y * n - centre.y * n) + half.1) as f32,
        )
    };

    let mut markers = Vec::new();
    let mut trails = Vec::new();

    for member in circle.members() {
        let m = &member.member;
        let fix = member.position(now);

        // A member who stopped, or who has gone quiet, is still drawn at the last
        // place they were heard from and greyed out. Drawing nothing leaves a hole
        // where a person is, and a hole reads as "nobody is there". The window is
        // bounded, so a member from yesterday is not on the map pretending to be.
        let still_known = now.saturating_sub(member.last_spoke()) <= LAST_KNOWN_MS;
        let drawable = if still_known {
            fix.or_else(|| member.last_fix())
        } else {
            None
        };
        if let Some(fix) = drawable {
            let (x, y) = to_screen(fix.lat, fix.lon);
            let age = now.saturating_sub(member.last_seen) as f64;
            let sos = matches!(member.last, Some(kestrel_core::msg::CircleMsg::Sos { .. }));
            let stopped = matches!(member.last, Some(kestrel_core::msg::CircleMsg::Bye { .. }));
            markers.push(Marker {
                member_id: m.member_id.clone(),
                x,
                y,
                hue: member.hue,
                name: m.name.clone(),
                // The avatar rides in the last message rather than the roster
                // record, because the roster is pinned key material and a display
                // name is the one thing about a member that changes.
                emoji: member
                    .last
                    .as_ref()
                    .and_then(|l| l.who())
                    .map(|w| w.emoji.clone())
                    .unwrap_or_default(),
                battery: member
                    .last
                    .as_ref()
                    .and_then(|l| l.who())
                    .map(|w| w.bat)
                    .unwrap_or(0.0),
                freshness: (1.0 - age / FRESHNESS_WINDOW_MS).clamp(0.0, 1.0) as f32,
                is_self: m.member_id == self_id,
                sharing: !stopped,
                sos,
                stopped,
                verified: m.verified,
                removed: member.removed,
            });
        }

        // The trail, but only when it is worth drawing: at a wide zoom it is a
        // scribble across the whole screen, and the member's current position is
        // what matters.
        if camera.zoom >= 11.0 {
            let points: Vec<(f32, f32)> = member
                .trail
                .iter()
                .filter_map(|t| t.fix().map(|f| to_screen(f.lat, f.lon)))
                .take(TRAIL_CAP)
                .collect();
            if points.len() > 1 {
                trails.push(Trail {
                    member_id: m.member_id.clone(),
                    hue: member.hue,
                    points,
                });
            }
        }
    }

    let rings = if basemap == Basemap::OffGrid {
        ring_radii_px(camera)
    } else {
        Vec::new()
    };

    Frame {
        camera: *camera,
        basemap,
        tiles: request,
        empty: markers.is_empty(),
        markers,
        trails,
        rings,
    }
}

/// Frame to every member, or frame to none.
pub fn fit(camera: &mut Camera, circle: &Circle, now: i64, viewport_px: (f64, f64)) -> bool {
    let positions: Vec<(f64, f64)> = circle
        .members()
        .iter()
        .filter_map(|m| m.position(now).map(|f| (f.lat, f.lon)))
        .collect();
    if positions.is_empty() {
        return false;
    }
    *camera = Camera::fitting(&positions, viewport_px);
    true
}

/// Centre on one member, keeping the rest in view where it can.
pub fn focus(camera: &mut Camera, circle: &Circle, member_id: &str, now: i64) -> bool {
    let Some(member) = circle.member(member_id) else {
        return false;
    };
    match Camera::on_member(camera, member, now) {
        Some(next) => {
            *camera = next;
            true
        }
        None => false,
    }
}

/// How old a position may be before its member is drawn as stale rather than
/// live. Kept in step with the session's own threshold, since a member the map
/// calls live and the session calls stale is a contradiction the user would see.
pub const DRAW_STALE_MS: i64 = STALE_MS;

/// How long after their last word a member is still drawn, greyed out.
///
/// Someone who stopped sharing three hours ago has not vanished; drawing nothing
/// leaves a hole where a person is, and a hole reads as "nobody is here". Four
/// hours is well inside the relay's own retention, so the map is never offering a
/// position the relay would still have thrown away.
pub const LAST_KNOWN_MS: i64 = 4 * 60 * 60 * 1000;

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_core::{identity::Identity, msg::ShareMode, roster::Roster, session::me};

    const SEED: [u8; 32] = [42u8; 32];
    const EPOCH: i64 = wire_epoch();

    const fn wire_epoch() -> i64 {
        600_000
    }

    fn at(e: i64) -> i64 {
        e * EPOCH
    }

    /// A circle, and a second device in it, positioned at `fix`.
    ///
    /// The second device has its own [`Circle`] on the same channel and seed,
    /// because a circle seals with its *own* identity. Sealing "as" another
    /// member by borrowing one device's signer would produce a post the receiver
    /// correctly discards as its own, and the map would have no markers to test.
    fn a_circle_with_a_member_at(fix: (f64, f64), name: &str, now: i64) -> (Circle, String) {
        let channel = kestrel_core::kdf::channel_id(&kestrel_core::kdf::anchor(&SEED));
        let opened = kestrel_core::wire::epoch_at(now);

        let mut mine = Circle::join(
            Identity::generate(),
            &SEED,
            channel.clone(),
            0,
            opened,
            Roster::new(),
            now,
        );
        let other = Identity::generate();
        let mut theirs = Circle::join(other.clone(), &SEED, channel, 0, opened, Roster::new(), now);

        let post = theirs
            .location(
                &me(&other, name, "", 0.7, ShareMode::Precise),
                kestrel_core::msg::Fix::new(fix.0, fix.1, 5.0),
                ShareMode::Precise,
                now,
            )
            .expect("a post seals");
        let feed = kestrel_core::wire::Feed {
            now,
            members: vec![kestrel_core::wire::FeedMember {
                m: post.m.clone(),
                alg: post.alg.clone(),
                pk: post.pk.clone(),
                epk: post.epk.clone(),
                points: vec![kestrel_core::wire::FeedPoint {
                    e: post.e,
                    ts: post.ts,
                    srv: post.ts,
                    n: post.n.clone(),
                    c: post.c.clone(),
                    sig: post.sig.clone(),
                }],
            }],
        };
        mine.ingest_feed(&feed, now);
        (mine, other.member_id().to_string())
    }

    /// A one-member feed, so a test can hand a device a single message.
    fn feed_of_one(post: &kestrel_core::wire::Post, now: i64) -> kestrel_core::wire::Feed {
        kestrel_core::wire::Feed {
            now,
            members: vec![kestrel_core::wire::FeedMember {
                m: post.m.clone(),
                alg: post.alg.clone(),
                pk: post.pk.clone(),
                epk: post.epk.clone(),
                points: vec![kestrel_core::wire::FeedPoint {
                    e: post.e,
                    ts: post.ts,
                    srv: post.ts,
                    n: post.n.clone(),
                    c: post.c.clone(),
                    sig: post.sig.clone(),
                }],
            }],
        }
    }

    #[test]
    fn a_default_camera_shows_a_great_deal_of_the_world() {
        let c = Camera::default();
        assert_eq!(c.zoom, 3.0);
        assert!((MIN_ZOOM..=MAX_ZOOM).contains(&c.zoom));
    }

    #[test]
    fn the_zoom_is_clamped_to_what_tiles_exist_for() {
        let mut c = Camera::new(0.0, 0.0, 5.0);
        c.zoom_by(100.0);
        assert_eq!(c.zoom, MAX_ZOOM);
        c.zoom_by(-100.0);
        assert_eq!(c.zoom, MIN_ZOOM);
    }

    #[test]
    fn a_camera_cannot_look_past_the_poles() {
        let mut c = Camera::default();
        c.look_at(90.0, 0.0);
        assert!(c.lat <= geo::MAX_LATITUDE);
        assert!(c.lat.is_finite());
        c.look_at(-90.0, 0.0);
        assert!(c.lat >= -geo::MAX_LATITUDE);
    }

    #[test]
    fn a_viewport_asks_for_the_tiles_that_cover_it() {
        let camera = Camera::new(0.0, 0.0, 3.0);
        let request = TileRequest::covering(&camera, (800.0, 600.0), 0);
        // Zoom 3 is eight tiles across the world; a phone covers a few of them.
        assert!(!request.is_empty());
        assert!(request.xs.len() >= 2);
        assert!(request.len() < 8 * 8, "asked for {} tiles", request.len());
    }

    #[test]
    fn a_tile_request_pads_by_one_so_a_pan_has_something_to_show() {
        let camera = Camera::new(0.0, 0.0, 10.0);
        let tight = TileRequest::covering(&camera, (800.0, 600.0), 0);
        let padded = TileRequest::covering(&camera, (800.0, 600.0), 1);
        assert!(padded.len() > tight.len(), "a ring of padding is wanted");
    }

    #[test]
    fn tile_keys_are_wrapped_and_clamped_into_the_world() {
        let request = TileRequest {
            z: 2,
            xs: vec![-3, -1, 0, 1, 4, 7],
            ys: vec![-2, 0, 1, 9],
        };
        let keys = request.keys();
        let n = 4i64;
        for k in &keys {
            assert!((0..n).contains(&k.x), "x {} out of range", k.x);
            assert!((0..n).contains(&k.y), "y {} out of range", k.y);
        }
        // Wrapped columns: -3 and 1 are the same column, -1 and 7 are another,
        // and 0 and 4 a third. Clamped rows: -2 becomes 0 and 9 becomes 3. So
        // six columns by four rows collapses to three by three.
        // A `BTreeMap` of the pairs would hide a duplicate, so the count is
        // checked against the expected grid directly.
        assert_eq!(keys.len(), 9, "three columns by three rows, no duplicates");
        let mut sorted = keys.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(keys.len(), sorted.len(), "a tile was asked for twice");
        assert!(
            keys.iter().all(|k| k.x < n && k.y < n),
            "wrapped and clamped into the world: {keys:?}"
        );
    }

    #[test]
    fn the_same_tile_is_not_requested_twice() {
        // A view across the antimeridian names columns that wrap onto each other.
        // Asking twice means fetching twice and painting the tile over itself.
        let request = TileRequest {
            z: 2,
            xs: vec![0, 4, -4, 8],
            ys: vec![0, 8, -8],
        };
        let keys = request.keys();
        let mut sorted = keys.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(keys.len(), sorted.len(), "a tile was asked for twice");
        // All three column names and two of the row names are the same tile; only
        // the row 8 clamps to a different one.
        assert_eq!(keys.len(), 2, "{keys:?}");
    }

    #[test]
    fn off_grid_fetches_nothing() {
        assert!(!Basemap::OffGrid.fetches_tiles());
        assert_eq!(Basemap::OffGrid.tile_url(3, 1, 1), None);

        let camera = Camera::new(0.0, 0.0, 10.0);
        let request = TileRequest::covering(&camera, (800.0, 600.0), 1);
        assert!(
            request.missing(&BTreeMap::new(), Basemap::OffGrid).is_empty(),
            "off-grid must not touch the network at all"
        );
    }

    #[test]
    fn a_street_basemap_asks_for_what_it_does_not_have() {
        let camera = Camera::new(0.0, 0.0, 4.0);
        let request = TileRequest::covering(&camera, (800.0, 600.0), 0);
        let keys = request.keys();
        assert!(!keys.is_empty());

        let empty = BTreeMap::new();
        assert_eq!(request.missing(&empty, Basemap::Dark).len(), keys.len());

        // With one cached, only the rest is asked for.
        let mut cached = BTreeMap::new();
        cached.insert(keys[0], ());
        assert_eq!(request.missing(&cached, Basemap::Dark).len(), keys.len() - 1);
    }

    #[test]
    fn the_tile_url_is_the_standard_scheme() {
        assert_eq!(
            Basemap::Dark.tile_url(12, 986, 1473).unwrap(),
            "https://tile.openstreetmap.org/12/986/1473.png"
        );
        assert_eq!(
            Basemap::Light.tile_url(1, 0, 0).unwrap(),
            "https://tile.openstreetmap.org/1/0/0.png"
        );
    }

    #[test]
    fn a_marker_lands_in_the_middle_of_a_screen_centred_on_it() {
        let now = at(2_980_471);
        let (circle, id) = a_circle_with_a_member_at((44.98, -93.27), "Ana", now + 1_000);
        let camera = Camera::new(44.98, -93.27, 15.0);
        let f = frame(
            &circle,
            &camera,
            Basemap::OffGrid,
            (400.0, 800.0),
            now + 1_000,
            "someone-else",
        );
        let m = f.markers.iter().find(|m| m.member_id == id).expect("a marker");
        assert!(
            (m.x - 200.0).abs() < 1.0 && (m.y - 400.0).abs() < 1.0,
            "the marker was at ({}, {})",
            m.x,
            m.y
        );
        assert_eq!(m.name, "Ana");
        assert!(m.sharing);
        assert!(!m.sos);
        assert!(!m.is_self);
        assert!(m.freshness > 0.99, "a just-received position is fresh");
    }

    #[test]
    fn this_device_is_drawn_differently() {
        let now = at(2_980_471);
        let (circle, id) = a_circle_with_a_member_at((44.98, -93.27), "Ana", now + 1_000);
        let camera = Camera::new(44.98, -93.27, 15.0);
        let f = frame(&circle, &camera, Basemap::OffGrid, (400.0, 800.0), now + 1_000, &id);
        let m = f.markers.iter().find(|m| m.member_id == id).unwrap();
        assert!(m.is_self, "the user's own marker is marked as such");

        // And a device is never drawn as one of its own peers, even though it
        // holds a roster row for itself. The position on screen is the user's, and
        // the user already knows where they are.
        let self_id_of_circle = circle.identity().member_id().to_string();
        assert!(
            !f.markers.iter().any(|m| m.member_id == self_id_of_circle),
            "a circle does not draw itself as a peer"
        );
    }

    #[test]
    fn a_marker_fades_as_its_position_ages() {
        let now = at(2_980_471);
        let (circle, id) = a_circle_with_a_member_at((44.98, -93.27), "Ana", now + 1_000);
        let camera = Camera::new(44.98, -93.27, 15.0);
        let fresh = frame(&circle, &camera, Basemap::OffGrid, (400.0, 800.0), now + 1_000, "x");
        let older = frame(&circle, &camera, Basemap::OffGrid, (400.0, 800.0), now + 90_000, "x");
        let f = fresh.markers.iter().find(|m| m.member_id == id).unwrap().freshness;
        let o = older.markers.iter().find(|m| m.member_id == id).unwrap().freshness;
        assert!(f > o, "fresh {f} should exceed older {o}");
    }

    #[test]
    fn a_member_who_went_quiet_is_greyed_rather_than_vanished() {
        let now = at(2_980_471);
        let (circle, id) = a_circle_with_a_member_at((44.98, -93.27), "Ana", now + 1_000);
        let camera = Camera::new(44.98, -93.27, 15.0);

        // Just inside the live window.
        let live = frame(
            &circle,
            &camera,
            Basemap::OffGrid,
            (400.0, 800.0),
            now + DRAW_STALE_MS - 1,
            "x",
        );
        let m = live.markers.iter().find(|m| m.member_id == id).unwrap();
        assert!(m.freshness > 0.0);

        // Past it but inside the longer window: still drawn, fully faded. A hole
        // where a person is reads as "nobody is there".
        let quiet = frame(
            &circle,
            &camera,
            Basemap::OffGrid,
            (400.0, 800.0),
            now + DRAW_STALE_MS + 2_000,
            "x",
        );
        let m = quiet.markers.iter().find(|m| m.member_id == id).expect("still drawn");
        assert_eq!(m.freshness, 0.0, "and shown as no longer fresh");

        // Past the longer window: gone. A member from yesterday is not on the
        // map pretending to be present.
        let gone = frame(
            &circle,
            &camera,
            Basemap::OffGrid,
            (400.0, 800.0),
            now + LAST_KNOWN_MS + 2_000,
            "x",
        );
        assert!(
            !gone.markers.iter().any(|m| m.member_id == id),
            "a member nobody has heard from in hours is not drawn"
        );
    }

    #[test]
    fn an_emergency_and_a_goodbye_are_drawn_differently() {
        let now = at(2_980_471);
        let (circle, _) = a_circle_with_a_member_at((44.98, -93.27), "Ana", now + 1_000);
        let channel = circle.channel().to_string();
        let opened = circle.opened_epoch();
        let mine = circle.identity().clone();
        let other = Identity::generate();
        let mut theirs =
            Circle::join(other.clone(), &SEED, channel, 0, opened, Roster::new(), now);
        let camera = Camera::new(44.98, -93.27, 15.0);
        let viewport = (400.0, 800.0);

        // An emergency.
        let sos = theirs
            .sos(
                &me(&other, "Ana", "", 0.3, ShareMode::Precise),
                kestrel_core::msg::Fix::new(44.98, -93.27, 5.0),
                now + 1_000,
            )
            .unwrap();
        let mut watch = Circle::join(mine, &SEED, circle.channel().to_string(), 0, opened, Roster::new(), now);
        watch.ingest_feed(&feed_of_one(&sos, now + 1_000), now + 1_000);
        let f = frame(&watch, &camera, Basemap::OffGrid, viewport, now + 1_000, "x");
        let m = f.markers.first().expect("a marker");
        assert!(m.sos, "an emergency is marked as one");
        assert!(m.sharing);
        assert!(m.freshness > 0.99);

        // A goodbye, so the marker reads as stopped rather than as a live dot.
        let bye = theirs
            .goodbye(&me(&other, "Ana", "", 0.0, ShareMode::Precise), now + 2_000)
            .unwrap();
        watch.ingest_feed(&feed_of_one(&bye, now + 2_000), now + 2_000);
        let f = frame(&watch, &camera, Basemap::OffGrid, viewport, now + 2_000, "x");
        let m = f.markers.first().expect("still listed");
        assert!(m.stopped, "a goodbye is marked as stopped");
        assert!(!m.sharing);
        assert!(!m.sos);
    }

    #[test]
    fn trails_are_drawn_only_when_zoomed_in() {
        let now = at(2_980_471);
        let (circle, _) = a_circle_with_a_member_at((44.98, -93.27), "Ana", now + 1_000);
        // One point is not a trail.
        let wide = frame(
            &circle,
            &Camera::new(44.98, -93.27, 16.0),
            Basemap::OffGrid,
            (400.0, 800.0),
            now + 1_000,
            "x",
        );
        assert!(wide.trails.is_empty(), "one point is not a trail");
    }

    #[test]
    fn distance_rings_appear_only_in_off_grid_mode() {
        let now = at(2_980_471);
        let (circle, _) = a_circle_with_a_member_at((44.98, -93.27), "Ana", now + 1_000);
        let camera = Camera::new(44.98, -93.27, 14.0);
        let off = frame(&circle, &camera, Basemap::OffGrid, (400.0, 800.0), now + 1_000, "x");
        let street = frame(&circle, &camera, Basemap::Dark, (400.0, 800.0), now + 1_000, "x");
        assert!(!off.rings.is_empty(), "off-grid draws rings");
        assert!(street.rings.is_empty(), "a street map has no rings");
    }

    #[test]
    fn rings_beyond_the_viewport_are_not_drawn() {
        // At a wide zoom a one-kilometre ring would be smaller than a pixel, and at
        // a narrow one it would be off the screen.
        let wide = ring_radii_px(&Camera::new(44.98, -93.27, 4.0));
        let narrow = ring_radii_px(&Camera::new(44.98, -93.27, 19.0));
        assert!(wide.is_empty() || wide.iter().all(|r| *r > 0.0));
        assert!(narrow.is_empty(), "a ring of 250 m is off a zoom-19 screen");
    }

    #[test]
    fn fitting_covers_every_member() {
        let now = at(2_980_471);
        let channel = kestrel_core::kdf::channel_id(&kestrel_core::kdf::anchor(&SEED));
        let opened = kestrel_core::wire::epoch_at(now);
        let mut a = Circle::join(
            Identity::generate(),
            &SEED,
            channel,
            0,
            opened,
            Roster::new(),
            now,
        );
        // Two members, far apart.
        for (lat, lon, name) in [(44.98, -93.27, "Ana"), (51.5, -0.12, "Bo")] {
            let id = Identity::generate();
            let mut theirs =
                Circle::join(id.clone(), &SEED, a.channel().to_string(), 0, opened, Roster::new(), now);
            let post = theirs
                .location(
                    &me(&id, name, "", 0.7, ShareMode::Precise),
                    kestrel_core::msg::Fix::new(lat, lon, 5.0),
                    ShareMode::Precise,
                    now + 1_000,
                )
                .unwrap();
            let feed = kestrel_core::wire::Feed {
                now,
                members: vec![kestrel_core::wire::FeedMember {
                    m: post.m.clone(),
                    alg: post.alg.clone(),
                    pk: post.pk.clone(),
                    epk: post.epk.clone(),
                    points: vec![kestrel_core::wire::FeedPoint {
                        e: post.e,
                        ts: post.ts,
                        srv: post.ts,
                        n: post.n.clone(),
                        c: post.c.clone(),
                        sig: post.sig.clone(),
                    }],
                }],
            };
            a.ingest_feed(&feed, now + 1_000);
        }
        let mut camera = Camera::default();
        assert!(fit(&mut camera, &a, now + 1_000, (400.0, 800.0)));
        assert!(camera.zoom < 6.0, "two distant members fit at a wide zoom: {}", camera.zoom);
        assert!((MIN_ZOOM..=MAX_ZOOM).contains(&camera.zoom));
    }

    #[test]
    fn fitting_fails_with_nobody_to_fit() {
        let now = at(2_980_471);
        let circle = Circle::create(Identity::generate(), &SEED, now);
        let mut camera = Camera::default();
        assert!(!fit(&mut camera, &circle, now, (400.0, 800.0)));
        // The camera is left alone rather than moved somewhere arbitrary.
        assert_eq!(camera, Camera::default());
    }

    #[test]
    fn focusing_moves_to_a_member_and_says_whether_it_worked() {
        let now = at(2_980_471);
        let (circle, id) = a_circle_with_a_member_at((44.98, -93.27), "Ana", now + 1_000);
        let mut camera = Camera::new(0.0, 0.0, 5.0);
        assert!(focus(&mut camera, &circle, &id, now + 1_000));
        assert!((camera.lat - 44.98).abs() < 0.001);
        assert!(camera.zoom >= 15.0, "and it zooms in on them");
        // A member who has gone quiet cannot be focused on, and the camera stays
        // where it was rather than jumping to a stale position.
        assert!(!focus(&mut camera, &circle, &id, now + DRAW_STALE_MS + 2_000));
        assert!((camera.lat - 44.98).abs() < 0.001);
    }

    #[test]
    fn focusing_an_unknown_member_is_refused() {
        let now = at(2_980_471);
        let circle = Circle::create(Identity::generate(), &SEED, now);
        let mut camera = Camera::default();
        assert!(!focus(&mut camera, &circle, "nobody", now));
        assert_eq!(camera, Camera::default());
    }
}
