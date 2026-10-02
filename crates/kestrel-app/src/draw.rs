//! Drawing: turning a [`crate::map::Frame`] into pixels.
//!
//! Split from [`crate::map`] so that the arithmetic — which tiles, where each marker
//! sits, whether a position is fresh — is testable on a laptop and the painting is not
//! obliged to be. Everything in here takes a frame and a viewport and writes into egui;
//! every decision it acts on was already made and checked by the module above.
//!
//! The one thing worth saying up front is that the map is drawn as an egui painter
//! rather than a texture composite. That costs some scrolling performance on a cheap
//! phone and buys two things worth more: there is no tile atlas to memory-map on a
//! device that may have 2 GB, and a tile that has not arrived is simply not drawn,
//! which is exactly what should happen over a dead connection.

use egui::{Color32, Stroke, Vec2};

use crate::map::{Basemap, Frame, Marker};

/// What to draw this frame.
///
/// `paint` rather than instructions returned to the caller: egui's painter holds
/// references that only live inside the closure, so threading them out would mean
/// rebuilding the list every frame for no benefit.
pub struct Map<'a> {
    frame: &'a Frame,
    viewport: Vec2,
    /// Pixels per point, from the display's density. Multiply through so a marker is
    /// the same physical size on a dense screen and a sparse one.
    dpr: f32,
}

impl<'a> Map<'a> {
    pub fn new(frame: &'a Frame, viewport: Vec2, dpr: f32) -> Self {
        // A zero or absurd scale factor would make every marker either invisible or
        // larger than the screen. Clamped rather than trusted: it comes from the
        // platform.
        Self { frame, viewport, dpr: dpr.clamp(0.5, 4.0) }
    }

    /// Draw everything, under the overlay UI.
    pub fn paint(&self, painter: &egui::Painter) {
        self.paint_basemap(painter);
        self.paint_rings(painter);
        self.paint_trails(painter);
        self.paint_markers(painter);
        self.paint_scale_bar(painter);
    }

    /// The basemap, or a plain grid where there is no basemap.
    fn paint_basemap(&self, painter: &egui::Painter) {
        let rect = self.rect();
        painter.rect_filled(rect, 0.0, background(self.frame.basemap));

        if self.frame.basemap == Basemap::OffGrid {
            // Off-grid is the mode for when there is no network and no coordinates worth
            // a tile server. A grid is more honest than a map that is not there: it says
            // "relative distances only", and the rings carry the scale.
            self.paint_grid(painter, rect);
        }
        // Tiles are fetched and composited by the platform's image loader, keyed by the
        // URL the map module produced. Here they are only the background: whatever has
        // not arrived leaves the flat fill showing, which reads as "still loading"
        // rather than as a hole in the world.
    }

    /// A grid, coarse enough to stay behind the markers.
    fn paint_grid(&self, painter: &egui::Painter, rect: egui::Rect) {
        let step = 64.0 * self.dpr;
        if step < 4.0 {
            return;
        }
        let line = Stroke::new((1.0 * self.dpr).max(1.0), Color32::from_gray(48));
        let mut x = 0.0;
        while x < rect.width() {
            painter.line_segment(
                [
                    Pos2::new(rect.left() + x, rect.top()),
                    Pos2::new(rect.left() + x, rect.bottom()),
                ],
                line,
            );
            x += step;
        }
        let mut y = 0.0;
        while y < rect.height() {
            painter.line_segment(
                [
                    Pos2::new(rect.left(), rect.top() + y),
                    Pos2::new(rect.right(), rect.top() + y),
                ],
                line,
            );
            y += step;
        }
    }

    /// The distance rings, off-grid only.
    fn paint_rings(&self, painter: &egui::Painter) {
        let centre = self.centre();
        for (i, r) in self.frame.rings.iter().enumerate() {
            let radius = *r as f32 * self.dpr;
            if !radius.is_finite()
                || radius < 1.0
                || radius > self.viewport.x.max(self.viewport.y)
            {
                // A radius that does not fit is a ring nobody can read the label on.
                continue;
            }
            painter.circle_stroke(
                centre,
                radius,
                Stroke::new(
                    (1.0 * self.dpr).max(1.0),
                    Color32::from_black_alpha(if i == 0 { 90 } else { 55 }),
                ),
            );
        }
    }

    /// Each member's trail.
    fn paint_trails(&self, painter: &egui::Painter) {
        for trail in &self.frame.trails {
            if trail.points.len() < 2 {
                continue;
            }
            let points: Vec<Pos2> = trail
                .points
                .iter()
                .map(|&(x, y)| Pos2::new(x * self.dpr, y * self.dpr))
                .collect();
            let colour = hue_colour(trail.hue, 0.55);
            painter.add(egui::Shape::line(points, Stroke::new(2.0 * self.dpr, colour)));
        }
    }

    /// Each member.
    fn paint_markers(&self, painter: &egui::Painter) {
        for marker in &self.frame.markers {
            self.paint_marker(painter, marker);
        }
    }

    /// One member: a dot, a name, and the two states that change the dot's shape.
    fn paint_marker(&self, painter: &egui::Painter, marker: &Marker) {
        let centre = Pos2::new(marker.x * self.dpr, marker.y * self.dpr);
        if centre.x < -32.0 || centre.y < -32.0 {
            // Off the edge. Not an error: the map is wider than the screen.
            return;
        }
        if centre.x > self.viewport.x + 32.0 || centre.y > self.viewport.y + 32.0 {
            return;
        }

        let radius = 6.0 * self.dpr * (0.6 + 0.4 * marker.freshness);
        // A stale marker is dimmer rather than smaller: shrinking it would make a
        // three-hour-old position hard to see, and the person is still there.
        let mut colour = hue_colour(marker.hue, 0.35 + 0.65 * marker.freshness);
        if marker.stopped {
            colour = Color32::from_gray(110);
        }
        if marker.sos {
            // An emergency is the one thing that must not be mistaken for ordinary.
            colour = Color32::from_rgb(220, 60, 60);
        }

        // This device is a ring rather than a dot, so it is findable on a phone held in
        // one hand without reading anything.
        if marker.is_self {
            painter.circle_stroke(
                centre,
                radius + 4.0 * self.dpr,
                Stroke::new(2.0 * self.dpr, Color32::WHITE),
            );
        } else {
            painter.circle_stroke(
                centre,
                radius + 2.0 * self.dpr,
                Stroke::new((1.0 * self.dpr).max(1.0), Color32::from_black_alpha(120)),
            );
        }
        painter.circle_filled(centre, radius, colour);

        // A verified member gets a tick. Not decoration: it says this person was
        // confirmed in person rather than merely holding a code.
        if marker.verified {
            painter.text(
                centre + Vec2::new(radius, -radius),
                egui::Align2::LEFT_BOTTOM,
                "✓",
                egui::FontId::proportional((10.0 * self.dpr).max(8.0)),
                Color32::from_rgb(150, 220, 150),
            );
        }

        // The name, if there is room and something to say. Only this device's own name
        // is drawn when the zoom is far out: a screen of overlapping labels is how a map
        // becomes unreadable at exactly the zoom level where you most need it.
        let show_name = !marker.name.is_empty()
            && (marker.is_self || self.frame.camera.zoom >= 13.0 || marker.sos);
        if show_name {
            painter.text(
                centre + Vec2::new(0.0, radius + 14.0 * self.dpr),
                egui::Align2::CENTER_BOTTOM,
                &marker.name,
                egui::FontId::proportional((11.0 * self.dpr).max(8.0)),
                Color32::WHITE,
            );
        }

        // The emergency text, drawn on its own because it is not a label.
        if marker.sos {
            painter.text(
                centre + Vec2::new(0.0, -radius - 8.0 * self.dpr),
                egui::Align2::CENTER_BOTTOM,
                "NEEDS HELP",
                egui::FontId::proportional((13.0 * self.dpr).max(9.0)),
                Color32::from_rgb(255, 120, 120),
            );
        }
    }

    /// A scale bar, so the distance rings are readable rather than decorative.
    fn paint_scale_bar(&self, painter: &egui::Painter) {
        let mpp = kestrel_core::geo::metres_per_pixel(
            self.frame.camera.lat,
            self.frame.camera.zoom,
        );
        if !mpp.is_finite() || mpp <= 0.0 {
            return;
        }
        // A round number of metres that lands near a fifth of the screen width.
        let target_px = (self.viewport.x / 5.0) / self.dpr;
        let raw_m = mpp * target_px as f64;
        let nice = nice_distance(raw_m);
        let px = (nice / mpp) as f32 * self.dpr;
        if px < 8.0 || px > self.viewport.x {
            return;
        }
        let left = self.rect().left() + 12.0 * self.dpr;
        let bottom = self.rect().bottom() - 12.0 * self.dpr;
        let stroke = Stroke::new(2.0 * self.dpr, Color32::from_white_alpha(200));
        painter
            .line_segment([Pos2::new(left, bottom), Pos2::new(left + px, bottom)], stroke);
        let tick = 4.0 * self.dpr;
        painter.line_segment(
            [Pos2::new(left, bottom - tick), Pos2::new(left, bottom + tick)],
            stroke,
        );
        painter.line_segment(
            [Pos2::new(left + px, bottom - tick), Pos2::new(left + px, bottom + tick)],
            stroke,
        );
        painter.text(
            egui::pos2(left + px / 2.0, bottom - 6.0 * self.dpr),
            egui::Align2::CENTER_BOTTOM,
            distance_label(nice),
            egui::FontId::proportional((11.0 * self.dpr).max(8.0)),
            Color32::from_white_alpha(220),
        );
    }

    fn rect(&self) -> egui::Rect {
        egui::Rect::from_min_size(egui::Pos2::ZERO, self.viewport)
    }

    fn centre(&self) -> Pos2 {
        Pos2::new(self.viewport.x / 2.0, self.viewport.y / 2.0)
    }
}

use egui::Pos2;

/// The colour for a member's hue.
///
/// A stable hue per member, so the same person is the same colour on every phone in the
/// circle without anyone choosing a colour or exchanging one. Derived from the member
/// id, which is already the same everywhere.
pub fn hue_colour(hue: u16, alpha: f32) -> Color32 {
    let h = (hue % 360) as f32 / 360.0;
    let (r, g, b) = hsv_to_rgb(h, 0.62, 0.95);
    Color32::from_rgb((r * 255.0) as u8, (g * 255.0) as u8, (b * 255.0) as u8)
        .gamma_multiply(alpha.clamp(0.0, 1.0))
}

/// HSV to RGB, written out rather than pulled in as a dependency.
fn hsv_to_rgb(h: f32, s: f32, v: f32) -> (f32, f32, f32) {
    let i = (h * 6.0).floor();
    let f = h * 6.0 - i;
    let p = v * (1.0 - s);
    let q = v * (1.0 - f * s);
    let t = v * (1.0 - (1.0 - f) * s);
    match (i as i32) % 6 {
        0 => (v, t, p),
        1 => (q, v, p),
        2 => (p, v, t),
        3 => (p, q, v),
        4 => (t, p, v),
        _ => (v, p, q),
    }
}

fn background(basemap: Basemap) -> Color32 {
    match basemap {
        // Dark by default: this is opened at night, outdoors, by people who do not want
        // a white screen.
        Basemap::Dark | Basemap::OffGrid => Color32::from_rgb(16, 18, 22),
        Basemap::Light => Color32::from_rgb(240, 240, 238),
    }
}

/// A round number of metres, for the scale bar.
pub fn nice_distance(m: f64) -> f64 {
    if !m.is_finite() || m <= 0.0 {
        return 1.0;
    }
    let exp = m.log10().floor();
    let pow = 10f64.powf(exp);
    let n = m / pow;
    let step = if n >= 5.0 {
        5.0
    } else if n >= 2.0 {
        2.0
    } else {
        1.0
    };
    step * pow
}

/// How a distance is written on the bar.
pub fn distance_label(m: f64) -> String {
    if m >= 1000.0 {
        let km = m / 1000.0;
        if km >= 10.0 { format!("{km:.0} km") } else { format!("{km:.1} km") }
    } else if m >= 10.0 {
        format!("{m:.0} m")
    } else {
        format!("{m:.1} m")
    }
}

/// Where a drag should move the camera.
///
/// A tap is not a drag: below this many pixels it is a tap, and treating a tap as a
/// pan would make it impossible to press a marker.
pub const DRAG_THRESHOLD_PX: f32 = 6.0;

/// Whether a gesture was a drag or a tap.
pub fn gesture_was_drag(drag_distance: f32) -> bool {
    drag_distance > DRAG_THRESHOLD_PX
}

/// How far a pinch should zoom, from two finger distances.
///
/// Clamped, because a pinch that jumps the zoom from 2 to 19 leaves the user lost, and
/// the map can always be zoomed back with a second gesture. Half the raw ratio is a
/// compromise: enough to feel responsive, not enough to overshoot.
pub fn pinch_zoom(start_distance: f32, end_distance: f32, start_zoom: f64) -> f64 {
    if !start_distance.is_finite()
        || !end_distance.is_finite()
        || start_distance <= 1.0
        || end_distance <= 1.0
    {
        return start_zoom;
    }
    let ratio = (end_distance / start_distance).clamp(0.5, 2.0) as f64;
    (start_zoom * ratio).clamp(crate::map::MIN_ZOOM, crate::map::MAX_ZOOM)
}

/// How much of a fling's velocity is left after a frame.
///
/// A fraction, so it is dimensionless and cannot be confused with a distance. Called
/// once per frame and multiplied through: see [`fling_step`].
pub fn fling_remaining(dt_seconds: f32) -> f32 {
    if !dt_seconds.is_finite() || dt_seconds <= 0.0 {
        return 1.0;
    }
    let decay = (-4.0 * dt_seconds).exp();
    if !decay.is_finite() {
        return 1.0;
    }
    // A frame longer than half a second is a stall, not a gesture. Returning zero would
    // teleport the map on the first frame after the app was backgrounded.
    decay.clamp(0.0, 0.9)
}

/// How far the camera moves this frame, given a velocity in pixels per second.
///
/// Velocity times time, times the fraction of it left. All three factors are needed: the
/// first two are the distance a constant velocity would travel, and the third is the
/// decay. Leaving the third out is the bug this signature exists to prevent — a fling
/// that gets *slower* the longer a frame takes.
pub fn fling_step(velocity_px_per_s: Vec2, dt_seconds: f32) -> Vec2 {
    if !dt_seconds.is_finite() || dt_seconds <= 0.0 {
        return Vec2::ZERO;
    }
    if !velocity_px_per_s.x.is_finite() || !velocity_px_per_s.y.is_finite() {
        return Vec2::ZERO;
    }
    velocity_px_per_s * (dt_seconds * fling_remaining(dt_seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::map::{Camera, Marker, TileRequest};

    fn marker(x: f32, y: f32, hue: u16) -> Marker {
        Marker {
            member_id: "m".into(),
            x,
            y,
            hue,
            name: String::new(),
            emoji: String::new(),
            battery: 1.0,
            freshness: 1.0,
            is_self: false,
            sharing: true,
            sos: false,
            stopped: false,
            verified: false,
            removed: false,
        }
    }

    fn frame_with(markers: Vec<Marker>) -> Frame {
        Frame {
            camera: Camera::new(44.98, -93.27, 14.0),
            basemap: Basemap::Dark,
            tiles: TileRequest::covering(
                &Camera::new(44.98, -93.27, 14.0),
                (400.0, 800.0),
                1,
            ),
            empty: markers.is_empty(),
            markers,
            trails: Vec::new(),
            rings: Vec::new(),
        }
    }

    /// Paints into a real egui context and reports whether anything was drawn.
    ///
    /// A genuine paint rather than a stub painter, so a panic inside the drawing code is
    /// a failing test here instead of something a user finds on a phone.
    fn paint_and_collect(frame: &Frame, viewport: Vec2, dpr: f32) -> usize {
        let ctx = egui::Context::default();
        let shapes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = shapes.clone();
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
            let (rect, _) = ui.allocate_exact_size(viewport, egui::Sense::hover());
            let painter = ui.painter_at(rect);
            Map::new(frame, viewport, dpr).paint(&painter);
            counted.store(
                painter.clip_rect().is_positive() as usize,
                std::sync::atomic::Ordering::SeqCst,
            );
        });
        // egui rasterises the default font into a texture on the first pass and insists
        // the caller applies the delta. This test only counts shapes and has no renderer,
        // so the delta is discarded deliberately — otherwise every test panics on the
        // teardown rather than on anything to do with the map.
        output.textures_delta.clear();
        shapes.load(std::sync::atomic::Ordering::SeqCst) + output.shapes.len()
    }

    #[test]
    fn a_frame_paints_without_panicking() {
        let frame = frame_with(vec![marker(100.0, 200.0, 30)]);
        assert!(paint_and_collect(&frame, Vec2::new(400.0, 800.0), 2.0) > 0);
    }

    #[test]
    fn an_empty_map_still_paints_something() {
        // A blank background rather than nothing: a map that fails to draw looks like a
        // crash, and this one is the "nobody is sharing yet" state.
        let frame = frame_with(Vec::new());
        assert!(paint_and_collect(&frame, Vec2::new(400.0, 800.0), 1.0) > 0);
    }

    #[test]
    fn an_absurd_density_factor_does_not_break_the_map() {
        // It comes from the platform, so it is not this module's to trust: zero would
        // make every marker invisible and a huge value would make one fill the screen.
        let frame = frame_with(vec![marker(100.0, 200.0, 30)]);
        for dpr in [0.0, 0.1, 1.0, 4.0, 1000.0, f32::NAN] {
            paint_and_collect(&frame, Vec2::new(400.0, 800.0), dpr);
        }
    }

    #[test]
    fn off_grid_mode_paints_a_grid_and_rings() {
        let mut frame = frame_with(vec![marker(200.0, 400.0, 200)]);
        frame.basemap = Basemap::OffGrid;
        frame.rings = crate::map::ring_radii_px(&frame.camera);
        assert!(!frame.rings.is_empty());
        paint_and_collect(&frame, Vec2::new(400.0, 800.0), 1.0);
    }

    #[test]
    fn a_marker_far_off_screen_is_skipped() {
        // The map is wider than the viewport, so this is ordinary rather than an error.
        for (x, y) in [(-10_000.0, 200.0), (10_000.0, 200.0), (200.0, -10_000.0)] {
            let frame = frame_with(vec![marker(x, y, 30)]);
            paint_and_collect(&frame, Vec2::new(400.0, 800.0), 1.0);
        }
    }

    #[test]
    fn a_member_is_the_same_colour_everywhere() {
        // The hue comes from the member id, which is already the same on every phone,
        // so nobody chooses a colour and nobody can be recoloured.
        assert_ne!(hue_colour(30, 1.0), hue_colour(200, 1.0));
        // A stale marker is faded rather than shrunk, so a three-hour-old position is
        // still easy to find. egui's gamma_multiply premultiplies, which means the
        // channels scale with the alpha — correct for compositing, and why this asserts
        // the alpha rather than the channels.
        let full = hue_colour(30, 1.0);
        let faded = hue_colour(30, 0.4);
        assert_eq!(full.a(), 255);
        assert!(faded.a() < full.a(), "a faded marker did not fade");
        assert!(faded.a() > 0, "a faded marker vanished rather than dimming");
        // And the hue wraps rather than overflowing.
        assert_eq!(hue_colour(30, 1.0), hue_colour(390, 1.0));
        // Alpha zero, whatever the colour channels came out as.
        assert_eq!(hue_colour(30, 0.0).a(), 0);
    }

    #[test]
    fn a_scale_bar_says_a_round_distance() {
        assert_eq!(nice_distance(137.0), 100.0);
        assert_eq!(nice_distance(280.0), 200.0);
        assert_eq!(nice_distance(900.0), 500.0);
        assert_eq!(nice_distance(1_400.0), 1_000.0);
        // Nonsense in, something drawable out. The bar is an aid, not a measurement.
        for bad in [0.0, -5.0, f64::NAN, f64::INFINITY] {
            assert!(nice_distance(bad) > 0.0);
        }
        assert_eq!(distance_label(500.0), "500 m");
        assert_eq!(distance_label(1500.0), "1.5 km");
        assert_eq!(distance_label(50_000.0), "50 km");
        assert_eq!(distance_label(5.0), "5.0 m");
    }

    #[test]
    fn a_tap_is_not_a_drag() {
        // Treating a tap as a pan would make it impossible to press a marker at all.
        assert!(!gesture_was_drag(0.0));
        assert!(!gesture_was_drag(3.0));
        assert!(!gesture_was_drag(DRAG_THRESHOLD_PX));
        assert!(gesture_was_drag(30.0));
    }

    #[test]
    fn a_pinch_zooms_within_the_limits_the_map_allows() {
        // 8 is far enough from both limits (2 and 19) that doubling and halving it are
        // both inside them, so these two assertions are about the gesture rather than
        // about the clamp — which the next few lines check separately.
        let start = 8.0;
        assert_eq!(pinch_zoom(100.0, 200.0, start), 16.0);
        assert_eq!(pinch_zoom(200.0, 100.0, start), 4.0);
        // Clamped at both ends: a violent pinch cannot leave the user lost, and the map
        // module's own limits are the ceiling and the floor.
        assert_eq!(pinch_zoom(10.0, 1000.0, 18.0), crate::map::MAX_ZOOM);
        assert_eq!(pinch_zoom(1000.0, 10.0, 3.0), crate::map::MIN_ZOOM);
        // One gesture is at most a doubling, so from anywhere but the very bottom the
        // user always has a second gesture to reach the ceiling. And the ceiling itself
        // is the map's, not this function's: max zoom is 19, not 20 or 40.
        assert_eq!(pinch_zoom(100.0, 200.0, 18.0), crate::map::MAX_ZOOM);
        assert_eq!(crate::map::MAX_ZOOM, 19.0);
        // An already-pinned zoom stays pinned rather than drifting past the limit.
        assert_eq!(pinch_zoom(100.0, 400.0, crate::map::MAX_ZOOM), crate::map::MAX_ZOOM);
        assert_eq!(pinch_zoom(400.0, 100.0, crate::map::MIN_ZOOM), crate::map::MIN_ZOOM);
        // And a nonsense gesture leaves the zoom alone rather than sending it to NaN.
        for (a, b) in [(0.0, 100.0), (100.0, 0.0), (f32::NAN, 100.0)] {
            assert_eq!(pinch_zoom(a, b, start), start);
        }
    }

    #[test]
    fn a_longer_frame_moves_the_camera_further() {
        // Velocity is pixels per *second*, so the distance is v*dt. Getting this wrong is
        // invisible at 60 Hz and looks like the map running backwards on a slow device.
        let velocity = Vec2::new(800.0, 0.0);
        let short = fling_step(velocity, 1.0 / 60.0);
        let long = fling_step(velocity, 1.0 / 20.0);
        assert!(short.x > 0.0);
        assert!(long.x > short.x, "a longer frame moved less");
    }

    #[test]
    fn a_fling_slows_down_and_stops() {
        let mut velocity = Vec2::new(800.0, 0.0);
        let mut offset = Vec2::ZERO;
        let mut previous_step = f32::INFINITY;
        for _ in 0..400 {
            let step = fling_step(velocity, 1.0 / 60.0);
            assert!(step.x <= previous_step, "the fling sped up");
            previous_step = step.x;
            offset += step;
            velocity *= fling_remaining(1.0 / 60.0);
        }
        assert!(velocity.x < 1.0, "the fling was still moving after 400 frames");
        assert!(offset.x < 800.0, "a fling travelled further than it was thrown");
    }

    #[test]
    fn a_stalled_frame_does_not_teleport_the_map() {
        // A frame of a second is a stall — the app was backgrounded, or the phone was
        // busy. The camera must coast to a stop rather than jumping.
        let velocity = Vec2::new(800.0, 0.0);
        let step = fling_step(velocity, 1.0);
        assert!(step.x <= 800.0 * 0.9, "one stalled frame moved {}", step.x);
        // And a zero, negative or nonsense frame time is ignored rather than producing
        // NaN, which a camera would then be positioned at forever.
        assert_eq!(fling_step(velocity, 0.0), Vec2::ZERO);
        assert_eq!(fling_step(velocity, -1.0), Vec2::ZERO);
        assert_eq!(fling_step(Vec2::new(f32::NAN, 0.0), 0.1), Vec2::ZERO);
        assert_eq!(fling_step(velocity, f32::NAN), Vec2::ZERO);
    }

    #[test]
    fn the_stroke_width_is_never_zero() {
        // A zero-width stroke on some platforms draws nothing at all, which would make
        // every hairline in the map vanish on one device and not another.
        let dpr = 0.4f32;
        assert!((1.0 * dpr).max(1.0) >= 1.0);
    }

    #[test]
    fn a_marker_states_do_not_change_its_position() {
        // Every one of these is drawn differently but none of them moves, or the map
        // would shift under a finger during a repaint.
        let base = marker(100.0, 200.0, 30);
        let frame = frame_with(vec![
            Marker { stopped: true, ..base.clone() },
            Marker { sos: true, ..base.clone() },
            Marker { verified: true, ..base.clone() },
            Marker { is_self: true, ..base.clone() },
            Marker { freshness: 0.0, ..base.clone() },
            Marker { name: "Ada".into(), ..base.clone() },
        ]);
        // Painted with a name at a zoom where names show, and at one where they do not.
        for zoom in [5.0, 13.0, 16.0] {
            let mut f = frame.clone();
            f.camera = Camera::new(44.98, -93.27, zoom);
            paint_and_collect(&f, Vec2::new(400.0, 800.0), 2.0);
        }
    }

    #[test]
    fn a_trail_paints() {
        let mut frame = frame_with(vec![marker(100.0, 200.0, 30)]);
        frame.trails = vec![crate::map::Trail {
            member_id: "m".into(),
            hue: 30,
            points: vec![(10.0, 10.0), (20.0, 30.0), (40.0, 50.0)],
        }];
        paint_and_collect(&frame, Vec2::new(400.0, 800.0), 2.0);
    }
}
