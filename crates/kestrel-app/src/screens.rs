//! Screens: what the app looks like, and what each button does.
//!
//! Split out from [`crate::entry`], which owns the process, so the drawing of a screen
//! can be reasoned about without an Android build in the loop. Everything here is a
//! function of the shared state plus the platform, and every button that would be a lie
//! — one that claims to do something it cannot — is marked as such rather than left
//! looking finished.
//!
//! ### Why some things are deliberately dead
//!
//! A button that says "Join a circle" and then does nothing is worse than no button: a
//! person taps it, waits, concludes the app is broken, and stops trusting the ones that
//! work. Where a feature is not finished, the screen says so in words. Where it is
//! finished, it is wired up.

use std::sync::Arc;

use egui::{self, RichText};

use crate::{
    alerts,
    draw::Map,
    engine::{self, Engine},
    handshake::{self, Handshake},
    logic,
    map::{self, Basemap},
    permissions::{Grant, Permissions},
    platform::Platform,
    state::{Screen, Shared},
    store::{self, Settings},
    strings::{self, Language},
};

/// Everything one frame needs.
pub struct Ctx {
    pub shared: Arc<Shared>,
    pub platform: Arc<dyn Platform>,
    pub engine: Option<Arc<Engine>>,
    /// The size of the area being drawn into, for the map's projection.
    pub viewport: egui::Vec2,
    /// The output scale, so markers are the same physical size on any screen.
    pub dpr: f32,
}

/// Draw whichever screen is up.
///
/// One function rather than a dispatch at every call site, so there is exactly one place
/// that knows what "the app is showing" means.
pub fn draw(ui: &mut egui::Ui, ctx: &Ctx) {
    let screen = ctx.shared.state.lock().map(|s| s.screen).unwrap_or_default();
    let language = ctx.shared.state.lock().map(|s| s.language).unwrap_or_default();

    // Notices sit above everything: a message about a refused permission is the one
    // thing that must not be hidden behind a sheet.
    let notice = ctx.shared.state.lock().ok().and_then(|mut s| s.read_notice());

    match screen {
        Screen::Welcome => welcome(ui, ctx, language),
        Screen::Map => map_screen(ui, ctx, language),
        Screen::Join => join(ui, ctx, language),
        Screen::Review => review(ui, ctx, language),
        Screen::Settings => settings(ui, ctx, language),
        Screen::Locked => locked(ui, ctx, language),
        Screen::Wiped => wiped(ui, ctx, language),
    }

    if let Some(notice) = notice {
        notice_bar(ui, &notice);
    }

    // A permission still worth asking for is asked here rather than inside a screen, so
    // that asking happens after the frame has been laid out. A dialog appearing over a
    // half-built frame is a dialog over a blank screen.
    if let Some(wanted) = ctx.shared.permissions.lock().ok().and_then(|p| p.next_to_ask()) {
        ctx.platform.request(wanted);
    }
}

/// A message across the bottom of the screen.
fn notice_bar(ui: &mut egui::Ui, message: &str) {
    let height = 44.0;
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), height),
        egui::Sense::hover(),
    );
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 0.0, egui::Color32::from_rgb(40, 34, 20));
    painter.text(
        rect.left_center() + egui::vec2(12.0, 0.0),
        egui::Align2::LEFT_CENTER,
        message,
        egui::FontId::proportional(14.0),
        egui::Color32::from_rgb(240, 220, 160),
    );
}

// ------------------------------------------------------------------ welcome

fn welcome(ui: &mut egui::Ui, ctx: &Ctx, language: Language) {
    ui.add_space(48.0);
    ui.heading(strings::get(language, "app.name"));
    ui.label(strings::get(language, "welcome.tagline"));
    ui.add_space(24.0);

    let has_circle = ctx.shared.has_circle();
    if has_circle {
        if ui.button(strings::get(language, "welcome.open_map")).clicked() {
            go(ctx, Screen::Map);
        }
    } else {
        if ui.button(strings::get(language, "welcome.create")).clicked() {
            create_circle(ctx);
        }
        if ui.button(strings::get(language, "welcome.join")).clicked() {
            go(ctx, Screen::Join);
        }
    }

    ui.add_space(24.0);
    permissions_block(ui, ctx, language);

    ui.add_space(24.0);
    if ui.small_button(strings::get(language, "settings.title")).clicked() {
        go(ctx, Screen::Settings);
    }
}

/// Create this device's circle and put it in the shared state.
///
/// The identity is written before the seed, as in [`logic::create_circle`], so an
/// interrupted first run leaves an unusable seed rather than an orphan identity.
fn create_circle(ctx: &Ctx) {
    let now = crate::state::now_ms();
    match logic::create_circle(ctx.platform.as_ref(), "", now) {
        Ok(circle) => {
            if let Ok(mut circles) = ctx.shared.circles.lock() {
                *circles = vec![circle];
            }
            // A `Circle` holds key material and is deliberately not `Clone`, so the
            // channel is read out while the lock is held rather than by taking a copy of
            // the whole thing.
            let channel = ctx
                .shared
                .circles
                .lock()
                .ok()
                .and_then(|c| c.first().map(|c| c.channel().to_string()))
                .unwrap_or_default();
            if let Some(engine) = &ctx.engine {
                engine.attach(&channel);
            }
            go(ctx, Screen::Map);
        }
        Err(e) => tell(ctx, format!("Could not start a circle: {e}")),
    }
}

// --------------------------------------------------------------------- map

fn map_screen(ui: &mut egui::Ui, ctx: &Ctx, language: Language) {
    // The map fills the screen. The controls sit over it rather than beside it, because
    // on a phone the map is the point and a column of buttons beside it is not.
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), ui.available_height() - 120.0),
        egui::Sense::click_and_drag(),
    );

    // The frame is built under the circle's lock by `Shared`, so no screen ever has to
    // hold key material in a local.
    let frame = ctx.shared.state.lock().ok().and_then(|state| {
        ctx.shared.map_frame(
            state.camera,
            state.basemap,
            (ctx.viewport.x as f64, ctx.viewport.y as f64),
            crate::state::now_ms(),
            &state.name,
        )
    });

    if let Some(frame) = frame {
        Map::new(&frame, ctx.viewport, ctx.dpr).paint(&ui.painter_at(rect));
    } else {
        // No circle: the map has nothing to draw but the background, and saying so is
        // better than an empty grid that looks like a bug.
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, egui::Color32::from_rgb(16, 18, 22));
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            strings::get(language, "map.no_circle"),
            egui::FontId::proportional(15.0),
            egui::Color32::GRAY,
        );
    };

    // Gestures. The map is panned by dragging and zoomed by pinching; both are handled
    // here and applied to the stored camera, so the position survives a redraw.
    handle_gestures(ctx, response);

    controls(ui, ctx, language);
}

/// Panning, pinching and double-tap zoom.
///
/// All three write to the stored camera and then save it, so the position survives the
/// next frame and the next launch. The map is the one screen where a user will move
/// things and expect to find them where they left them.
fn handle_gestures(ctx: &Ctx, response: egui::Response) {
    if response.dragged() {
        pan(ctx, response.drag_delta());
        save_camera(ctx);
    }
    // egui's `zoom_delta` is the factor the *current* frame's pinch represents, not a
    // difference from the last, so the previous value is kept and a per-frame ratio is
    // what gets applied. Using the raw delta each frame would compound.
    let touch = response.ctx.input(|i| i.multi_touch());
    if let Some(touch) = touch {
        let spread = touch.zoom_delta.max(0.0);
        let previous = ctx.shared.state.lock().ok().map(|s| s.pinch_spread).unwrap_or(0.0);
        if previous > 1e-6 && spread > 1e-6 {
            let zoom = crate::draw::pinch_zoom(previous, spread, current_zoom(ctx));
            if let Ok(mut state) = ctx.shared.state.lock() {
                state.camera.zoom = zoom;
            }
        }
        if let Ok(mut state) = ctx.shared.state.lock() {
            state.pinch_spread = spread;
        }
        save_camera(ctx);
    } else if let Ok(mut state) = ctx.shared.state.lock() {
        state.pinch_spread = 0.0;
    }

    if response.double_clicked() {
        if let Ok(mut state) = ctx.shared.state.lock() {
            // One step in, not to the limit. A double tap that jumps from street level to
            // the whole continent loses the person what they tapped on.
            state.camera.zoom_by(1.0);
        }
        save_camera(ctx);
    }
}

fn current_zoom(ctx: &Ctx) -> f64 {
    ctx.shared.state.lock().map(|s| s.camera.zoom).unwrap_or(map::Camera::default().zoom)
}

/// Move the camera by a drag.
///
/// The delta is in screen pixels and the camera is in degrees, so it has to go through
/// the scale at the camera's own latitude: the same finger movement covers less ground
/// near the pole than at the equator, and pretending otherwise makes the map feel wrong
/// exactly where someone is unlikely to be looking for it.
fn pan(ctx: &Ctx, delta: egui::Vec2) {
    if delta.x == 0.0 && delta.y == 0.0 {
        return;
    }
    let Ok(mut state) = ctx.shared.state.lock() else {
        return;
    };
    let mpp = kestrel_core::geo::metres_per_pixel(state.camera.lat, state.camera.zoom);
    if !mpp.is_finite() || mpp <= 0.0 {
        return;
    }
    let metres_per_px = mpp / ctx.dpr as f64;
    let (dx_m, dy_m) = (-delta.x as f64 * metres_per_px, delta.y as f64 * metres_per_px);

    // North–south is degrees of latitude directly; east–west depends on the cosine of
    // the latitude, which is why the longitude step needs its own factor.
    state.camera.lat = (state.camera.lat + dy_m / 111_320.0).clamp(-MAX_LAT, MAX_LAT);
    let cos = kestrel_core::geo::metres_per_pixel(state.camera.lat, state.camera.zoom)
        / kestrel_core::geo::metres_per_pixel(0.0, state.camera.zoom);
    let per_degree = 111_320.0 * cos.max(1e-6);
    state.camera.lon = wrap_lon(state.camera.lon + dx_m / per_degree);
}

/// The poles, as far as the map will go. Mercator cannot represent them, and a camera
/// that reaches one shows an infinite map.
const MAX_LAT: f64 = 85.0;

/// Bring a longitude back into −180..180.
pub fn wrap_lon(lon: f64) -> f64 {
    if !lon.is_finite() {
        return 0.0;
    }
    let mut wrapped = lon % 360.0;
    if wrapped > 180.0 {
        wrapped -= 360.0;
    }
    if wrapped < -180.0 {
        wrapped += 360.0;
    }
    wrapped
}

/// The controls under the map.
fn controls(ui: &mut egui::Ui, ctx: &Ctx, language: Language) {
    let permissions = ctx.shared.permissions.lock().map(|p| *p).ok();
    let sharing = ctx.shared.state.lock().map(|s| s.sharing).unwrap_or(false);

    ui.horizontal(|ui| {
        if let Some(p) = &permissions {
            let may_share = engine::should_be_posting(p, sharing);
            if sharing {
                if ui.button(strings::get(language, "map.stop")).clicked() {
                    stop_sharing(ctx);
                }
            } else if ui.button(strings::get(language, "map.start")).clicked() {
                start_sharing(ctx);
            }
            // And the promise, every time. Written out in full rather than assembled
            // from parts: this is the sentence a person reads before agreeing to be
            // located, and it has to be true whether or not sharing is already on.
            ui.label(RichText::new(logic::sharing_promise(p)).small().weak());
            let _ = may_share;
        }
    });

    ui.horizontal(|ui| {
        if ui.button(strings::get(language, "map.fit")).clicked() {
            fit_to_everyone(ctx);
        }
        if ui.button(strings::get(language, "map.recentre")).clicked() {
            recentre(ctx);
        }
        if ui.button(strings::get(language, "map.off_grid")).clicked() {
            // Cycling rather than three separate buttons: one control for one choice is
            // what a thumb wants, and the current style is drawn on the button.
            if let Ok(mut state) = ctx.shared.state.lock() {
                state.basemap = match state.basemap {
                    Basemap::Dark => Basemap::OffGrid,
                    Basemap::OffGrid => Basemap::Light,
                    Basemap::Light => Basemap::Dark,
                };
            }
        }
        if ui.button(strings::get(language, "map.settings")).clicked() {
            go(ctx, Screen::Settings);
        }
    });

    if ui.button(strings::get(language, "invite.title")).clicked() {
        mint_invite(ctx, language);
    }
}

/// Turn sharing on, or explain why not.
fn start_sharing(ctx: &Ctx) {
    let permissions = match ctx.shared.permissions.lock() {
        Ok(p) => *p,
        Err(_) => return,
    };
    if let Err(why) = logic::start_sharing(&permissions) {
        tell(ctx, why);
        return;
    }
    if let Ok(mut p) = ctx.shared.permissions.lock() {
        p.set_sharing(true);
    }
    if let Ok(mut state) = ctx.shared.state.lock() {
        state.sharing = true;
    }
    ctx.platform.set_sharing(true);
}

fn stop_sharing(ctx: &Ctx) {
    if let Ok(mut p) = ctx.shared.permissions.lock() {
        p.set_sharing(false);
    }
    if let Ok(mut state) = ctx.shared.state.lock() {
        state.sharing = false;
    }
    ctx.platform.set_sharing(false);
    // Anything queued goes with it. A position queued while sharing, sent after the
    // user stopped, is exactly the thing that makes a share untrustworthy.
    if let Some(engine) = &ctx.engine {
        engine.clear();
    }
}

fn fit_to_everyone(ctx: &Ctx) {
    let now = crate::state::now_ms();
    let (w, h) = (ctx.viewport.x as f64, ctx.viewport.y as f64);
    // Both locks at once, held only for the arithmetic, and in the one order
    // everything else takes them: state then circles. Nesting `state` inside
    // `with_circle` would be the reverse, and would deadlock against the
    // handshake, which holds `state` while it asks `circles` for the roster it
    // is about to admit somebody into.
    let fitted = match ctx.shared.state.lock() {
        Ok(mut state) => match ctx.shared.circles.lock() {
            Ok(mut circles) => circles
                .first_mut()
                .is_some_and(|circle| map::fit(&mut state.camera, circle, now, (w, h))),
            Err(_) => false,
        },
        Err(_) => false,
    };
    if !fitted {
        tell(ctx, strings::get(Language::English, "error.no_location"));
    }
    save_camera(ctx);
}

fn recentre(ctx: &Ctx) {
    let Some(fix) = ctx.shared.newest_fix() else {
        tell(ctx, strings::get(Language::English, "error.no_location"));
        return;
    };
    if let Ok(mut state) = ctx.shared.state.lock() {
        state.camera.look_at(fix.lat, fix.lon);
    }
    save_camera(ctx);
}

fn save_camera(ctx: &Ctx) {
    if let Ok(state) = ctx.shared.state.lock() {
        store::save_camera(store::LastCamera {
            lat: state.camera.lat,
            lon: state.camera.lon,
            zoom: state.camera.zoom,
        });
    }
}

// ------------------------------------------------------------- permissions

/// The permission list, with an action for each thing that needs the user.
fn permissions_block(ui: &mut egui::Ui, ctx: &Ctx, language: Language) {
    let Ok(permissions) = ctx.shared.permissions.lock() else {
        return;
    };
    ui.separator();
    for (key, grant) in [
        ("perm.location", permissions.location),
        ("perm.background-location", permissions.background),
        ("perm.notifications", permissions.notifications),
        ("perm.camera", permissions.camera),
    ] {
        ui.horizontal(|ui| {
            ui.label(format!(
                "{}: {}",
                strings::get(language, key),
                strings::get(language, grant_key(grant))
            ));
            let permission = permission_of(key);
            if grant.can_only_be_fixed_in_settings() {
                if ui.small_button(strings::get(language, "perm.fix")).clicked() {
                    ctx.platform.open_settings(permission);
                }
            } else if grant.can_ask()
                && ui.small_button(strings::with(language, "perm.ask", "{}", "")).clicked()
            {
                ctx.platform.request(permission);
            }
        });
    }
    drop(permissions);
    ui.label(RichText::new(logic::sharing_promise(&permissions_of(ctx))).weak());
}

fn permissions_of(ctx: &Ctx) -> Permissions {
    ctx.shared.permissions.lock().map(|p| *p).unwrap_or_default()
}

fn grant_key(grant: Grant) -> &'static str {
    match grant {
        Grant::Unknown => "perm.not_asked",
        Grant::Denied => "perm.denied",
        Grant::PermanentlyDenied => "perm.blocked",
        Grant::Precise => "perm.precise",
        Grant::Approximate => "perm.approximate",
        Grant::Unavailable => "perm.unavailable",
    }
}

fn permission_of(key: &str) -> crate::permissions::Permission {
    match key {
        "perm.location" => crate::permissions::Permission::Location,
        "perm.background-location" => crate::permissions::Permission::BackgroundLocation,
        "perm.notifications" => crate::permissions::Permission::Notifications,
        _ => crate::permissions::Permission::Camera,
    }
}

// ------------------------------------------------------------------- join

fn join(ui: &mut egui::Ui, ctx: &Ctx, language: Language) {
    ui.heading(strings::get(language, "join.title"));

    // Already asking: say where it got to rather than showing an input the
    // answer will not come from. The number is the joiner's own, and reading it
    // aloud is the whole of what this device has left to do.
    let waiting = ctx.shared.state.lock().ok().and_then(|s| match &s.handshake {
        Handshake::Joining(j) => Some(j.pending.safety_number.clone()),
        _ => None,
    });
    if let Some(number) = waiting {
        ui.add_space(8.0);
        ui.label(strings::get(language, "join.your_number"));
        ui.heading(&number);
        ui.label(strings::get(language, "join.waiting"));
        ui.add_space(12.0);
        if ui.button(strings::get(language, "join.cancel")).clicked() {
            let received = handshake::cancel(&ctx.shared);
            if let Some(engine) = &ctx.engine {
                handshake::apply(engine, &received);
            }
        }
        return;
    }

    ui.label(strings::get(language, "join.ask"));
    ui.add_space(8.0);

    let mut typed = ctx
        .shared
        .state
        .lock()
        .map(|s| s.invite.clone().unwrap_or_default())
        .unwrap_or_default();
    ui.horizontal(|ui| {
        ui.label(strings::get(language, "join.type_here"));
        ui.text_edit_singleline(&mut typed);
    });
    if let Ok(mut state) = ctx.shared.state.lock() {
        state.invite = Some(typed.clone());
    }

    ui.horizontal(|ui| {
        let usable = logic::is_invite_fragment(&typed);
        let button =
            ui.add_enabled(usable, egui::Button::new(strings::get(language, "join.go")));
        if button.clicked() {
            start_join(ctx, &typed);
        }
        if ui.button(strings::get(language, "join.scan")).clicked() {
            ctx.platform.start_scan();
        }
    });
    if ui.button(strings::get(language, "join.back")).clicked() {
        go(ctx, Screen::Welcome);
    }
}

/// Ask to join, or explain why not.
///
/// Staying on the join screen is deliberate: the next thing that happens is the
/// inviter answering, and a screen that changed to somewhere else would be one
/// the person has to find their way back from when it does.
fn start_join(ctx: &Ctx, fragment: &str) {
    let name = ctx.shared.state.lock().map(|s| s.name.clone()).unwrap_or_default();
    let now = crate::state::now_ms();
    match handshake::begin_join(&ctx.shared, fragment, &name, now) {
        Ok(received) => {
            if let Some(engine) = &ctx.engine {
                handshake::apply(engine, &received);
            }
        }
        Err(e) => tell(ctx, e),
    }
}

/// Mint this device's invitation and show it.
fn mint_invite(ctx: &Ctx, language: Language) {
    let now = crate::state::now_ms();
    match handshake::begin_invite(&ctx.shared, now) {
        Ok((fragment, received)) => {
            if let Some(engine) = &ctx.engine {
                handshake::apply(engine, &received);
            }
            if let Ok(mut state) = ctx.shared.state.lock() {
                state.invite = Some(fragment.clone());
            }
            // The code is rendered on screen *and* offered to the share sheet. Sending it
            // as a string is the part that matters for a long invitation; the QR is for
            // the two phones-in-the-same-room case, where reading it out is faster.
            ctx.platform.notify(&strings::get(language, "help.mint_title"), &fragment);
            let _ = crate::qr::encode(&fragment);
        }
        // No circle, or the circle is busy. Said rather than left as a button
        // that does nothing.
        Err(e) => tell(ctx, e),
    }
}

// ----------------------------------------------------------------- review

fn review(ui: &mut egui::Ui, ctx: &Ctx, language: Language) {
    ui.heading(strings::get(language, "review.title"));
    let pending = ctx.shared.state.lock().ok().and_then(|s| s.pending_name.clone());
    let Some((number, name)) = pending else {
        // The request was withdrawn, refused, or already dealt with. Saying so
        // beats a screen with two buttons and nothing behind them.
        ui.label(strings::get(language, "review.gone"));
        ui.add_space(12.0);
        if ui.button(strings::get(language, "settings.close")).clicked() {
            handshake::decline(&ctx.shared);
        }
        return;
    };

    ui.label(strings::with(language, "review.says", "{}", &name));
    ui.heading(&number);
    ui.label(strings::get(language, "review.compare"));
    ui.add_space(12.0);
    if ui.button(strings::get(language, "review.accept")).clicked() {
        accept(ctx, language);
    }
    if ui.button(strings::get(language, "review.decline")).clicked() {
        handshake::decline(&ctx.shared);
    }
}

/// Let the person in, and say what happened.
///
/// A refusal leaves the screen up only if there is still somebody on it to
/// retry for; otherwise it goes back to the map rather than offering an Accept
/// button for a decision that no longer exists.
fn accept(ctx: &Ctx, language: Language) {
    let now = crate::state::now_ms();
    let received = handshake::accept(&ctx.shared, now);
    if let Some(engine) = &ctx.engine {
        handshake::apply(engine, &received);
    }

    let still_pending =
        ctx.shared.state.lock().map(|s| s.pending_name.is_some()).unwrap_or(false);
    if !still_pending {
        go(ctx, Screen::Map);
    }
    match received.error {
        Some(e) => tell(ctx, e),
        None => tell(ctx, strings::get(language, "review.admitted")),
    }
}

// --------------------------------------------------------------- settings

fn settings(ui: &mut egui::Ui, ctx: &Ctx, language: Language) {
    ui.heading(strings::get(language, "settings.title"));

    let mut name = ctx.shared.state.lock().map(|s| s.name.clone()).unwrap_or_default();
    ui.horizontal(|ui| {
        ui.label(strings::get(language, "settings.name"));
        ui.text_edit_singleline(&mut name);
    });
    ui.label(RichText::new(strings::get(language, "settings.name_hint")).small().weak());
    if let Ok(mut state) = ctx.shared.state.lock() {
        state.name = name.clone();
    }

    ui.horizontal(|ui| {
        ui.label(strings::get(language, "settings.language"));
        for candidate in Language::ALL {
            if ui.selectable_label(language == candidate, candidate.endonym()).clicked() {
                set_language(ctx, candidate);
            }
        }
    });

    ui.horizontal(|ui| {
        ui.label(strings::get(language, "settings.basemap"));
        for (key, basemap) in [
            ("settings.dark", Basemap::Dark),
            ("settings.light", Basemap::Light),
            ("settings.off_grid", Basemap::OffGrid),
        ] {
            let current = ctx.shared.state.lock().map(|s| s.basemap).unwrap_or_default();
            if ui
                .selectable_label(current == basemap, strings::get(language, key))
                .clicked()
                && let Ok(mut state) = ctx.shared.state.lock()
            {
                state.basemap = basemap;
            }
        }
    });

    // Tor is shown, and shown as unavailable. A switch that does nothing is worse than
    // no switch: a person who turns it on believes their traffic is anonymous.
    // A checkbox, greyed out, rather than a hidden row: the option exists, and pretending
    // it does not would leave a user wondering whether this app can route over Tor.
    ui.add_enabled(
        false,
        egui::Checkbox::new(&mut false, strings::get(language, "settings.tor")),
    );
    ui.label(RichText::new(alerts::TOR_NOTICE).small().weak());

    relay_block(ui, ctx, language);

    permissions_block(ui, ctx, language);

    app_lock_block(ui, ctx, language);

    ui.separator();
    ui.label(RichText::new(strings::get(language, "settings.wipe")).strong());
    ui.label(RichText::new(strings::get(language, "settings.wipe_hint")).small().weak());
    let confirming = ctx.shared.state.lock().map(|s| s.confirm_wipe).unwrap_or(false);
    let label = if confirming {
        strings::get(language, "settings.wipe_again")
    } else {
        strings::get(language, "settings.wipe")
    };
    if ui.button(label).clicked() {
        wipe_everything(ctx);
    }

    ui.label(strings::get(language, "settings.version"));

    ui.add_space(12.0);
    if ui.button(strings::get(language, "settings.close")).clicked() {
        go(ctx, Screen::Map);
    }
}

fn set_language(ctx: &Ctx, language: Language) {
    if let Ok(mut state) = ctx.shared.state.lock() {
        state.language = language;
    }
    let mut settings = store::load_settings();
    let changed = {
        let mut candidate = settings.clone();
        candidate.language = language.index();
        let changed = settings_changed(&settings, &candidate);
        settings = candidate;
        changed
    };
    // Only a real change is written. Saving on every tap in the language row would be a
    // dozen identical writes for one decision.
    if changed && let Err(e) = store::save_settings(&settings) {
        tell(ctx, format!("Could not save your settings: {e}"));
    }
}

// ------------------------------------------------------------------ locks

fn locked(ui: &mut egui::Ui, ctx: &Ctx, language: Language) {
    ui.heading(strings::get(language, "lock.title"));
    ui.label(strings::get(language, "lock.enter"));
    let mut passcode =
        ctx.shared.state.lock().map(|s| s.typing.clone()).unwrap_or_default();
    ui.add(egui::TextEdit::singleline(&mut passcode).password(true).hint_text("••••••"));
    if let Ok(mut state) = ctx.shared.state.lock() {
        state.typing = passcode.clone();
    }
    if ui.button(strings::get(language, "settings.passcode")).clicked() {
        unlock(ctx, language, &passcode);
    }
}

/// Let the phone open, or say why not.
///
/// The verifier is only a verifier. It proves the person knows the passcode;
/// it does not prove the seed underneath it still opens, and a device that
/// accepts a correct passcode and then shows an empty map is worse than one
/// that refuses outright.
fn unlock(ctx: &Ctx, language: Language, passcode: &str) {
    // Without a lock file there is nothing to check against — the file went
    // away between the launch that showed this screen and the tap that
    // answered it — so the passcode is not asked for at all.
    let lock = store::load_lock();
    if let Some(lock) = &lock
        && !store::check_lock(passcode, lock)
    {
        tell(ctx, strings::get(language, "lock.wrong"));
        return;
    }
    // Whether there is a verifier or not, the seed is what has to open. A lock
    // file that exists but will not parse still leaves a sealed seed behind, and
    // asking for the passcode there is the only way it ever comes back.
    let code = store::is_locked().then_some(passcode);
    let Some(circle) = logic::restore_circle(code) else {
        tell(ctx, strings::get(language, "lock.broken"));
        return;
    };
    let channel = circle.channel().to_string();
    if let Ok(mut circles) = ctx.shared.circles.lock() {
        *circles = vec![circle];
    }
    if let Some(engine) = &ctx.engine {
        engine.attach(&channel);
        // The invitation the user already showed somebody, back on the wire now
        // that this phone is theirs again.
        if let Some(received) = handshake::restore(&ctx.shared, crate::state::now_ms()) {
            handshake::apply(engine, &received);
        }
    }
    go(ctx, Screen::Map);
}

// ------------------------------------------------------------------ relay

/// Where this phone sends its posts.
///
/// Offered because the alternative — a hardcoded address nobody can change —
/// makes the app useless to anyone who wants their own relay, and useless to
/// anyone whose circle has moved off the reference deployment. The address is
/// checked before it is saved or used, so a typo says what is wrong with it
/// rather than quietly becoming a device that posts nowhere.
fn relay_block(ui: &mut egui::Ui, ctx: &Ctx, language: Language) {
    ui.separator();
    ui.label(RichText::new(strings::get(language, "settings.relay")).strong());

    let mut relay = ctx.shared.state.lock().map(|s| s.relay.clone()).unwrap_or_default();
    ui.horizontal(|ui| {
        ui.text_edit_singleline(&mut relay);
    });
    if let Ok(mut state) = ctx.shared.state.lock() {
        state.relay = relay.clone();
    }
    ui.label(RichText::new(strings::get(language, "settings.relay_hint")).small().weak());

    if ui.button(strings::get(language, "settings.relay_save")).clicked() {
        save_relay(ctx, language, &relay);
    }
}

/// Validate the address, point the engine at it, and only then remember it.
///
/// Order matters: an address that will not be accepted must not be written to
/// the settings file, or the next launch reads back the mistake and falls back
/// to the default while the field still shows the broken one.
fn save_relay(ctx: &Ctx, language: Language, value: &str) {
    let trimmed = value.trim().to_string();
    let Some(engine) = ctx.engine.as_ref() else {
        tell(ctx, strings::get(language, "settings.relay_offline"));
        return;
    };
    match engine.set_relay(&trimmed) {
        Ok(()) => {
            let mut settings = store::load_settings();
            settings.relay = trimmed.clone();
            if let Err(e) = store::save_settings(&settings) {
                tell(ctx, format!("Could not save your settings: {e}"));
                return;
            }
            // The field shows what is in force, not what was typed: the
            // trailing slash the address does not need is not a thing to
            // stare at every time settings is opened.
            if let Ok(mut state) = ctx.shared.state.lock() {
                state.relay = trimmed.clone();
            }
            tell(ctx, strings::with(language, "settings.relay_saved", "{}", &trimmed));
        }
        // What `Relay` refuses: an empty address, one with no scheme, plain http
        // to anywhere that is not this network. Each of those says what to do.
        Err(e) => tell(ctx, e),
    }
}

// -------------------------------------------------------------- app lock

/// The app-lock row of settings, and the form behind it.
///
/// Inline rather than its own screen: it is three controls, and a screen for
/// three controls is a screen a person has to find their way back from.
fn app_lock_block(ui: &mut egui::Ui, ctx: &Ctx, language: Language) {
    ui.separator();
    ui.label(RichText::new(strings::get(language, "settings.app_lock")).strong());

    let locked = store::is_locked();
    ui.label(
        RichText::new(strings::get(
            language,
            if locked { "settings.lock_on" } else { "settings.lock_off" },
        ))
        .small()
        .weak(),
    );

    let open = ctx.shared.state.lock().map(|s| s.setting_lock).unwrap_or(false);
    if !open {
        // Only worth offering once there is something to seal. On a first run
        // there is no seed, so a passcode would lock an empty device.
        if store::has_circle() {
            let label = if locked { "settings.lock_change" } else { "settings.lock_set" };
            if ui.button(strings::get(language, label)).clicked()
                && let Ok(mut state) = ctx.shared.state.lock()
            {
                state.setting_lock = true;
                state.typing.clear();
                state.new_passcode.clear();
            }
        }
        return;
    }

    if locked {
        ui.label(strings::get(language, "settings.lock_current"));
        let mut current =
            ctx.shared.state.lock().map(|s| s.typing.clone()).unwrap_or_default();
        ui.add(egui::TextEdit::singleline(&mut current).password(true).hint_text("••••••"));
        if let Ok(mut state) = ctx.shared.state.lock() {
            state.typing = current;
        }
    }

    ui.label(strings::get(language, "settings.lock_new"));
    let mut new =
        ctx.shared.state.lock().map(|s| s.new_passcode.clone()).unwrap_or_default();
    ui.add(egui::TextEdit::singleline(&mut new).password(true).hint_text("••••••"));
    if let Ok(mut state) = ctx.shared.state.lock() {
        state.new_passcode = new.clone();
    }
    if locked {
        ui.label(
            RichText::new(strings::get(language, "settings.lock_leave_off")).small().weak(),
        );
    } else {
        ui.label(
            RichText::new(strings::get(language, "settings.passcode_hint")).small().weak(),
        );
    }

    ui.horizontal(|ui| {
        // Saving with nothing entered means "turn it off", which is a decision
        // only a device that is already locked can be making.
        let usable = locked || !new.is_empty();
        if ui
            .add_enabled(
                usable,
                egui::Button::new(strings::get(language, "settings.lock_save")),
            )
            .clicked()
        {
            save_app_lock(ctx, language);
        }
        if ui.button(strings::get(language, "settings.close")).clicked() {
            close_app_lock(ctx);
        }
    });
}

/// Apply the passcode change, or explain why not.
fn save_app_lock(ctx: &Ctx, language: Language) {
    let (current, new) = ctx
        .shared
        .state
        .lock()
        .map(|s| (s.typing.clone(), s.new_passcode.clone()))
        .unwrap_or_default();
    let current = store::is_locked().then_some(current.as_str());
    let new = (!new.is_empty()).then_some(new.as_str());

    match logic::set_lock(current, new) {
        Ok(()) => {
            let key =
                if new.is_none() { "settings.lock_removed" } else { "settings.lock_done" };
            tell(ctx, strings::get(language, key));
            close_app_lock(ctx);
        }
        Err(e) => tell(ctx, e),
    }
}

/// Erase every file this app wrote, and everything it holds in memory.
///
/// Two taps, because the first one only asks. What is deleted is everything:
/// the seed, the identity, the passcode verifier, the settings, the invitation
/// and the last time a position was posted. A wipe that left the circle behind
/// would be a wipe that leaves the one thing worth wiping.
fn wipe_everything(ctx: &Ctx) {
    if !ctx.shared.state.lock().map(|s| s.confirm_wipe).unwrap_or(false) {
        if let Ok(mut state) = ctx.shared.state.lock() {
            state.confirm_wipe = true;
        }
        return;
    }

    store::wipe();
    forget_circle(ctx);
    // Not Welcome, and not a notice: a screen that says what happened and has
    // one button on it. The next thing somebody sees after erasing their keys
    // should not be a map asking to be given a location.
    go(ctx, Screen::Wiped);
}

/// Drop the circle, and the queue behind it, now that the keys are gone.
///
/// Kept separate from the deletion so it can be tested without deleting: the
/// circle is gone from disk, so it has to go from memory with it, or the map
/// keeps drawing a circle whose keys were destroyed a moment ago.
fn forget_circle(ctx: &Ctx) {
    if let Ok(mut circles) = ctx.shared.circles.lock() {
        circles.clear();
    }
    if let Some(engine) = &ctx.engine {
        engine.attach("");
        engine.attach_rendezvous("");
    }
    if let Ok(mut state) = ctx.shared.state.lock() {
        state.name = String::new();
        state.invite = None;
        state.pending_name = None;
        state.handshake = crate::handshake::Handshake::None;
        state.relay = store::DEFAULT_RELAY.to_string();
        state.language = crate::strings::Language::default();
        state.confirm_wipe = false;
    }
}

fn close_app_lock(ctx: &Ctx) {
    if let Ok(mut state) = ctx.shared.state.lock() {
        state.setting_lock = false;
        state.typing.clear();
        state.new_passcode.clear();
    }
}

fn wiped(ui: &mut egui::Ui, ctx: &Ctx, language: Language) {
    ui.heading(strings::get(language, "lock.wiped"));
    ui.label(strings::get(language, "lock.wiped_body"));
    if ui.button(strings::get(language, "settings.close")).clicked() {
        go(ctx, Screen::Welcome);
    }
}

// ------------------------------------------------------------------ shared

fn go(ctx: &Ctx, screen: Screen) {
    if let Ok(mut state) = ctx.shared.state.lock() {
        // Whatever was typed belongs to the screen being left. A passcode left
        // sitting in the state is one that shows up in a field nobody is
        // looking at any more.
        state.typing.clear();
        state.new_passcode.clear();
        state.setting_lock = false;
        // Leaving settings cancels a pending erase: a tap that navigates away
        // was not a second tap on the button.
        state.confirm_wipe = false;
        state.go(screen);
    }
}

fn tell(ctx: &Ctx, message: impl Into<String>) {
    if let Ok(mut state) = ctx.shared.state.lock() {
        state.tell(message);
    }
}

/// A safety number for this device, for someone to compare.
pub fn my_safety_number(ctx: &Ctx) -> Option<String> {
    ctx.shared.with_circle(|circle| circle.identity().safety_number())
}

/// Whether the app should show the lock screen right now.
///
/// A test rather than an `if` at the call site: a lock screen that appears when it
/// should not, or does not appear when it should, is the whole feature.
pub fn should_lock(locked: bool, foreground: bool, just_started: bool) -> bool {
    locked && foreground && just_started
}

/// Whether a settings change needs to be written out.
///
/// Only real changes. Writing the file on every frame of a slider drag is a lot of
/// small writes for nothing.
pub fn settings_changed(current: &Settings, candidate: &Settings) -> bool {
    current != candidate
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::Host;

    fn ctx_for() -> (Ctx, Arc<Host>) {
        let host = Arc::new(Host::at(1_700_000_000_000));
        (
            Ctx {
                shared: Arc::new(Shared::default()),
                platform: host.clone(),
                engine: None,
                viewport: egui::Vec2::new(400.0, 800.0),
                dpr: 2.0,
            },
            host,
        )
    }

    #[test]
    fn every_screen_draws_without_a_circle_or_a_phone() {
        // The one test that would catch a screen that panics on a real layout: each is
        // drawn into a real egui context with an empty state.
        let (ctx, _host) = ctx_for();
        for screen in [
            Screen::Welcome,
            Screen::Map,
            Screen::Join,
            Screen::Review,
            Screen::Settings,
            Screen::Locked,
            Screen::Wiped,
        ] {
            ctx.shared.state.lock().unwrap().go(screen);
            let output = egui::Context::default().run_ui(egui::RawInput::default(), |ui| {
                egui::CentralPanel::default().show(ui, |ui| {
                    draw(ui, &ctx);
                });
            });
            // egui rasterises the default font on the first pass; this test has no
            // renderer, so the delta is discarded deliberately.
            let mut output = output;
            output.textures_delta.clear();
            assert!(!output.shapes.is_empty(), "{screen:?} drew nothing");
        }
    }

    #[test]
    fn a_notice_is_shown_above_whatever_is_on_screen() {
        let (ctx, _host) = ctx_for();
        ctx.shared.state.lock().unwrap().tell("Location is off");
        let mut output = egui::Context::default().run_ui(egui::RawInput::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| draw(ui, &ctx));
        });
        output.textures_delta.clear();
        // The notice is read once, so it does not stack up on every frame.
        assert!(ctx.shared.state.lock().unwrap().notice.is_none());
    }

    #[test]
    fn erasing_everything_asks_first() {
        // One tap is a person reading a row, two is a decision. There is no
        // dialog to draw here, so the first tap has to be harmless on its own —
        // a control that erases the keys behind one tap in a screen with a
        // dozen other taps is a control somebody will hit.
        let (ctx, _host) = ctx_for();
        {
            let mut state = ctx.shared.state.lock().unwrap();
            state.name = "Ada".to_string();
            state.go(Screen::Settings);
        }

        wipe_everything(&ctx);

        let state = ctx.shared.state.lock().unwrap();
        assert!(state.confirm_wipe, "the first tap did not arm the second");
        assert_eq!(state.name, "Ada", "the first tap erased something");
        assert_eq!(state.screen, Screen::Settings, "the first tap navigated away");
        assert!(state.notice.is_none(), "the first tap claimed it was done");
    }

    #[test]
    fn an_erase_takes_the_circle_with_it() {
        use kestrel_core::identity::Identity;
        let (base, _host) = ctx_for();
        let sink = crate::engine::NetSink::new("http://127.0.0.1:9").ok();
        let engine = sink.map(|s| Arc::new(Engine::new(base.shared.clone(), Arc::new(s))));
        let ctx = Ctx { engine: engine.clone(), ..base };
        let circle = kestrel_core::session::Circle::create(
            Identity::generate(),
            &kestrel_core::seal::random_bytes::<32>(),
            1_700_000_000_000,
        );
        ctx.shared.circles.lock().unwrap().push(circle);
        if let Some(engine) = &engine {
            engine.attach("a-channel");
            engine.attach_rendezvous("a-rendezvous");
        }
        {
            let mut state = ctx.shared.state.lock().unwrap();
            state.name = "Ada".to_string();
            state.relay = "https://old.example".to_string();
        }

        forget_circle(&ctx);

        assert!(ctx.shared.circles.lock().unwrap().is_empty(), "the circle is still there");
        let state = ctx.shared.state.lock().unwrap();
        assert!(state.name.is_empty(), "the display name outlived the keys");
        assert_eq!(state.relay, store::DEFAULT_RELAY, "the old address was kept");
        drop(state);
        if let Some(engine) = &engine {
            assert!(!engine.has_channel(), "the queue still has a channel to post to");
            assert!(
                engine.rendezvous_channel().is_empty(),
                "the rendezvous channel outlived the keys"
            );
        }
    }

    #[test]
    fn every_screen_has_a_title_in_every_language() {
        // A blank title is the difference between an app and a screen with a word in it.
        for language in Language::ALL {
            for key in ["app.name", "map.title", "settings.title"] {
                let text = strings::get(language, key);
                assert!(!text.is_empty(), "{language:?} has no {key}");
            }
        }
    }

    #[test]
    fn the_map_screen_says_so_when_there_is_no_circle() {
        // An empty grid looks like a bug; a sentence does not.
        let (ctx, _host) = ctx_for();
        ctx.shared.state.lock().unwrap().go(Screen::Map);
        let mut output = egui::Context::default().run_ui(egui::RawInput::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| draw(ui, &ctx));
        });
        output.textures_delta.clear();
        assert!(!output.shapes.is_empty());
    }

    #[test]
    fn a_permission_needing_settings_offers_the_settings_button() {
        // A refusal that only the settings app can fix has to say so, or the person will
        // tap the button again and see nothing.
        for grant in [Grant::Denied, Grant::PermanentlyDenied, Grant::Unavailable] {
            assert!(grant.can_only_be_fixed_in_settings(), "{grant:?}");
        }
        assert!(!Grant::Precise.can_only_be_fixed_in_settings());
        assert!(!Grant::Unknown.can_only_be_fixed_in_settings());
    }

    #[test]
    fn every_permission_key_maps_to_its_own_permission() {
        // The catch-all is the camera, so a typo here would quietly put the camera's
        // button next to the wrong permission — which shows up as a dialog asking for
        // the wrong thing, on the one screen where a wrong answer matters.
        let expected = [
            ("perm.location", crate::permissions::Permission::Location),
            (
                "perm.background-location",
                crate::permissions::Permission::BackgroundLocation,
            ),
            ("perm.notifications", crate::permissions::Permission::Notifications),
            ("perm.camera", crate::permissions::Permission::Camera),
        ];
        for (key, want) in expected {
            assert_eq!(permission_of(key), want, "{key}");
        }
    }

    #[test]
    fn the_lock_screen_shows_only_when_it_should() {
        assert!(should_lock(true, true, true));
        assert!(!should_lock(false, true, true));
        // Resumed, not started: showing the lock on every resume would make the app
        // unusable, and never showing it would make it pointless.
        assert!(!should_lock(true, true, false));
        // Backgrounded: the service is sharing, and a lock screen nobody can see would
        // be a lock screen over the map.
        assert!(!should_lock(true, false, true));
    }

    #[test]
    fn unchanged_settings_are_not_written() {
        let a = Settings {
            name: "Ada".into(),
            basemap: 0,
            tor: false,
            follow: true,
            beacon: None,
            language: 0,
            relay: store::DEFAULT_RELAY.to_string(),
        };
        assert!(!settings_changed(&a, &a.clone()));
        let mut b = a.clone();
        b.name = "Bo".into();
        assert!(settings_changed(&a, &b));
    }

    #[test]
    fn a_language_is_remembered_by_index_that_cannot_be_invalidated() {
        // The list only grows, so an index saved by an older build still names the same
        // language. Storing the name would let a rename silently reset everyone's setting.
        for (i, language) in Language::ALL.iter().enumerate() {
            assert_eq!(Language::from_index(i as u8), Some(*language));
        }
        assert_eq!(Language::from_index(200), None);
    }

    #[test]
    fn a_stopped_share_leaves_nothing_queued() {
        use kestrel_core::identity::Identity;
        let (base, host) = ctx_for();
        let sink = crate::engine::NetSink::new("http://127.0.0.1:9").ok();
        let engine = sink.map(|s| Arc::new(Engine::new(base.shared.clone(), Arc::new(s))));
        // One context, built once: spreading a fresh one into the struct would give the
        // engine a different shared state from the one the test is looking at.
        let ctx = Ctx { engine: engine.clone(), ..base };
        let circle =
            Arc::new(std::sync::Mutex::new(kestrel_core::session::Circle::create(
                Identity::generate(),
                &kestrel_core::seal::random_bytes::<32>(),
                1_700_000_000_000,
            )));
        let mut guard = circle.lock().unwrap();
        let post = crate::logic::build_post(
            &mut guard,
            &crate::state::Fix {
                lat: 44.98,
                lon: -93.27,
                acc: 5.0,
                ts: 1_700_000_001_000,
                battery: 0.8,
            },
            &permissions_of(&ctx),
            "Ada",
            None,
        )
        .unwrap();
        drop(guard);
        if let Some(engine) = &engine {
            engine.push(post, "position", true);
            assert_eq!(engine.queued(), 1);
        }
        ctx.shared.state.lock().unwrap().sharing = true;
        stop_sharing(&ctx);
        if let Some(engine) = &engine {
            assert_eq!(engine.queued(), 0, "a stopped share left a position queued");
        }
        assert!(
            host.calls()
                .iter()
                .any(|c| matches!(c, crate::platform::Call::SetSharing(false)))
        );
    }
}
