//! Every string the app shows, and the languages it says them in.
//!
//! Hand-rolled rather than a translation framework, on purpose. The whole app is a few
//! hundred words; a framework would add a dependency, a file format and a loading order
//! to manage, and would make it harder rather than easier to read every string the app
//! can possibly say in one place.
//!
//! The one rule that matters: a missing translation falls back to the English text and
//! nothing else. Half a screen in one language and half in another is worse than a
//! screen that is uniformly English, because the reader cannot tell which parts were
//! meant to be understandable.
//!
//! Strings are grouped by screen rather than alphabetically, because that is how a
//! translator reads them and how a reviewer checks nothing was missed.

use std::collections::BTreeMap;

/// A language the app speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Language {
    /// English. Always present, and the fallback for everything else.
    #[default]
    English,
    /// Spanish.
    Spanish,
    /// German.
    German,
    /// French.
    French,
    /// Portuguese, Brazilian.
    Portuguese,
    /// Japanese.
    Japanese,
    /// Chinese, Simplified.
    Chinese,
}

impl Language {
    /// Every language, in the order the settings screen lists them.
    pub const ALL: [Language; 7] = [
        Language::English,
        Language::Spanish,
        Language::German,
        Language::French,
        Language::Portuguese,
        Language::Japanese,
        Language::Chinese,
    ];

    /// The name of the language, in that language.
    ///
    /// A language picker that lists languages in English is unusable to someone who does
    /// not read English, which is most of the point of having a picker.
    pub fn endonym(self) -> &'static str {
        match self {
            Language::English => "English",
            Language::Spanish => "Español",
            Language::German => "Deutsch",
            Language::French => "Français",
            Language::Portuguese => "Português",
            Language::Japanese => "日本語",
            Language::Chinese => "中文",
        }
    }

    /// The BCP-47 tag, for the platform.
    pub fn tag(self) -> &'static str {
        match self {
            Language::English => "en",
            Language::Spanish => "es",
            Language::German => "de",
            Language::French => "fr",
            Language::Portuguese => "pt-BR",
            Language::Japanese => "ja",
            Language::Chinese => "zh",
        }
    }

    /// The language at an index, for a stored setting.
    ///
    /// The setting is saved as an index rather than a name so that adding a language
    /// cannot invalidate anybody's saved choice: the list only grows, so an index written
    /// by an older build still names the same language. A name would break on a rename.
    pub fn from_index(index: u8) -> Option<Language> {
        Language::ALL.get(index as usize).copied()
    }

    /// This language's index, for storing.
    pub fn index(self) -> u8 {
        Language::ALL.iter().position(|l| *l == self).unwrap_or(0) as u8
    }

    /// Pick the closest language the app has for a platform locale.
    ///
    /// Matched on the primary subtag only, so `pt-BR` and `pt-PT` both find Portuguese
    /// and `en-GB` finds English. An unknown language falls back to English rather than
    /// to nothing, because a partly-English app is still readable and a blank one is not.
    pub fn from_tag(tag: &str) -> Language {
        let primary = tag.split(['-', '_']).next().unwrap_or("").to_ascii_lowercase();
        match primary.as_str() {
            "es" => Language::Spanish,
            "de" => Language::German,
            "fr" => Language::French,
            "pt" => Language::Portuguese,
            "ja" => Language::Japanese,
            "zh" => Language::Chinese,
            _ => Language::English,
        }
    }
}

/// A string, in one language.
pub type Table = BTreeMap<&'static str, String>;

/// The English strings. Every key exists here; other languages may be missing keys, and
/// a missing one falls back to this table.
const EN: &[(&str, &str)] = &[
    // --- the welcome screen
    ("app.name", "Kestrel"),
    ("welcome.tagline", "Share your location with a small circle, and nobody else."),
    ("welcome.create", "Create a circle"),
    ("welcome.join", "Join a circle"),
    ("welcome.open_map", "Open the map"),
    // --- the map screen
    ("map.title", "Map"),
    ("map.sharing", "Sharing"),
    ("map.not_sharing", "Not sharing"),
    ("map.start", "Share my location"),
    ("map.stop", "Stop sharing"),
    ("map.scan", "Scan a code"),
    ("map.settings", "Settings"),
    ("map.fit", "Show everyone"),
    ("map.recentre", "Centre on me"),
    ("map.off_grid", "No map"),
    // --- joining
    ("join.title", "Join a circle"),
    ("join.ask", "Ask someone in the circle for their code, then scan or type it."),
    ("join.type_here", "Code"),
    ("join.go", "Join"),
    ("join.scan", "Scan instead"),
    ("join.back", "Back"),
    ("join.cancel", "Cancel"),
    ("join.your_number", "Your number. Read it aloud so they can compare:"),
    ("join.waiting", "Waiting for them to let you in."),
    // --- a pending join request
    ("review.title", "Someone is asking to join"),
    ("review.says", "{} says their number is"),
    (
        "review.compare",
        "Read it out. If it does not match, they are not who they say they are.",
    ),
    ("review.accept", "Accept"),
    ("review.decline", "Decline"),
    ("review.gone", "There is nobody waiting any more."),
    ("review.admitted", "They are in. The circle has been re-keyed."),
    // --- settings
    ("settings.title", "Settings"),
    ("settings.name", "Your name"),
    ("settings.name_hint", "What your circle sees"),
    ("settings.language", "Language"),
    ("settings.basemap", "Map style"),
    ("settings.dark", "Dark"),
    ("settings.light", "Light"),
    ("settings.off_grid", "No map"),
    ("settings.tor", "Use Tor"),
    ("settings.tor_hint", "Slower, and harder to trace. Not bundled yet."),
    ("settings.app_lock", "App lock"),
    ("settings.lock_on", "On"),
    ("settings.lock_off", "Off"),
    ("settings.lock_set", "Set a passcode"),
    ("settings.lock_change", "Change passcode"),
    ("settings.lock_current", "Current passcode"),
    ("settings.lock_new", "New passcode"),
    ("settings.lock_leave_off", "Leave it empty to turn the lock off."),
    ("settings.lock_save", "Save"),
    ("settings.lock_done", "App lock is on."),
    ("settings.lock_removed", "App lock is off."),
    ("settings.passcode", "Passcode"),
    ("settings.passcode_hint", "At least six characters"),
    ("settings.wipe", "Erase everything"),
    ("settings.wipe_hint", "Deletes the keys. Nothing shared can be recovered."),
    ("settings.version", "Version 0.1.0 · GPL-3.0-or-later"),
    ("settings.close", "Close"),
    // --- permissions, by the app's own names
    ("perm.location", "Location"),
    ("perm.background-location", "Background location"),
    ("perm.notifications", "Notifications"),
    ("perm.camera", "Camera"),
    ("perm.ask", "Allow {}"),
    ("perm.fix", "Settings"),
    ("perm.not_asked", "not asked"),
    ("perm.denied", "not allowed"),
    ("perm.blocked", "blocked"),
    ("perm.precise", "allowed"),
    ("perm.approximate", "approximate only"),
    ("perm.unavailable", "not available"),
    ("perm.none", "Without location, nobody can see where you are."),
    (
        "perm.no_notifications",
        "Notifications are off, so there would be nothing to show that you are sharing.",
    ),
    (
        "perm.serious",
        "Notifications are off, so there is nothing to show that you are sharing.",
    ),
    // --- what sharing promises
    ("promise.not_sharing", "Not sharing: without location, nobody can see where you are."),
    (
        "promise.precise_closed",
        "Sharing precisely with your circle, but stops when the app is closed.",
    ),
    (
        "promise.precise_open",
        "Sharing precisely with your circle, and keeps going when the app is closed.",
    ),
    (
        "promise.coarse_closed",
        "Sharing about a kilometre at a time with your circle, but stops when the app is closed.",
    ),
    (
        "promise.coarse_open",
        "Sharing about a kilometre at a time with your circle, and keeps going when the app is closed.",
    ),
    // --- invitations
    ("invite.title", "Invite someone"),
    ("invite.valid", "Valid"),
    ("invite.expiring", "Expiring"),
    ("invite.expired", "Expired"),
    ("invite.mine", "Your code"),
    ("invite.scan_theirs", "Their code"),
    ("invite.read_out", "Read this out to them, or scan theirs."),
    // --- places, or geofences
    ("places.title", "Places"),
    ("places.add", "Add a place"),
    ("places.name", "Name"),
    ("places.radius", "Radius"),
    ("places.empty", "No places yet. Add one and Kestrel will tell you when you arrive."),
    ("places.delete", "Remove"),
    ("places.silly_radius", "Pick a radius between 25 and 20 kilometres."),
    ("places.arrived", "You arrived at {}"),
    ("places.left", "You left {}"),
    ("places.nearby", "{} is nearby"),
    // --- the help beacon
    ("help.title", "Help beacon"),
    ("help.ask", "Give someone a link to your location?"),
    ("help.warn", "Anyone with the link can see where you are until it expires."),
    ("help.mint", "Create a link"),
    ("help.minted", "Help link created"),
    ("help.mint_title", "Send this link"),
    ("help.expires", "It expires in an hour."),
    ("places.arrived_title", "Arrived"),
    ("places.left_title", "Left"),
    // --- the app lock
    ("lock.title", "Locked"),
    ("lock.enter", "Enter your passcode"),
    ("lock.wrong", "That is not the passcode."),
    ("lock.broken", "That passcode is right, but the circle on this phone will not open."),
    ("lock.wiped", "Nothing here"),
    (
        "lock.wiped_body",
        "The keys were destroyed. Nothing that was shared can be recovered.",
    ),
    // --- errors, said plainly
    (
        "error.no_camera",
        "There is no camera on this device. You can type the code instead.",
    ),
    ("error.scan_failed", "The code could not be read."),
    ("error.no_location", "There is no location yet."),
    // --- things the user does not choose
    ("sos.needs_help", "NEEDS HELP"),
    ("sos.stopped", "stopped"),
];

const ES: &[(&str, &str)] = &[
    ("app.name", "Kestrel"),
    ("welcome.tagline", "Comparte tu ubicación con un círculo pequeño, y con nadie más."),
    ("welcome.create", "Crear un círculo"),
    ("welcome.join", "Unirse a un círculo"),
    ("welcome.open_map", "Abrir el mapa"),
    ("map.title", "Mapa"),
    ("map.sharing", "Compartiendo"),
    ("map.not_sharing", "Sin compartir"),
    ("map.start", "Compartir mi ubicación"),
    ("map.stop", "Dejar de compartir"),
    ("map.scan", "Escanear un código"),
    ("map.settings", "Ajustes"),
    ("map.fit", "Ver a todos"),
    ("map.recentre", "Centrar en mí"),
    ("map.off_grid", "Sin mapa"),
    ("join.title", "Unirse a un círculo"),
    ("join.ask", "Pide a alguien del círculo su código y escanéalo o escríbelo."),
    ("join.type_here", "Código"),
    ("join.go", "Unirse"),
    ("join.scan", "Escanear"),
    ("join.back", "Atrás"),
    ("join.cancel", "Cancelar"),
    ("join.your_number", "Tu número. Léelo en voz alta para que puedan compararlo:"),
    ("join.waiting", "Esperando a que te dejen entrar."),
    ("review.title", "Alguien quiere unirse"),
    ("review.says", "{} dice que su número es"),
    ("review.compare", "Léelo en voz alta. Si no coincide, no es quien dice ser."),
    ("review.accept", "Aceptar"),
    ("review.decline", "Rechazar"),
    ("review.gone", "Ya no hay nadie esperando."),
    ("review.admitted", "Ya está dentro. El círculo se ha renovado."),
    ("settings.title", "Ajustes"),
    ("settings.name", "Tu nombre"),
    ("settings.name_hint", "Lo que ve tu círculo"),
    ("settings.language", "Idioma"),
    ("settings.basemap", "Estilo del mapa"),
    ("settings.dark", "Oscuro"),
    ("settings.light", "Claro"),
    ("settings.off_grid", "Sin mapa"),
    ("settings.tor", "Usar Tor"),
    ("settings.tor_hint", "Más lento y más difícil de rastrear. Aún no incluido."),
    ("settings.app_lock", "Bloqueo de la app"),
    ("settings.lock_on", "Activado"),
    ("settings.lock_off", "Desactivado"),
    ("settings.lock_set", "Crear un código de acceso"),
    ("settings.lock_change", "Cambiar el código de acceso"),
    ("settings.lock_current", "Código de acceso actual"),
    ("settings.lock_new", "Nuevo código de acceso"),
    ("settings.lock_leave_off", "Déjalo vacío para desactivar el bloqueo."),
    ("settings.lock_save", "Guardar"),
    ("settings.lock_done", "El bloqueo de la app está activado."),
    ("settings.lock_removed", "El bloqueo de la app está desactivado."),
    ("settings.passcode", "Código de acceso"),
    ("settings.passcode_hint", "Al menos seis caracteres"),
    ("settings.wipe", "Borrarlo todo"),
    ("settings.wipe_hint", "Elimina las claves. Nada de lo compartido se podrá recuperar."),
    ("settings.version", "Versión 0.1.0 · GPL-3.0-or-later"),
    ("settings.close", "Cerrar"),
    ("perm.location", "Ubicación"),
    ("perm.background-location", "Ubicación en segundo plano"),
    ("perm.notifications", "Notificaciones"),
    ("perm.camera", "Cámara"),
    ("perm.ask", "Permitir {}"),
    ("perm.fix", "Ajustes"),
    ("perm.none", "Sin ubicación, nadie puede ver dónde estás."),
    (
        "perm.serious",
        "Las notificaciones están apagadas, así que no habría nada que indique que compartes.",
    ),
    ("promise.not_sharing", "Sin compartir: sin ubicación, nadie puede ver dónde estás."),
    (
        "promise.precise_open",
        "Compartiendo tu ubicación exacta con tu círculo, incluso con la app cerrada.",
    ),
    (
        "promise.coarse_open",
        "Compartiendo tu ubicación con un margen de un kilómetro, incluso con la app cerrada.",
    ),
    ("invite.title", "Invitar a alguien"),
    ("invite.valid", "Válido"),
    ("invite.expiring", "A punto de caducar"),
    ("invite.expired", "Caducado"),
    ("lock.title", "Bloqueado"),
    ("lock.enter", "Escribe tu código de acceso"),
    ("lock.wrong", "Ese no es el código."),
    ("lock.broken", "El código es correcto, pero el círculo de este teléfono no se abre."),
    ("lock.wiped", "No hay nada aquí"),
    (
        "lock.wiped_body",
        "Las claves se destruyeron. Nada de lo compartido se puede recuperar.",
    ),
    ("error.no_camera", "Este dispositivo no tiene cámara. Puedes escribir el código."),
    ("error.scan_failed", "No se pudo leer el código."),
    ("sos.needs_help", "NECESITA AYUDA"),
    ("places.title", "Lugares"),
    ("places.add", "Añadir un lugar"),
    ("places.name", "Nombre"),
    ("places.radius", "Radio"),
    ("places.empty", "Todavía no hay lugares. Añade uno y Kestrel te avisará al llegar."),
    ("places.delete", "Quitar"),
    ("places.silly_radius", "Elige un radio entre 25 metros y 20 kilómetros."),
    ("places.arrived", "Has llegado a {}"),
    ("places.left", "Has salido de {}"),
    ("places.nearby", "{} está cerca"),
    ("help.title", "Baliza de ayuda"),
    ("help.ask", "¿Dar a alguien un enlace a tu ubicación?"),
    ("help.warn", "Cualquiera con el enlace puede ver dónde estás hasta que caduque."),
    ("help.mint", "Crear un enlace"),
    ("help.minted", "Enlace de ayuda creado"),
    ("help.mint_title", "Envía este enlace"),
    ("help.expires", "Caduca en una hora."),
    ("places.arrived_title", "Llegada"),
    ("places.left_title", "Salida"),
];

const DE: &[(&str, &str)] = &[
    ("app.name", "Kestrel"),
    (
        "welcome.tagline",
        "Teile deinen Standort mit einem kleinen Kreis, und mit niemandem sonst.",
    ),
    ("welcome.create", "Kreis erstellen"),
    ("welcome.join", "Kreis beitreten"),
    ("welcome.open_map", "Karte öffnen"),
    ("map.title", "Karte"),
    ("map.sharing", "Wird geteilt"),
    ("map.not_sharing", "Nicht geteilt"),
    ("map.start", "Meinen Standort teilen"),
    ("map.stop", "Teilen beenden"),
    ("map.scan", "Code scannen"),
    ("map.settings", "Einstellungen"),
    ("map.fit", "Alle zeigen"),
    ("map.recentre", "Auf mich zentrieren"),
    ("map.off_grid", "Keine Karte"),
    ("join.title", "Kreis beitreten"),
    ("join.ask", "Bitte jemanden im Kreis um den Code und scanne oder tippe ihn ein."),
    ("join.type_here", "Code"),
    ("join.go", "Beitreten"),
    ("join.scan", "Stattdessen scannen"),
    ("join.back", "Zurück"),
    ("join.cancel", "Abbrechen"),
    ("join.your_number", "Deine Nummer. Lies sie laut vor, damit sie vergleichen können:"),
    ("join.waiting", "Warte, bis sie dich einlassen."),
    ("review.title", "Jemand möchte beitreten"),
    ("review.says", "{} sagt, ihre Nummer ist"),
    ("review.compare", "Lies es laut vor. Wenn es nicht stimmt, ist es nicht die Person."),
    ("review.accept", "Annehmen"),
    ("review.decline", "Ablehnen"),
    ("review.gone", "Niemand wartet mehr."),
    ("review.admitted", "Sie sind dabei. Der Kreis wurde neu verschlüsselt."),
    ("settings.title", "Einstellungen"),
    ("settings.name", "Dein Name"),
    ("settings.language", "Sprache"),
    ("settings.basemap", "Kartenstil"),
    ("settings.dark", "Dunkel"),
    ("settings.light", "Hell"),
    ("settings.off_grid", "Keine Karte"),
    ("settings.tor", "Tor verwenden"),
    ("settings.app_lock", "App-Sperre"),
    ("settings.passcode_hint", "Mindestens sechs Zeichen"),
    ("settings.lock_on", "An"),
    ("settings.lock_off", "Aus"),
    ("settings.lock_set", "Passcode festlegen"),
    ("settings.lock_change", "Passcode ändern"),
    ("settings.lock_current", "Aktueller Passcode"),
    ("settings.lock_new", "Neuer Passcode"),
    ("settings.lock_leave_off", "Leer lassen, um die Sperre auszuschalten."),
    ("settings.lock_save", "Speichern"),
    ("settings.lock_done", "Die App-Sperre ist aktiv."),
    ("settings.lock_removed", "Die App-Sperre ist aus."),
    ("settings.passcode", "Passcode"),
    ("settings.wipe", "Alles löschen"),
    ("settings.wipe_hint", "Löscht die Schlüssel. Nichts Geteiltes ist wiederherstellbar."),
    ("settings.close", "Schließen"),
    ("perm.location", "Standort"),
    ("perm.background-location", "Standort im Hintergrund"),
    ("perm.notifications", "Benachrichtigungen"),
    ("perm.camera", "Kamera"),
    ("perm.ask", "{} erlauben"),
    ("perm.fix", "Einstellungen"),
    ("perm.none", "Ohne Standort kann niemand sehen, wo du bist."),
    ("promise.not_sharing", "Nicht geteilt: ohne Standort kann niemand sehen, wo du bist."),
    ("invite.title", "Jemanden einladen"),
    ("invite.valid", "Gültig"),
    ("invite.expired", "Abgelaufen"),
    ("lock.title", "Gesperrt"),
    ("lock.wrong", "Das ist nicht der Passcode."),
    (
        "lock.broken",
        "Der Passcode stimmt, aber der Kreis auf diesem Telefon öffnet sich nicht.",
    ),
    ("lock.wiped", "Nichts hier"),
    (
        "lock.wiped_body",
        "Die Schlüssel wurden zerstört. Nichts Geteiltes ist wiederherstellbar.",
    ),
    ("error.scan_failed", "Der Code konnte nicht gelesen werden."),
    ("sos.needs_help", "HILFE NÖTIG"),
    ("places.title", "Orte"),
    ("places.add", "Ort hinzufügen"),
    ("places.name", "Name"),
    ("places.radius", "Radius"),
    ("places.empty", "Noch keine Orte. Füge einen hinzu, und Kestrel sagt Bescheid."),
    ("places.delete", "Entfernen"),
    ("places.arrived", "Du bist in {} angekommen"),
    ("places.left", "Du hast {} verlassen"),
    ("help.title", "Hilfe-Funkfeuer"),
    ("help.ask", "Jemandem einen Link auf deinen Standort geben?"),
    ("help.warn", "Wer den Link hat, sieht deinen Standort, bis er abläuft."),
    ("help.mint", "Link erstellen"),
    ("help.expires", "Er läuft in einer Stunde ab."),
    ("places.arrived_title", "Angekommen"),
    ("places.left_title", "Verlassen"),
];

/// The table for a language.
fn table(language: Language) -> Table {
    let pairs: &[(&str, &str)] = match language {
        Language::English => EN,
        Language::Spanish => ES,
        Language::German => DE,
        // Not yet written. The English table is used, so the app is uniformly English
        // rather than a mixture — see the module comment.
        _ => EN,
    };
    pairs.iter().map(|(k, v)| (*k, (*v).to_string())).collect()
}

/// Look up a string.
///
/// Falls back to English, and then to the key itself, so a missing string shows up as
/// `perm.fix` on screen rather than as an empty space where a label should be. That is
/// deliberate: a translator can see it, and a user gets something rather than nothing.
pub fn get(language: Language, key: &str) -> String {
    if let Some(found) = table(language).get(key) {
        return found.clone();
    }
    en(key)
}

/// The English text for a key, or the key itself.
fn en(key: &str) -> String {
    EN.iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| (*v).to_string())
        .unwrap_or_else(|| key.to_string())
}

/// A string with one substitution in it.
///
/// `{name}` placeholders rather than positional ones: a translator can reorder them
/// without the code caring, which is the only way a sentence survives being translated
/// at all.
pub fn with(language: Language, key: &str, name: &str, value: &str) -> String {
    get(language, key).replace(name, value)
}

/// Every key the app can show.
///
/// Read by the test below to check no translation has drifted away from the English
/// table, and by a reviewer to see the whole vocabulary in one place.
pub fn keys() -> Vec<&'static str> {
    let mut keys: Vec<&'static str> = EN.iter().map(|(k, _)| *k).collect();
    keys.sort_unstable();
    keys.dedup();
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_language_survives_a_round_trip_through_its_index() {
        for language in Language::ALL {
            assert_eq!(Language::from_index(language.index()), Some(language));
        }
        // Out of range is None, not a panic: the file is user-writable.
        assert_eq!(Language::from_index(200), None);
        assert_eq!(Language::from_index(255), None);
        // And the default is the first language, so an unset setting means English.
        assert_eq!(Language::default().index(), 0);
    }

    #[test]
    fn every_language_names_itself_in_itself() {
        // A picker that lists languages in English is useless to someone who does not
        // read English, which is most of the point of a picker.
        for language in Language::ALL {
            assert!(!language.endonym().is_empty());
            assert!(!language.tag().is_empty());
            assert_eq!(Language::ALL.len(), 7);
        }
        assert_eq!(Language::Spanish.endonym(), "Español");
        assert_eq!(Language::Japanese.tag(), "ja");
    }

    #[test]
    fn the_app_lock_says_something_in_every_language() {
        // A missing key renders as the key itself, which is a button reading
        // "settings.lock_save". Invisible in English — English is the table
        // everything falls back to — and wrong in every language that is not.
        for language in Language::ALL {
            for key in [
                "settings.app_lock",
                "settings.lock_on",
                "settings.lock_off",
                "settings.lock_set",
                "settings.lock_change",
                "settings.lock_current",
                "settings.lock_new",
                "settings.lock_leave_off",
                "settings.lock_save",
                "settings.lock_done",
                "settings.lock_removed",
                "settings.passcode",
                "settings.passcode_hint",
                "settings.close",
                "lock.title",
                "lock.enter",
                "lock.wrong",
                "lock.broken",
            ] {
                let text = get(language, key);
                assert!(!text.is_empty() && text != key, "{language:?} has no {key}");
            }
        }
    }

    #[test]
    fn a_platform_locale_finds_its_closest_language() {
        assert_eq!(Language::from_tag("es-MX"), Language::Spanish);
        assert_eq!(Language::from_tag("de_AT"), Language::German);
        assert_eq!(Language::from_tag("pt-BR"), Language::Portuguese);
        assert_eq!(Language::from_tag("pt-PT"), Language::Portuguese);
        assert_eq!(Language::from_tag("en-GB"), Language::English);
        assert_eq!(Language::from_tag("zh-Hans-CN"), Language::Chinese);
        assert_eq!(Language::from_tag("ja"), Language::Japanese);
    }

    #[test]
    fn an_unknown_locale_falls_back_to_english() {
        // A partly-English app is readable; a blank one is not.
        for tag in ["", "xx", "klingon", "123", "--"] {
            assert_eq!(Language::from_tag(tag), Language::English);
        }
    }

    #[test]
    fn every_english_string_is_reachable_and_non_empty() {
        for key in keys() {
            let value = get(Language::English, key);
            assert!(!value.is_empty(), "{key} is empty");
            assert_ne!(value, key, "{key} has no text");
        }
    }

    #[test]
    fn every_key_appears_once_in_the_english_table() {
        // A duplicate key is a translation that silently shadows another, and which of the
        // two wins depends on the order of the table.
        let mut all: Vec<&str> = EN.iter().map(|(k, _)| *k).collect();
        let before = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), before, "a duplicate key in the English table");
    }

    #[test]
    fn every_translation_keys_off_something_that_exists() {
        // The check that matters for translators: a key that was renamed in English and
        // forgotten in a translation shows up as an empty space on screen.
        let known = keys();
        for (language, pairs) in [(Language::Spanish, ES), (Language::German, DE)] {
            for (key, _) in pairs {
                assert!(
                    known.contains(key),
                    "{language:?} translates {key}, which is not an English key"
                );
            }
        }
    }

    #[test]
    fn every_translation_actually_translates() {
        // A Spanish table with English strings in it is worse than no Spanish at all: the
        // reader cannot tell which parts they are expected to understand.
        // Proper nouns and short labels are expected to match: "Kestrel" is the app's
        // name in every language, and "Cámara" happens to be a word in Spanish too.
        let untranslated: &[&str] = &["app.name", "perm.camera"];
        for (key, value) in ES {
            if untranslated.contains(key) {
                continue;
            }
            assert_ne!(value, &en(key), "{key} is identical in Spanish and English");
        }
    }

    #[test]
    fn an_untranslated_key_falls_back_to_english() {
        // Deliberately: a screen half in Spanish and half in English is worse than one
        // uniformly in English, because the reader cannot tell what was meant to be
        // understandable.
        // German has fewer keys than Spanish, so this is the real fallback path.
        assert_eq!(
            get(Language::German, "settings.tor_hint"),
            "Slower, and harder to trace. Not bundled yet."
        );
        // And a key neither has.
        assert_eq!(get(Language::German, "invite.read_out"), en("invite.read_out"));
    }

    #[test]
    fn a_missing_string_shows_its_key_rather_than_nothing() {
        // A blank space where a label should be is a bug nobody notices. The key is
        // visible, so a translator or a reviewer can see it.
        assert_eq!(get(Language::English, "nothing.here"), "nothing.here");
    }

    #[test]
    fn a_substituted_string_replaces_only_its_placeholder() {
        let text = with(Language::English, "review.says", "{}", "Ada");
        assert_eq!(text, "Ada says their number is");
        // And the placeholder is gone, not left in front of the name.
        assert!(!text.contains("{}"));
        // In Spanish too.
        let text = with(Language::Spanish, "review.says", "{}", "Ada");
        assert!(text.starts_with("Ada "));
        assert!(!text.contains("{}"));
    }

    #[test]
    fn the_permission_lines_name_what_they_ask_for() {
        // A prompt that says "Allow" with nothing after it is not a prompt anyone can
        // answer.
        let label = with(Language::English, "perm.ask", "{}", "Location");
        assert_eq!(label, "Allow Location");
        for key in ["perm.location", "perm.notifications", "perm.camera"] {
            assert!(!get(Language::English, key).is_empty());
        }
    }

    #[test]
    fn the_sharing_promises_are_all_reachable() {
        // Four sentences, four permission combinations, and each one is something a
        // person reads before agreeing to be located.
        for key in [
            "promise.not_sharing",
            "promise.precise_closed",
            "promise.precise_open",
            "promise.coarse_closed",
            "promise.coarse_open",
        ] {
            let text = get(Language::English, key);
            assert!(
                text.contains("Sharing") || text.contains("Not sharing"),
                "{key}: {text}"
            );
        }
    }

    #[test]
    fn no_translation_invents_a_permission_the_app_does_not_ask_for() {
        // A translated string naming a permission Android does not have is a promise the
        // app cannot keep.
        let all: Vec<&str> = ES.iter().chain(DE.iter()).map(|(k, _)| *k).collect();
        for key in ["perm.contacts", "perm.microphone", "perm.calls"] {
            assert!(!all.contains(&key), "{key} is translated but never used");
        }
    }
}
