//! The Kestrel relay.
//!
//! One binary, one SQLite file, no other dependencies. It stores ciphertext and
//! serves it back; it cannot read a position, a name, or who anyone is with whom.
//!
//! Configuration, all optional:
//!
//! | variable | default | meaning |
//! |---|---|---|
//! | `PORT` | `8788` | listen port |
//! | `HOST` | `127.0.0.1` | bind address; keep it on loopback behind a proxy |
//! | `KESTREL_DB` | `kestrel.db` | SQLite file, created if missing |
//! | `PUBLIC_ORIGIN` | `http://HOST:PORT` | the origin the relay treats as its own |
//! | `TRUST_PROXY` | unset | `1` reads the client address from the last `X-Forwarded-For` hop |
//! | `RATE_POST_MIN` | `256` | writes per channel per minute |
//! | `RATE_GET_MIN` | `240` | requests per address per minute, reads and writes |
//! | `ALLOWED_ORIGINS` | unset | comma-separated extra origins allowed to write |
//! | `CERT_FINGERPRINT` | unset | the release signing fingerprint, for asset links |
//! | `SWEEP_INTERVAL_MS` | `600000` | idle-channel sweep interval |

use kestrel_relay::{http, limits::Limiter, store};

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use http::{App, Config};
use kestrel_core::wire;
use tokio::sync::Mutex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let port: u16 = env_int("PORT", 8788).clamp(1, 65535) as u16;
    let host = env_string("HOST", "127.0.0.1");
    let db_path = PathBuf::from(env_string("KESTREL_DB", "kestrel.db"));
    let bind: SocketAddr = format!("{host}:{port}").parse()?;

    let config = Config {
        public_origin: env_string("PUBLIC_ORIGIN", &format!("http://{host}:{port}")),
        allowed_origins: env_string("ALLOWED_ORIGINS", "")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            // A custom scheme has no origin, so `new URL(s).origin` would be the
            // string "null" and matching against that would allow every sandboxed
            // frame on the internet. Normalise only what has a real origin, and
            // keep a custom scheme's literal spelling.
            .map(normalise_origin)
            .filter(|s| s != "null")
            .collect(),
        rate_post_min: env_int("RATE_POST_MIN", (wire::MEMBER_CAP * 4 * 4) as i64),
        rate_get_min: env_int("RATE_GET_MIN", 240),
        cert_fingerprint: env_string("CERT_FINGERPRINT", ""),
        trust_proxy: env_string("TRUST_PROXY", "") == "1",
    };
    if config.public_origin.starts_with("http://") && config.public_origin != "null" {
        tracing::warn!(
            origin = %config.public_origin,
            "PUBLIC_ORIGIN is plain http; the app will refuse a relay that is not https"
        );
    }

    let store = store::open_file(&db_path, now_ms())?;
    tracing::info!(db = %db_path.display(), "relay storage ready");

    let app = Arc::new(App {
        store: Mutex::new(store),
        limits: Mutex::new(Limiter::new()),
        config: Arc::new(config),
    });

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;

    runtime.block_on(async move {
        let router = http::router(app);
        let listener = tokio::net::TcpListener::bind(bind).await?;
        tracing::info!(%bind, "relay listening");
        axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(shutdown())
            .await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}

/// Stop accepting, then let in-flight requests finish.
///
/// `kill -9` is not destructive: SQLite runs in WAL mode, so at worst the last
/// few seconds of writes are lost, and a lost write is a lost position rather than
/// a corrupted circle.
async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutting down");
}

/// Reduce a configured origin to the form a browser sends.
///
/// `scheme://host[:port]`, lower-cased, with any path dropped: a browser sends an
/// origin and never a path, so an operator who wrote one gets the thing that will
/// actually be compared against.
///
/// Anything that is not that shape is returned with trailing slashes removed and
/// nothing else, so a custom scheme keeps its literal spelling. Reducing one to
/// the string "null" would match every sandboxed frame on the internet.
fn normalise_origin(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some((scheme, rest)) = trimmed.split_once("://") {
        // Only the host survives, and a host is case-insensitive while the scheme
        // is always lower case, so a browser's own normalisation is reproduced
        // rather than approximated.
        let host = rest.split('/').next().unwrap_or("");
        let rebuilt =
            format!("{}://{}", scheme.to_ascii_lowercase(), host.to_ascii_lowercase());
        if rebuilt.len() > "://".len() {
            return rebuilt;
        }
    }
    trimmed.trim_end_matches('/').to_string()
}

/// Read an integer, falling back for anything that is not a positive integer.
///
/// A zero or a negative or a word all fall back, rather than being clamped. A
/// misconfigured limit should be the documented default, not a surprising value
/// that nobody wrote down.
fn env_int(name: &str, default: i64) -> i64 {
    match std::env::var(name) {
        Ok(v) => match v.trim().parse::<i64>() {
            Ok(n) if n > 0 => n,
            _ => {
                tracing::warn!(name, value = %v, "not a positive integer, using the default");
                default
            }
        },
        Err(_) => default,
    }
}

fn env_string(name: &str, default: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
        _ => default.to_string(),
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_are_normalised() {
        assert_eq!(normalise_origin("https://Example.COM/"), "https://example.com");
        assert_eq!(normalise_origin("https://example.com/app/"), "https://example.com");
        assert_eq!(normalise_origin("http://localhost:8788"), "http://localhost:8788");
        // A custom scheme keeps its spelling, because it has no origin to reduce
        // to and reducing it to "null" would match every sandboxed frame.
        assert_eq!(normalise_origin("app://localhost/"), "app://localhost");
        assert_eq!(normalise_origin("myapp://host/path"), "myapp://host");
    }

    #[test]
    fn the_null_origin_is_filtered_out() {
        // This is the check that stops a sandboxed iframe being treated as an
        // allowed writer.
        assert_ne!(normalise_origin("null"), "");
        let filtered: Vec<String> = "null, https://ok.example, null"
            .split(',')
            .map(normalise_origin)
            .filter(|s| s != "null")
            .collect();
        assert_eq!(filtered, vec!["https://ok.example".to_string()]);
    }

    #[test]
    fn a_bad_integer_falls_back_to_the_default() {
        // A zero rate limit would refuse everything, so zero is not honoured.
        unsafe {
            std::env::set_var("KESTREL_TEST_INT", "0");
            assert_eq!(env_int("KESTREL_TEST_INT", 7), 7);
            std::env::set_var("KESTREL_TEST_INT", "-1");
            assert_eq!(env_int("KESTREL_TEST_INT", 7), 7);
            std::env::set_var("KESTREL_TEST_INT", "abc");
            assert_eq!(env_int("KESTREL_TEST_INT", 7), 7);
            std::env::set_var("KESTREL_TEST_INT", "1.5");
            assert_eq!(env_int("KESTREL_TEST_INT", 7), 7);
            std::env::set_var("KESTREL_TEST_INT", "9");
            assert_eq!(env_int("KESTREL_TEST_INT", 7), 9);
            std::env::remove_var("KESTREL_TEST_INT");
        }
    }

    #[test]
    fn the_default_limits_suit_a_full_circle() {
        let config = Config::default();
        // Sixteen members at fifteen second cadence is sixty-four posts a minute
        // from one circle, and a device polling every ten seconds is six reads.
        // The default has to clear both with room for a re-key burst.
        assert!(config.rate_post_min >= 64);
        assert!(config.rate_get_min >= 160);
    }
}
