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

use std::{net::SocketAddr, sync::Arc};

use tokio::sync::Mutex;

/// A relay that has been bound to a port but is not yet serving.
pub struct Bound {
    pub address: SocketAddr,
    pub app: Arc<http::App>,
    listener: tokio::net::TcpListener,
}

impl Bound {
    /// The relay's origin, for a client to point at.
    pub fn origin(&self) -> String {
        format!("http://{}", self.address)
    }

    /// Serve until the process ends or `shutdown` resolves.
    pub async fn serve<F: std::future::Future<Output = ()> + Send + 'static>(
        self,
        shutdown: F,
    ) -> Result<(), std::io::Error> {
        let router = http::router(self.app);
        axum::serve(
            self.listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown)
        .await
    }

    /// Every value in every table, for the privacy assertion.
    pub async fn dump(&self) -> String {
        let store = self.app.store.lock().await;
        store.dump_everything()
    }

    /// Move the relay's clock, so expiry is testable without a day's wait.
    pub async fn advance(&self, ms: i64) {
        let mut store = self.app.store.lock().await;
        let now = store.now() + ms;
        store.set_now(now);
    }

    /// How many points a channel holds.
    pub async fn count_points(&self, channel: &str) -> i64 {
        self.app.store.lock().await.count_points(channel).unwrap_or(0)
    }
}

/// Bind a relay on an ephemeral port, with an in-memory store.
pub async fn bind_in_memory(config: http::Config) -> Result<Bound, std::io::Error> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let app = Arc::new(http::App {
        store: Mutex::new(store::open_memory(now_ms()).expect("an in-memory store")),
        limits: Mutex::new(limits::Limiter::new()),
        config: Arc::new(config),
    });
    Ok(Bound { address, app, listener })
}

/// Bind a relay on a file, so the store's schema and durability are exercised.
pub async fn bind_file(
    path: &std::path::Path,
    config: http::Config,
) -> Result<Bound, std::io::Error> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let store = store::open_file(path, now_ms()).expect("a file store");
    let app = Arc::new(http::App {
        store: Mutex::new(store),
        limits: Mutex::new(limits::Limiter::new()),
        config: Arc::new(config),
    });
    Ok(Bound { address, app, listener })
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
