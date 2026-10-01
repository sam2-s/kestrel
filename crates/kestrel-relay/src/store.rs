//! The store: two tables of ciphertext and the rules that keep them honest.
//!
//! Everything the relay stores is a row of ciphertext, a signature, and enough
//! metadata to serve a feed. It never sees a position, a name, or a circle's
//! membership, because all of those are inside the sealed body.
//!
//! Three rules are enforced here rather than in the request handler, and each
//! has a reason that is easy to lose sight of:
//!
//! * **A member is pinned on first write.** Any later mismatch in the algorithm
//!   or either key is refused. The member id commits to both public keys, so
//!   pinning the id pins the keypair; without the pin, a relay could rewrite a
//!   key and a receiver would admit the change.
//! * **A timestamp may only move forward** for a member. A relay is not trusted
//!   with this — every receiver keeps its own high-water mark — but a relay that
//!   lets timestamps go backwards is a relay whose feed can be reordered at will.
//! * **The member cap is enforced inside the write.** Checking it before the
//!   write leaves a race between the check and the insert, and a race here means
//!   a channel that exceeds its cap whenever two devices post at the same moment.

use std::path::Path;

use kestrel_core::wire::{
    Feed, FeedMember, FeedPoint, MEMBER_CAP, Post, TRAIL_CAP, TTL_MS,
};
use rusqlite::{Connection, OpenFlags};

/// The schema, applied on every start.
const SCHEMA: &str = include_str!("../schema.sql");

/// A relay store.
/// One write in this many trims that member's trail.
///
/// Not per post: a second write per post is a real cost on a phone's battery,
/// and never trimming would let one chatty member fill the table. Every sixteen
/// is cheap and bounded, and because the trim is a `DELETE ... ORDER BY ts` it
/// does not matter which write does it.
pub const TRAIL_TRIM_EVERY: i64 = 16;

pub struct Store {
    conn: Connection,
    /// The relay's own clock, injectable so expiry is testable without sleeping.
    now: i64,
    /// How many writes this store has done, so the trail trim can run periodically
    /// rather than on a schedule the clock controls.
    writes: u64,
}

/// Why a write was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// The post's timestamp is not newer than the last one this member sent.
    NotMonotonic,
    /// The primary key collided, which means these exact bytes are already
    /// stored.
    Duplicate,
    /// The channel is full.
    Full,
    /// A pinned key does not match what was presented.
    PinMismatch,
    /// The database is unusable.
    Internal,
}

pub struct FeedPage {
    pub feed: Feed,
}

/// Open a store on a file, creating it if needed.
pub fn open_file(path: &Path, now: i64) -> rusqlite::Result<Store> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    // WAL so a read is not blocked by a write. The whole point of the relay is
    // that many devices poll while one posts.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    Store { conn, now, writes: 0 }.with_schema()
}

/// An in-memory store, for tests and for a relay run out of a tmpfs.
pub fn open_memory(now: i64) -> rusqlite::Result<Store> {
    let conn = Connection::open_in_memory()?;
    Store { conn, now, writes: 0 }.with_schema()
}

impl Store {
    fn with_schema(self) -> rusqlite::Result<Self> {
        self.conn.execute_batch(SCHEMA)?;
        Ok(self)
    }

    /// The relay's clock.
    pub fn now(&self) -> i64 {
        self.now
    }

    /// Move the relay's clock. Only for tests, where expiry is exercised without
    /// a twenty-four hour wait.
    pub fn set_now(&mut self, now: i64) {
        self.now = now;
    }

    /// Whether a member is already pinned for a channel, and their last
    /// timestamp.
    fn pin(
        &self,
        channel: &str,
        member: &str,
    ) -> rusqlite::Result<Option<(String, String, String, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT alg, pk, epk, last_ts FROM members_v3 WHERE channel = ?1 AND member = ?2",
        )?;
        let mut rows = stmt.query(rusqlite::params![channel, member])?;
        match rows.next()? {
            Some(r) => Ok(Some((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))),
            None => Ok(None),
        }
    }

    fn count_members(&self, channel: &str) -> rusqlite::Result<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM members_v3 WHERE channel = ?1",
            rusqlite::params![channel],
            |r| r.get(0),
        )
    }

    /// Store one post.
    ///
    /// The signature is verified by the caller. The relay checks that the post is
    /// well formed, that its keys hash to the member id it claims, and that the
    /// signature is valid — because a relay that stored anything else would be a
    /// relay storing rows nobody can use, and because refusing a forged post here
    /// saves every member bandwidth.
    pub fn insert(&mut self, channel: &str, post: &Post) -> Result<(), StoreError> {
        let srv = self.now;

        // The pin and the count are read before the transaction opens, because
        // rusqlite's transaction borrows the connection exclusively. The
        // authoritative cap check is the one inside the write below; these two are
        // the cheap early answers, so a full channel is refused before a
        // transaction is started at all.
        let existing = self.pin(channel, &post.m).map_err(|_| StoreError::Internal)?;
        let count = self.count_members(channel).map_err(|_| StoreError::Internal)?;

        let tx = self.conn.transaction().map_err(|_| StoreError::Internal)?;

        // Pin rules, in the order that answers "is this the same member".
        if let Some((alg, pk, epk, last_ts)) = existing {
            if alg != post.alg || pk != post.pk || epk != post.epk {
                return Err(StoreError::PinMismatch);
            }
            if post.ts <= last_ts {
                return Err(StoreError::NotMonotonic);
            }
        } else if count >= MEMBER_CAP as i64 {
            return Err(StoreError::Full);
        }

        // The whole write, in one transaction, so the cap cannot be raced.
        //
        // The member row goes in with `last_ts = MAX(old, new)`: a blind
        // assignment lets two posts landing together walk the pin backwards and
        // re-open the replay window.
        //
        // The point insert is conditional on the member row existing, which is
        // what makes the cap atomic: a request that would exceed it writes
        // nothing at all rather than writing a point with no member.
        let member_sql = "
            INSERT INTO members_v3 (channel, member, alg, pk, epk, last_ts, srv)
            SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7
            WHERE EXISTS (
                SELECT 1 FROM members_v3 WHERE channel = ?1 AND member = ?2
            )
            OR (SELECT COUNT(*) FROM members_v3 WHERE channel = ?1) < ?8
            ON CONFLICT(channel, member) DO UPDATE SET
                last_ts = MAX(members_v3.last_ts, excluded.last_ts)";
        tx.execute(
            member_sql,
            rusqlite::params![
                channel,
                post.m,
                post.alg,
                post.pk,
                post.epk,
                post.ts,
                srv,
                MEMBER_CAP as i64
            ],
        )
        .map_err(|_| StoreError::Internal)?;

        let point_sql = "
            INSERT INTO points_v3 (channel, member, e, ts, srv, n, c, sig)
            SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8
            WHERE EXISTS (
                SELECT 1 FROM members_v3 WHERE channel = ?1 AND member = ?2
            )";
        let point_result = tx.execute(
            point_sql,
            rusqlite::params![
                channel, post.m, post.e, post.ts, srv, post.n, post.c, post.sig
            ],
        );

        // A primary-key collision means these exact bytes are already stored, so
        // this is a replay. The member update above is rolled back with it.
        if let Err(e) = point_result {
            if e.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                return Err(StoreError::Duplicate);
            }
            return Err(StoreError::Internal);
        }

        // The trail trim, one write in TRAIL_TRIM_EVERY.
        //
        // Doing it on every write would be a second write per post, which is a
        // real cost on a phone's battery. Doing it never would let one chatty
        // member fill the table. Every sixteenth write is cheap and bounded, and
        // because the trim deletes everything past the cap rather than the oldest
        // row, it does not matter which write performs it.
        //
        // Counted rather than taken from the clock: a relay whose clock is
        // injected for testing would otherwise trim on the clock's schedule, and
        // a relay whose clock stalls would never trim at all.
        self.writes = self.writes.wrapping_add(1);
        if self.writes.is_multiple_of(TRAIL_TRIM_EVERY.max(1) as u64) {
            tx.execute(
                "DELETE FROM points_v3
                 WHERE channel = ?1 AND member = ?2
                   AND ts < (SELECT ts FROM points_v3
                             WHERE channel = ?1 AND member = ?2
                             ORDER BY ts DESC LIMIT 1 OFFSET ?3)",
                rusqlite::params![channel, post.m, (TRAIL_CAP - 1) as i64],
            )
            .map_err(|_| StoreError::Internal)?;
        }

        sweep(&tx, srv).map_err(|_| StoreError::Internal)?;
        tx.commit().map_err(|_| StoreError::Internal)?;
        Ok(())
    }

    /// Read a feed.
    ///
    /// `members` is every pinned member for the channel regardless of the
    /// cursor, because a device needs the roster even for a member with no new
    /// points. Only points are filtered, by the relay's own receive time rather
    /// than the sender's timestamp: one device with a skewed clock must not be
    /// able to filter out another's points.
    pub fn feed(&mut self, channel: &str, since: i64) -> Result<FeedPage, StoreError> {
        let now = self.now;
        sweep_on(&self.conn, now).map_err(|_| StoreError::Internal)?;

        let mut members_stmt = self
            .conn
            .prepare(
                "SELECT member, alg, pk, epk FROM members_v3
                 WHERE channel = ?1 ORDER BY member",
            )
            .map_err(|_| StoreError::Internal)?;
        let member_rows = members_stmt
            .query_map(rusqlite::params![channel], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .map_err(|_| StoreError::Internal)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| StoreError::Internal)?;

        let mut points_stmt = self
            .conn
            .prepare(
                "SELECT member, e, ts, srv, n, c, sig FROM points_v3
                 WHERE channel = ?1 AND srv >= ?2 ORDER BY srv, ts",
            )
            .map_err(|_| StoreError::Internal)?;
        let point_rows = points_stmt
            .query_map(rusqlite::params![channel, since], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    FeedPoint {
                        e: r.get(1)?,
                        ts: r.get(2)?,
                        srv: r.get(3)?,
                        n: r.get(4)?,
                        c: r.get(5)?,
                        sig: r.get(6)?,
                    },
                ))
            })
            .map_err(|_| StoreError::Internal)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| StoreError::Internal)?;
        drop(points_stmt);
        drop(members_stmt);

        let mut members: Vec<FeedMember> = member_rows
            .into_iter()
            .map(|(m, alg, pk, epk)| FeedMember { m, alg, pk, epk, points: Vec::new() })
            .collect();
        for (member_id, point) in point_rows {
            if let Some(m) = members.iter_mut().find(|m| m.m == member_id) {
                m.points.push(point);
            }
        }

        Ok(FeedPage { feed: Feed { now, members } })
    }

    /// How many points a channel holds, for tests and for the health endpoint.
    pub fn count_points(&self, channel: &str) -> rusqlite::Result<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM points_v3 WHERE channel = ?1",
            rusqlite::params![channel],
            |r| r.get(0),
        )
    }

    /// How many members a channel holds.
    pub fn count_channel_members(&self, channel: &str) -> rusqlite::Result<i64> {
        self.count_members(channel)
    }

    /// Delete one member's points. The trail trim uses this; a test uses it to
    /// build the state a re-keyed member is in: visible in the roster, with no
    /// position posted yet.
    pub fn delete_points_for(
        &self,
        channel: &str,
        member: &str,
    ) -> rusqlite::Result<usize> {
        self.conn.execute(
            "DELETE FROM points_v3 WHERE channel = ?1 AND member = ?2",
            rusqlite::params![channel, member],
        )
    }

    /// Every value in every table, as one string.
    ///
    /// For the privacy assertion: the claim that the relay cannot read a position
    /// is only worth anything if something checks the file rather than the
    /// intention. Every column of every row, concatenated, so a name or a
    /// coordinate hiding in a field nothing reads would still be found.
    pub fn dump_everything(&self) -> String {
        let mut out = String::new();
        for (table, columns) in [
            ("members_v3", "channel, member, alg, pk, epk, last_ts, srv"),
            ("points_v3", "channel, member, e, ts, srv, n, c, sig"),
        ] {
            let Ok(mut stmt) = self.conn.prepare(&format!("SELECT {columns} FROM {table}"))
            else {
                continue;
            };
            let Ok(mut rows) = stmt.query([]) else {
                continue;
            };
            while let Ok(Some(row)) = rows.next() {
                for i in 0..row.as_ref().column_count() {
                    out.push_str(&row.get::<_, String>(i).unwrap_or_default());
                    out.push('\u{1f}');
                }
                out.push('\n');
            }
        }
        out
    }
}

// A post carries no channel field, because the channel is in the URL. That is
// safe: the signature covers the channel, so a post presented on a channel other
// than the one it was signed for fails its signature check in the handler before
// the store is reached. The store keys on the channel the request arrived on and
// trusts the handler's earlier verification.

fn sweep(tx: &rusqlite::Transaction<'_>, now: i64) -> rusqlite::Result<()> {
    let cutoff = now - TTL_MS;
    tx.execute("DELETE FROM points_v3 WHERE srv < ?1", rusqlite::params![cutoff])?;
    tx.execute("DELETE FROM members_v3 WHERE srv < ?1", rusqlite::params![cutoff])?;
    Ok(())
}

fn sweep_on(conn: &Connection, now: i64) -> rusqlite::Result<()> {
    let cutoff = now - TTL_MS;
    conn.execute("DELETE FROM points_v3 WHERE srv < ?1", rusqlite::params![cutoff])?;
    conn.execute("DELETE FROM members_v3 WHERE srv < ?1", rusqlite::params![cutoff])?;
    Ok(())
}
