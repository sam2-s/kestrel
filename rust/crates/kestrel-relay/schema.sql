-- The relay's whole storage: two tables and three indexes.
--
-- Every statement is idempotent, so the schema is applied on every start and
-- restarting against an existing file is always safe.
--
-- Column order matters, and is asserted by the test suite: an older file read by
-- a newer build has to line up, so a column cannot be inserted in the middle
-- without a migration.
--
-- There is no AUTOINCREMENT, no foreign key and no ON DELETE CASCADE. Rows
-- expire by age and are swept on every read and write, so there is never a
-- parent to cascade from and no sequence to keep.

CREATE TABLE IF NOT EXISTS members_v3 (
  channel TEXT NOT NULL,
  member  TEXT NOT NULL,
  alg     TEXT NOT NULL,
  pk      TEXT NOT NULL,
  epk     TEXT NOT NULL,
  last_ts INTEGER NOT NULL,
  srv     INTEGER NOT NULL,
  PRIMARY KEY (channel, member)
);

-- One row per stored point. The primary key is the backstop against a
-- whole-body replay: the bytes are identical, so the insert collides.
CREATE TABLE IF NOT EXISTS points_v3 (
  channel TEXT NOT NULL,
  member  TEXT NOT NULL,
  e       INTEGER NOT NULL,
  ts      INTEGER NOT NULL,
  srv     INTEGER NOT NULL,
  n       TEXT NOT NULL,
  c       TEXT NOT NULL,
  sig     TEXT NOT NULL,
  PRIMARY KEY (channel, member, ts)
);

-- The sweep reads by age across all channels, so this index is what keeps
-- expiry from being a full scan.
CREATE INDEX IF NOT EXISTS idx_points_v3_srv ON points_v3 (srv);

-- The feed reads one channel in time order. The sweep index alone cannot serve
-- that, and it is the only hot read in the system.
CREATE INDEX IF NOT EXISTS idx_points_v3_channel_srv ON points_v3 (channel, srv);

CREATE INDEX IF NOT EXISTS idx_members_v3_srv ON members_v3 (srv);

-- Retired table names, dropped so a database from an older deployment does not
-- keep rows nobody will ever read.
DROP TABLE IF EXISTS points_v2;
DROP TABLE IF EXISTS members_v2;
DROP TABLE IF EXISTS points;
DROP TABLE IF EXISTS members;
