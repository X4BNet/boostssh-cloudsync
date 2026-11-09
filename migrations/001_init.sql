CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  family_id TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  replaced_by_hash TEXT
);
CREATE INDEX IF NOT EXISTS refresh_tokens_family_idx ON refresh_tokens(family_id);

CREATE TABLE IF NOT EXISTS snapshots (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  revision INTEGER NOT NULL,
  envelope_json TEXT NOT NULL,
  received_at TEXT NOT NULL,
  UNIQUE(user_id, revision)
);
CREATE INDEX IF NOT EXISTS snapshots_user_revision_idx ON snapshots(user_id, revision DESC);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  event TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- Keep small receipts and per-device watermarks when snapshot retention prunes
-- ciphertext, so lost responses and delayed uploads cannot resurrect old data.
CREATE TABLE IF NOT EXISTS cloudsync_uploads (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  backup_id TEXT NOT NULL,
  envelope_hash TEXT NOT NULL,
  revision INTEGER NOT NULL,
  PRIMARY KEY(user_id, backup_id)
);
CREATE TABLE IF NOT EXISTS cloudsync_device_sequences (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  PRIMARY KEY(user_id, device_id)
);
