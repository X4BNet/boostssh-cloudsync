ALTER TABLE snapshots ADD COLUMN size_bytes INTEGER NOT NULL DEFAULT 0;
UPDATE snapshots SET size_bytes = length(CAST(envelope_json AS BLOB));

ALTER TABLE cloudsync_uploads ADD COLUMN accepted_at INTEGER NOT NULL DEFAULT 0;
UPDATE cloudsync_uploads SET accepted_at = unixepoch();
CREATE INDEX cloudsync_uploads_accepted_idx ON cloudsync_uploads(accepted_at);
CREATE INDEX refresh_tokens_expiry_idx ON refresh_tokens(expires_at);
CREATE INDEX audit_events_created_idx ON audit_events(created_at);

-- Revision counters outlive receipts and deleted ciphertext.
CREATE TABLE cloudsync_account_state (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  last_revision INTEGER NOT NULL DEFAULT 0,
  retained_bytes INTEGER NOT NULL DEFAULT 0,
  minimum_created_at INTEGER NOT NULL DEFAULT 0
);
INSERT INTO cloudsync_account_state(user_id, last_revision, retained_bytes)
SELECT users.id,
  MAX(COALESCE((SELECT MAX(revision) FROM snapshots WHERE user_id = users.id), 0),
      COALESCE((SELECT MAX(revision) FROM cloudsync_uploads WHERE user_id = users.id), 0)),
  COALESCE((SELECT SUM(size_bytes) FROM snapshots WHERE user_id = users.id), 0)
FROM users;
