import { createHash } from 'node:crypto';
import type { Config } from './config.js';
import type { SqliteDatabase } from './database.js';
import type { CloudSyncEnvelope } from './schemas.js';
import { HttpError } from './security.js';

export class StoragePolicy {
  private nextMaintenance = 0;
  constructor(private readonly database: SqliteDatabase, private readonly config: Config) {
    const pageSize = database.pragma('page_size', { simple: true }) as number;
    const pages = Math.floor(config.maxDatabaseBytes / pageSize);
    if (pages < (database.pragma('page_count', { simple: true }) as number)) {
      throw new Error('MAX_DATABASE_BYTES is below the existing database size');
    }
    database.pragma(`max_page_count = ${pages}`);
    database.pragma('journal_size_limit = 4194304');
    this.maintain();
  }

  maintain() {
    const now = Math.floor(Date.now() / 1000);
    if (now < this.nextMaintenance) return;
    this.database.transaction(() => {
      this.database.prepare('DELETE FROM refresh_tokens WHERE expires_at <= ?').run(now);
      // Expired receipts describe envelopes that are already too old to accept,
      // including uploads originally at the allowed future-clock boundary.
      // Persist the cutoff so increasing the configured window or moving the
      // clock backwards cannot make forgotten legacy uploads replayable.
      this.database.prepare(`UPDATE cloudsync_account_state SET minimum_created_at = MAX(minimum_created_at, ?)
        WHERE user_id IN (SELECT user_id FROM cloudsync_uploads WHERE accepted_at < ?)`)
        .run(now - this.config.maxUploadAgeSeconds, now - this.config.maxUploadAgeSeconds - this.config.maxClockSkewSeconds - 1);
      this.database.prepare('DELETE FROM cloudsync_uploads WHERE accepted_at < ?')
        .run(now - this.config.maxUploadAgeSeconds - this.config.maxClockSkewSeconds - 1);
      this.database.prepare('DELETE FROM audit_events WHERE created_at < ?')
        .run(new Date((now - this.config.auditRetentionSeconds) * 1000).toISOString());
      this.trimAudit();
    })();
    this.nextMaintenance = now + 60;
  }

  private trimAudit() {
    this.database.prepare(`DELETE FROM audit_events WHERE id <= COALESCE(
      (SELECT id FROM audit_events ORDER BY id DESC LIMIT 1 OFFSET ?), -1)`)
      .run(this.config.maxAuditEvents);
  }

  audit(userId: string | null, event: string) {
    this.database.prepare('INSERT INTO audit_events(user_id, event, created_at) VALUES (?, ?, ?)')
      .run(userId, event, new Date().toISOString());
    this.trimAudit();
  }

  private requireReceiptCapacity(userId: string) {
    const count = this.database.prepare('SELECT COUNT(*) AS count FROM cloudsync_uploads WHERE user_id = ?')
      .get(userId) as { count: number };
    if (count.count >= this.config.maxUploadReceiptsPerUser) throw new HttpError(507, 'upload_receipt_limit');
  }

  save(userId: string, envelope: CloudSyncEnvelope, sequence: number | null) {
    this.maintain();
    const encoded = JSON.stringify(envelope);
    const hash = createHash('sha256').update(encoded).digest('hex');
    const now = Math.floor(Date.now() / 1000);
    return this.database.transaction(() => {
      const receipt = this.database.prepare('SELECT envelope_hash, revision FROM cloudsync_uploads WHERE user_id = ? AND backup_id = ?')
        .get(userId, envelope.backupId) as { envelope_hash: string; revision: number } | undefined;
      if (receipt) {
        if (receipt.envelope_hash !== hash) throw new HttpError(409, 'backup_id_exists');
        return { status: 200, body: { revision: receipt.revision } };
      }
      const existing = this.database.prepare('SELECT user_id, envelope_json, revision FROM snapshots WHERE id = ?')
        .get(envelope.backupId) as { user_id: string; envelope_json: string; revision: number } | undefined;
      if (existing) {
        if (existing.user_id !== userId || existing.envelope_json !== encoded) throw new HttpError(409, 'backup_id_exists');
        this.requireReceiptCapacity(userId);
        this.database.prepare('INSERT INTO cloudsync_uploads(user_id, backup_id, envelope_hash, revision, accepted_at) VALUES (?, ?, ?, ?, ?)')
          .run(userId, envelope.backupId, hash, existing.revision, now);
        return { status: 200, body: { revision: existing.revision } };
      }
      const createdAt = Math.floor(Date.parse(envelope.createdAt) / 1000);
      const current = this.database.prepare('SELECT last_revision, retained_bytes, minimum_created_at FROM cloudsync_account_state WHERE user_id = ?')
        .get(userId) as { last_revision: number; retained_bytes: number; minimum_created_at: number };
      if (createdAt < Math.max(now - this.config.maxUploadAgeSeconds, current.minimum_created_at)) throw new HttpError(409, 'upload_expired');
      if (createdAt > now + this.config.maxClockSkewSeconds) throw new HttpError(400, 'invalid_upload_time');
      const previous = this.database.prepare('SELECT sequence FROM cloudsync_device_sequences WHERE user_id = ? AND device_id = ?')
        .get(userId, envelope.deviceId) as { sequence: number } | undefined;
      if (previous && previous.sequence > 0 && sequence === null) throw new HttpError(409, 'missing_upload_sequence');
      if (sequence !== null && previous && sequence <= previous.sequence) throw new HttpError(409, 'stale_upload');
      if (!previous) {
        const devices = this.database.prepare('SELECT COUNT(*) AS count FROM cloudsync_device_sequences WHERE user_id = ?')
          .get(userId) as { count: number };
        if (devices.count >= this.config.maxDevicesPerUser) throw new HttpError(409, 'device_limit');
      }
      this.requireReceiptCapacity(userId);
      const size = Buffer.byteLength(encoded);
      if (size > this.config.maxUserStorageBytes) throw new HttpError(413, 'backup_quota_exceeded');
      const older = this.database.prepare('SELECT id, size_bytes FROM snapshots WHERE user_id = ? ORDER BY revision DESC')
        .all(userId) as { id: string; size_bytes: number }[];
      let retainedBytes = size;
      let retainedCount = 1;
      const remove = this.database.prepare('DELETE FROM snapshots WHERE user_id = ? AND id = ?');
      for (const row of older) {
        if (retainedCount < this.config.snapshotLimit && retainedBytes + row.size_bytes <= this.config.maxUserStorageBytes) {
          retainedCount++;
          retainedBytes += row.size_bytes;
        } else remove.run(userId, row.id);
      }
      const total = this.database.prepare('SELECT COALESCE(SUM(retained_bytes), 0) AS bytes FROM cloudsync_account_state')
        .get() as { bytes: number };
      if (total.bytes - current.retained_bytes + retainedBytes > this.config.maxSnapshotStorageBytes) {
        throw new HttpError(507, 'storage_quota_exceeded');
      }
      const revision = current.last_revision + 1;
      this.database.prepare('INSERT INTO snapshots(id, user_id, revision, envelope_json, received_at, size_bytes) VALUES (?, ?, ?, ?, ?, ?)')
        .run(envelope.backupId, userId, revision, encoded, new Date().toISOString(), size);
      this.database.prepare('INSERT INTO cloudsync_uploads(user_id, backup_id, envelope_hash, revision, accepted_at) VALUES (?, ?, ?, ?, ?)')
        .run(userId, envelope.backupId, hash, revision, now);
      this.database.prepare(`INSERT INTO cloudsync_device_sequences(user_id, device_id, sequence) VALUES (?, ?, ?)
        ON CONFLICT(user_id, device_id) DO UPDATE SET sequence = excluded.sequence`)
        .run(userId, envelope.deviceId, sequence ?? 0);
      this.database.prepare('UPDATE cloudsync_account_state SET last_revision = ?, retained_bytes = ? WHERE user_id = ?')
        .run(revision, retainedBytes, userId);
      this.audit(userId, 'cloudsync.upload');
      return { status: 201, body: { revision } };
    })();
  }

  delete(userId: string) {
    this.maintain();
    this.database.transaction(() => {
      this.database.prepare('DELETE FROM snapshots WHERE user_id = ?').run(userId);
      this.database.prepare('UPDATE cloudsync_account_state SET retained_bytes = 0 WHERE user_id = ?').run(userId);
      this.audit(userId, 'cloudsync.delete');
    })();
  }
}
