import express from 'express';
import helmet from 'helmet';
import { createHash, randomUUID } from 'node:crypto';
import type { Config } from './config.js';
import type { SqliteDatabase } from './database.js';
import { credentialsSchema, envelopeSchema, refreshSchema } from './schemas.js';
import { hashPassword, hashToken, issueTokens, requireAuth, verifyPassword, type AuthenticatedRequest } from './auth.js';

export function createApp(database: SqliteDatabase, config: Config) {
  if (config.jwtSecret.length < 32) throw new Error('JWT_SECRET must contain at least 32 characters');
  const app = express();
  app.disable('x-powered-by');
  app.use(helmet());
  app.use(express.json({ limit: config.maxBackupBytes }));

  const audit = (userId: string | null, event: string) => database.prepare(
    'INSERT INTO audit_events(user_id, event, created_at) VALUES (?, ?, ?)'
  ).run(userId, event, new Date().toISOString());

  app.get('/v1/health', (_request, response) => response.json({ status: 'ok' }));

  app.post('/v1/auth/register', async (request, response) => {
    const parsed = credentialsSchema.safeParse(request.body);
    if (!parsed.success) return response.status(400).json({ error: 'invalid_request' });
    const existing = database.prepare('SELECT id FROM users WHERE email = ?').get(parsed.data.email);
    if (existing) return response.status(409).json({ error: 'email_exists' });
    const userId = randomUUID();
    const passwordHash = await hashPassword(parsed.data.password);
    database.prepare('INSERT INTO users(id, email, password_hash, created_at) VALUES (?, ?, ?, ?)')
      .run(userId, parsed.data.email, passwordHash, new Date().toISOString());
    audit(userId, 'auth.register');
    return response.status(201).json(issueTokens(database, config, userId));
  });

  app.post('/v1/auth/login', async (request, response) => {
    const parsed = credentialsSchema.safeParse(request.body);
    if (!parsed.success) return response.status(400).json({ error: 'invalid_request' });
    const user = database.prepare('SELECT id, password_hash FROM users WHERE email = ?').get(parsed.data.email) as { id: string; password_hash: string } | undefined;
    if (!user || !await verifyPassword(user.password_hash, parsed.data.password)) {
      return response.status(401).json({ error: 'invalid_credentials' });
    }
    audit(user.id, 'auth.login');
    return response.json(issueTokens(database, config, user.id));
  });

  app.post('/v1/auth/refresh', (request, response) => {
    const parsed = refreshSchema.safeParse(request.body);
    if (!parsed.success) return response.status(400).json({ error: 'invalid_request' });
    const tokenHash = hashToken(parsed.data.refreshToken);
    const token = database.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(tokenHash) as any;
    if (!token || token.expires_at <= Math.floor(Date.now() / 1000)) return response.status(401).json({ error: 'invalid_refresh_token' });
    if (token.revoked_at) {
      database.prepare('UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE family_id = ?').run(Math.floor(Date.now() / 1000), token.family_id);
      audit(token.user_id, 'auth.refresh_replay');
      return response.status(401).json({ error: 'refresh_token_reused' });
    }
    const replacement = issueTokens(database, config, token.user_id, token.family_id);
    database.prepare('UPDATE refresh_tokens SET revoked_at = ?, replaced_by_hash = ? WHERE token_hash = ?')
      .run(Math.floor(Date.now() / 1000), hashToken(replacement.refreshToken), tokenHash);
    audit(token.user_id, 'auth.refresh');
    return response.json(replacement);
  });

  app.post('/v1/auth/logout', (request, response) => {
    const parsed = refreshSchema.safeParse(request.body);
    if (parsed.success) {
      const token = database.prepare('SELECT family_id, user_id FROM refresh_tokens WHERE token_hash = ?').get(hashToken(parsed.data.refreshToken)) as any;
      if (token) {
        database.prepare('UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE family_id = ?').run(Math.floor(Date.now() / 1000), token.family_id);
        audit(token.user_id, 'auth.logout');
      }
    }
    return response.status(204).send();
  });

  app.get('/v1/cloudsync/latest', requireAuth(config), (_request, response) => {
    const auth = response.locals.auth as AuthenticatedRequest;
    const row = database.prepare('SELECT revision, envelope_json, received_at FROM snapshots WHERE user_id = ? ORDER BY revision DESC LIMIT 1').get(auth.userId) as any;
    if (!row) return response.status(404).json({ error: 'no_snapshot' });
    return response.json({ revision: row.revision, receivedAt: row.received_at, envelope: JSON.parse(row.envelope_json) });
  });

  app.put('/v1/cloudsync/latest', requireAuth(config), (request, response) => {
    const parsed = envelopeSchema.safeParse(request.body);
    if (!parsed.success) return response.status(400).json({ error: 'invalid_envelope' });
    const sequenceHeader = request.get('X-CloudSync-Sequence');
    const sequence = sequenceHeader === undefined ? null : Number(sequenceHeader);
    if (sequence !== null && (!/^[1-9][0-9]*$/.test(sequenceHeader!) || !Number.isSafeInteger(sequence))) {
      return response.status(400).json({ error: 'invalid_upload_sequence' });
    }
    const auth = response.locals.auth as AuthenticatedRequest;
    const encoded = JSON.stringify(parsed.data);
    const hash = createHash('sha256').update(encoded).digest('hex');
    const save = database.transaction(() => {
      const receipt = database.prepare('SELECT envelope_hash, revision FROM cloudsync_uploads WHERE user_id = ? AND backup_id = ?')
        .get(auth.userId, parsed.data.backupId) as { envelope_hash: string; revision: number } | undefined;
      if (receipt) return receipt.envelope_hash === hash
        ? { status: 200, body: { revision: receipt.revision } }
        : { status: 409, body: { error: 'backup_id_exists' } };

      // Backups created before receipt tracking are also safe to retry.
      const existing = database.prepare('SELECT user_id, envelope_json, revision FROM snapshots WHERE id = ?')
        .get(parsed.data.backupId) as { user_id: string; envelope_json: string; revision: number } | undefined;
      if (existing) {
        if (existing.user_id !== auth.userId || existing.envelope_json !== encoded) {
          return { status: 409, body: { error: 'backup_id_exists' } };
        }
        database.prepare('INSERT INTO cloudsync_uploads(user_id, backup_id, envelope_hash, revision) VALUES (?, ?, ?, ?)')
          .run(auth.userId, parsed.data.backupId, hash, existing.revision);
        return { status: 200, body: { revision: existing.revision } };
      }
      if (sequence !== null) {
        const previous = database.prepare('SELECT sequence FROM cloudsync_device_sequences WHERE user_id = ? AND device_id = ?')
          .get(auth.userId, parsed.data.deviceId) as { sequence: number } | undefined;
        if (previous && sequence <= previous.sequence) return { status: 409, body: { error: 'stale_upload' } };
      }
      const latest = database.prepare(`SELECT MAX(revision) AS revision FROM (
        SELECT COALESCE(MAX(revision), 0) AS revision FROM snapshots WHERE user_id = ?
        UNION ALL SELECT COALESCE(MAX(revision), 0) AS revision FROM cloudsync_uploads WHERE user_id = ?
      )`).get(auth.userId, auth.userId) as { revision: number };
      const revision = latest.revision + 1;
      database.prepare('INSERT INTO snapshots(id, user_id, revision, envelope_json, received_at) VALUES (?, ?, ?, ?, ?)')
        .run(parsed.data.backupId, auth.userId, revision, encoded, new Date().toISOString());
      database.prepare('INSERT INTO cloudsync_uploads(user_id, backup_id, envelope_hash, revision) VALUES (?, ?, ?, ?)')
        .run(auth.userId, parsed.data.backupId, hash, revision);
      if (sequence !== null) {
        database.prepare(`INSERT INTO cloudsync_device_sequences(user_id, device_id, sequence) VALUES (?, ?, ?)
          ON CONFLICT(user_id, device_id) DO UPDATE SET sequence = excluded.sequence`)
          .run(auth.userId, parsed.data.deviceId, sequence);
      }
      database.prepare(`DELETE FROM snapshots WHERE user_id = ? AND id NOT IN
        (SELECT id FROM snapshots WHERE user_id = ? ORDER BY revision DESC LIMIT ?)`)
        .run(auth.userId, auth.userId, config.snapshotLimit);
      audit(auth.userId, 'cloudsync.upload');
      return { status: 201, body: { revision } };
    });
    const result = save();
    return response.status(result.status).json(result.body);
  });

  app.delete('/v1/cloudsync', requireAuth(config), (_request, response) => {
    const auth = response.locals.auth as AuthenticatedRequest;
    database.prepare('DELETE FROM snapshots WHERE user_id = ?').run(auth.userId);
    audit(auth.userId, 'cloudsync.delete');
    return response.status(204).send();
  });

  app.use((_request, response) => response.status(404).json({ error: 'not_found' }));
  return app;
}
