import express from 'express';
import helmet from 'helmet';
import { randomUUID } from 'node:crypto';
import type { Config } from './config.js';
import type { SqliteDatabase } from './database.js';
import { credentialsSchema, envelopeSchema, refreshSchema } from './schemas.js';
import { dummyPasswordHash, hashPassword, hashToken, issueTokens, requireAuth, verifyPassword, type AuthenticatedRequest } from './auth.js';
import { accountRateKey, handleError, HttpError, limitRequests, PasswordGate, RateLimiter } from './security.js';
import { StoragePolicy } from './storage.js';

export function createApp(database: SqliteDatabase, config: Config) {
  if (config.jwtSecret.length < 32) throw new Error('JWT_SECRET must contain at least 32 characters');
  const app = express();
  const storage = new StoragePolicy(database, config);
  const passwords = new PasswordGate(config.passwordHashConcurrency);
  const accountLimiter = new RateLimiter(config.authAccountLimit, config.authWindowSeconds, config.rateLimitMaxEntries);
  const ipLimiter = new RateLimiter(config.authIpLimit, config.authWindowSeconds, config.rateLimitMaxEntries);
  const userLimiter = new RateLimiter(config.userRequestsPerMinute, 60, config.rateLimitMaxEntries);
  const limitUser = limitRequests(userLimiter, (_request, response) => (response.locals.auth as AuthenticatedRequest).userId);
  const authJson = express.json({ limit: 4096, inflate: false });
  app.disable('x-powered-by');
  app.set('trust proxy', config.trustedProxies.length ? config.trustedProxies : false);
  app.use(helmet());
  app.get('/v1/health', (_request, response) => response.json({ status: 'ok' }));
  app.use('/v1/auth', limitRequests(ipLimiter, request => request.ip ?? 'unknown'));

  const checkAccount = (email: string) => {
    const retry = accountLimiter.consume(accountRateKey(email));
    if (retry) throw new HttpError(429, 'rate_limited', retry);
  };

  app.post('/v1/auth/register', (_request, _response, next) => {
    if (!config.registrationEnabled) return next(new HttpError(403, 'registration_disabled'));
    next();
  }, authJson, async (request, response) => {
    const parsed = credentialsSchema.safeParse(request.body);
    if (!parsed.success) throw new HttpError(400, 'invalid_request');
    checkAccount(parsed.data.email);
    await passwords.run(async () => {
      // Hash even for existing addresses so the KDF path is uniform.
      const passwordHash = await hashPassword(parsed.data.password);
      storage.maintain();
      database.transaction(() => {
        const count = database.prepare('SELECT COUNT(*) AS count FROM users').get() as { count: number };
        if (count.count >= config.maxUsers) return;
        const userId = randomUUID();
        const result = database.prepare('INSERT OR IGNORE INTO users(id, email, password_hash, created_at) VALUES (?, ?, ?, ?)')
          .run(userId, parsed.data.email, passwordHash, new Date().toISOString());
        if (result.changes) {
          database.prepare('INSERT INTO cloudsync_account_state(user_id) VALUES (?)').run(userId);
          storage.audit(userId, 'auth.register');
        }
      })();
    });
    return response.status(202).json({ status: 'registration_received' });
  });

  app.post('/v1/auth/login', authJson, async (request, response) => {
    const parsed = credentialsSchema.safeParse(request.body);
    if (!parsed.success) throw new HttpError(400, 'invalid_request');
    checkAccount(parsed.data.email);
    return passwords.run(async () => {
      const user = database.prepare('SELECT id, password_hash FROM users WHERE email = ?').get(parsed.data.email) as { id: string; password_hash: string } | undefined;
      const valid = await verifyPassword(user?.password_hash ?? dummyPasswordHash, parsed.data.password);
      if (!user || !valid) throw new HttpError(401, 'invalid_credentials');
      storage.maintain();
      const tokens = database.transaction(() => {
        const issued = issueTokens(database, config, user.id);
        storage.audit(user.id, 'auth.login');
        return issued;
      })();
      return response.json(tokens);
    });
  });

  app.post('/v1/auth/refresh', authJson, (request, response) => {
    const parsed = refreshSchema.safeParse(request.body);
    if (!parsed.success) throw new HttpError(400, 'invalid_request');
    storage.maintain();
    const tokenHash = hashToken(parsed.data.refreshToken);
    const token = database.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(tokenHash) as any;
    if (!token || token.expires_at <= Math.floor(Date.now() / 1000)) throw new HttpError(401, 'invalid_refresh_token');
    if (token.revoked_at) {
      database.transaction(() => {
        database.prepare('UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE family_id = ?').run(Math.floor(Date.now() / 1000), token.family_id);
        storage.audit(token.user_id, 'auth.refresh_replay');
      })();
      throw new HttpError(401, 'refresh_token_reused');
    }
    const replacement = database.transaction(() => {
      const issued = issueTokens(database, config, token.user_id, token.family_id);
      database.prepare('UPDATE refresh_tokens SET revoked_at = ?, replaced_by_hash = ? WHERE token_hash = ?')
        .run(Math.floor(Date.now() / 1000), hashToken(issued.refreshToken), tokenHash);
      storage.audit(token.user_id, 'auth.refresh');
      return issued;
    })();
    return response.json(replacement);
  });

  app.post('/v1/auth/logout', authJson, (request, response) => {
    const parsed = refreshSchema.safeParse(request.body);
    if (parsed.success) {
      storage.maintain();
      const token = database.prepare('SELECT family_id, user_id FROM refresh_tokens WHERE token_hash = ?').get(hashToken(parsed.data.refreshToken)) as any;
      if (token) database.transaction(() => {
        database.prepare('UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE family_id = ?').run(Math.floor(Date.now() / 1000), token.family_id);
        storage.audit(token.user_id, 'auth.logout');
      })();
    }
    return response.status(204).send();
  });

  app.get('/v1/cloudsync/latest', requireAuth(config), limitUser, (_request, response) => {
    const auth = response.locals.auth as AuthenticatedRequest;
    const row = database.prepare('SELECT revision, envelope_json, received_at FROM snapshots WHERE user_id = ? ORDER BY revision DESC LIMIT 1').get(auth.userId) as any;
    if (!row) throw new HttpError(404, 'no_snapshot');
    return response.json({ revision: row.revision, receivedAt: row.received_at, envelope: JSON.parse(row.envelope_json) });
  });

  app.put('/v1/cloudsync/latest', requireAuth(config), limitUser, express.json({ limit: config.maxBackupBytes, inflate: false }), (request, response) => {
    const parsed = envelopeSchema.safeParse(request.body);
    if (!parsed.success) throw new HttpError(400, 'invalid_envelope');
    const sequenceHeader = request.get('X-CloudSync-Sequence');
    const sequence = sequenceHeader === undefined ? null : Number(sequenceHeader);
    if (sequence !== null && (!/^[1-9][0-9]*$/.test(sequenceHeader!) || !Number.isSafeInteger(sequence))) {
      throw new HttpError(400, 'invalid_upload_sequence');
    }
    const auth = response.locals.auth as AuthenticatedRequest;
    const result = storage.save(auth.userId, parsed.data, sequence);
    return response.status(result.status).json(result.body);
  });

  app.delete('/v1/cloudsync', requireAuth(config), limitUser, (_request, response) => {
    storage.delete((response.locals.auth as AuthenticatedRequest).userId);
    return response.status(204).send();
  });

  app.use((_request, response) => response.status(404).json({ error: 'not_found' }));
  app.use(handleError);
  return app;
}
