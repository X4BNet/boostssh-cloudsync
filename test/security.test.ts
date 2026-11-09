import request from 'supertest';
import argon2 from 'argon2';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { createApp } from '../src/app.js';
import { loadConfig, type Config } from '../src/config.js';
import { openDatabase, type SqliteDatabase } from '../src/database.js';
import { dummyPasswordHash, hashToken, issueTokens } from '../src/auth.js';
import { PasswordGate, RateLimiter } from '../src/security.js';

let database: SqliteDatabase;
let config: Config;
let app: ReturnType<typeof createApp>;
const password = 'long-security-test-password';
const credentials = (email = 'user@example.test') => ({ email, password });
function envelope(deviceId = 'device-1') {
  return {
    formatVersion: 2, schemaVersion: 1, backupId: randomUUID(), deviceId,
    createdAt: new Date().toISOString(),
    kdf: { name: 'argon2id', salt: 'YWJjZA==', memoryKiB: 65536, iterations: 3, parallelism: 1 },
    cipher: { name: 'AES-256-GCM', nonce: 'YWJjZA==', ciphertext: 'ZW5jcnlwdGVk' }
  };
}
function configure(overrides: Partial<Config>) {
  config = loadConfig({ ...config, ...overrides });
  app = createApp(database, config);
}
function seed(email = 'user@example.test') {
  const id = randomUUID();
  database.prepare('INSERT INTO users(id,email,password_hash,created_at) VALUES (?,?,?,?)')
    .run(id, email, dummyPasswordHash, new Date().toISOString());
  database.prepare('INSERT INTO cloudsync_account_state(user_id) VALUES (?)').run(id);
  return { id, ...issueTokens(database, config, id) };
}
function upload(token: string, value = envelope(), sequence?: number) {
  const call = request(app).put('/v1/cloudsync/latest').set('Authorization', `Bearer ${token}`);
  if (sequence !== undefined) call.set('X-CloudSync-Sequence', String(sequence));
  return call.send(value);
}
function count(table: string) {
  return (database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get() as { count: number }).count;
}
beforeEach(() => {
  config = loadConfig({ databasePath: ':memory:', jwtSecret: 'security-test-secret-at-least-32-characters' });
  database = openDatabase(':memory:');
  app = createApp(database, config);
});
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  vi.useRealTimers();
  database.close();
});

describe('request and authentication controls', () => {
  it('rejects compressed JSON without invoking a decompressor and stays healthy', async () => {
    const body = Buffer.concat([gzipSync('{"a":1}'), Buffer.from([0]), Buffer.alloc(100 * 1024, 0x58)]);
    const result = await request(app).post('/v1/auth/login').set('Content-Type', 'application/json')
      .set('Content-Encoding', 'gzip').send(body);
    expect(result.status).toBe(415);
    expect(result.body).toEqual({ error: 'unsupported_encoding' });
    expect((await request(app).get('/v1/health')).status).toBe(200);
  });

  it('never logs or returns malformed credential fragments in production', async () => {
    vi.stubEnv('NODE_ENV', 'production');
    configure({});
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    for (const body of ['{"password":CANARY9}', '{"refreshToken":CANARY9}']) {
      const result = await request(app).post('/v1/auth/login').set('Content-Type', 'application/json').send(body);
      expect(result.status).toBe(400);
      expect(result.body).toEqual({ error: 'invalid_json' });
    }
    expect(log).not.toHaveBeenCalled();
  });

  it('sanitizes unexpected errors and releases the hashing slot after failure', async () => {
    configure({ passwordHashConcurrency: 1 });
    const log = vi.spyOn(console, 'error').mockImplementation(() => {});
    const hash = vi.spyOn(argon2, 'hash').mockRejectedValueOnce(new Error('CANARY9 secret'));
    expect((await request(app).post('/v1/auth/register').send(credentials())).status).toBe(500);
    expect(log.mock.calls).toEqual([['{"event":"request_error","code":"internal_error"}']]);
    hash.mockResolvedValueOnce(dummyPasswordHash);
    expect((await request(app).post('/v1/auth/register').send(credentials())).status).toBe(202);
  });

  it('limits credential bodies to 4 KiB and authenticates uploads before parsing', async () => {
    expect((await request(app).post('/v1/auth/login').send({ padding: 'x'.repeat(5000) })).status).toBe(413);
    const response = await request(app).put('/v1/cloudsync/latest').set('Content-Type', 'application/json').send('{CANARY9');
    expect(response.status).toBe(401);
  });

  it('limits IPs and ignores forged forwarding headers by default', async () => {
    configure({ authIpLimit: 2 });
    for (let index = 0; index < 2; index++) {
      expect((await request(app).post('/v1/auth/login').set('X-Forwarded-For', `192.0.2.${index + 1}`).send({})).status).toBe(400);
    }
    const limited = await request(app).post('/v1/auth/login').set('X-Forwarded-For', '198.51.100.1').send({});
    expect(limited.status).toBe(429);
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
  });

  it('uses forwarding headers only for explicitly trusted proxies', async () => {
    configure({ authIpLimit: 1, trustedProxies: ['loopback'] });
    const call = (ip: string) => request(app).post('/v1/auth/login').set('X-Forwarded-For', ip).send({});
    expect((await call('192.0.2.1')).status).toBe(400);
    expect((await call('192.0.2.1')).status).toBe(429);
    expect((await call('192.0.2.2')).status).toBe(400);
  });

  it('shares normalized account limits across client IPs and auth endpoints', async () => {
    configure({ authAccountLimit: 1, trustedProxies: ['loopback'] });
    expect((await request(app).post('/v1/auth/register').set('X-Forwarded-For', '192.0.2.1').send(credentials())).status).toBe(202);
    expect((await request(app).post('/v1/auth/login').set('X-Forwarded-For', '192.0.2.2').send(credentials('USER@example.test'))).status).toBe(429);
  });

  it('bounds limiter keys, fails closed at capacity, and reclaims expired keys', () => {
    const now = vi.spyOn(Date, 'now').mockReturnValue(1000);
    const limiter = new RateLimiter(1, 60, 2);
    expect(limiter.consume('one')).toBe(0);
    expect(limiter.consume('one')).toBe(60);
    expect(limiter.consume('two')).toBe(0);
    expect(limiter.consume('three')).toBe(60);
    now.mockReturnValue(61_001);
    expect(limiter.consume('three')).toBe(0);
  });

  it('rejects excess password work without queuing it', async () => {
    const gate = new PasswordGate(1);
    let finish!: () => void;
    const first = gate.run(() => new Promise<void>(resolve => { finish = resolve; }));
    const extra = vi.fn();
    await expect(gate.run(extra)).rejects.toMatchObject({ status: 429, code: 'authentication_busy' });
    expect(extra).not.toHaveBeenCalled();
    finish();
    await first;
    await expect(gate.run(async () => 'released')).resolves.toBe('released');
  });

  it('enforces the password gate on the actual HTTP endpoint', async () => {
    configure({ passwordHashConcurrency: 1 });
    let entered!: () => void, finish!: (hash: string) => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const hash = vi.spyOn(argon2, 'hash').mockImplementationOnce(() => {
      entered();
      return new Promise<string>(resolve => { finish = resolve; });
    });
    const first = request(app).post('/v1/auth/register').send(credentials()).then(result => result);
    await started;
    const busy = await request(app).post('/v1/auth/register').send(credentials('other@example.test'));
    expect(busy.status).toBe(429);
    expect(hash).toHaveBeenCalledTimes(1);
    finish(dummyPasswordHash);
    expect((await first).status).toBe(202);
  });

  it('returns identical registration acknowledgements without changing existing passwords', async () => {
    const fresh = await request(app).post('/v1/auth/register').send(credentials());
    const existing = await request(app).post('/v1/auth/register').send({ ...credentials(), password: 'different-test-password' });
    expect(existing.status).toBe(202);
    expect(existing.body).toEqual(fresh.body);
    expect(existing.body).toEqual({ status: 'registration_received' });
    expect(count('users')).toBe(1);
    expect((await request(app).post('/v1/auth/login').send(credentials())).status).toBe(200);
    expect((await request(app).post('/v1/auth/login').send({ ...credentials(), password: 'different-test-password' })).status).toBe(401);
  });

  it('performs an Argon2 verification with equal cost parameters for missing accounts', async () => {
    seed();
    const verify = vi.spyOn(argon2, 'verify').mockResolvedValue(false);
    const known = await request(app).post('/v1/auth/login').send(credentials());
    const missing = await request(app).post('/v1/auth/login').send(credentials('missing@example.test'));
    expect(known.status).toBe(401);
    expect(missing.body).toEqual(known.body);
    expect(verify).toHaveBeenCalledTimes(2);
    expect(verify.mock.calls[0][0]).toBe(dummyPasswordHash);
    expect(verify.mock.calls[1][0]).toBe(dummyPasswordHash);
    expect(dummyPasswordHash).toContain('m=65536,p=1,t=3');
  });

  it('disables registration through the environment while existing users can log in', async () => {
    await request(app).post('/v1/auth/register').send(credentials());
    vi.stubEnv('REGISTRATION_ENABLED', 'false');
    configure({ registrationEnabled: loadConfig().registrationEnabled });
    expect((await request(app).post('/v1/auth/register').send(credentials('new@example.test'))).body).toEqual({ error: 'registration_disabled' });
    expect(count('users')).toBe(1);
    expect((await request(app).post('/v1/auth/login').send(credentials())).status).toBe(200);
  });

  it('caps accounts without disclosing whether signup was rejected at capacity', async () => {
    configure({ maxUsers: 1 });
    const first = await request(app).post('/v1/auth/register').send(credentials());
    const full = await request(app).post('/v1/auth/register').send(credentials('second@example.test'));
    expect(full.status).toBe(first.status);
    expect(full.body).toEqual(first.body);
    expect(count('users')).toBe(1);
  });

  it('rejects invalid limit and registration configuration', () => {
    for (const maxUsers of [0, -1, NaN, 1.5, Infinity]) expect(() => loadConfig({ maxUsers })).toThrow();
    vi.stubEnv('REGISTRATION_ENABLED', 'typo');
    expect(() => loadConfig()).toThrow('REGISTRATION_ENABLED');
  });
});

describe('bounded persistence and replay protection', () => {
  it('prunes ciphertext by byte quota and retains idempotent receipts', async () => {
    const first = envelope();
    const size = Buffer.byteLength(JSON.stringify(first));
    configure({ maxUserStorageBytes: size * 2 });
    const user = seed();
    expect((await upload(user.accessToken, first, 1)).status).toBe(201);
    expect((await upload(user.accessToken, envelope(), 2)).status).toBe(201);
    expect((await upload(user.accessToken, envelope(), 3)).status).toBe(201);
    expect(count('snapshots')).toBe(2);
    expect((database.prepare('SELECT retained_bytes FROM cloudsync_account_state').get() as any).retained_bytes).toBe(size * 2);
    expect((await upload(user.accessToken, first, 1)).status).toBe(200);
    expect(count('snapshots')).toBe(2);
  });

  it('enforces the shared storage quota atomically and frees space on deletion', async () => {
    const value = envelope();
    configure({ maxSnapshotStorageBytes: Buffer.byteLength(JSON.stringify(value)) });
    const first = seed(), second = seed('second@example.test');
    expect((await upload(first.accessToken, value)).status).toBe(201);
    const rejected = await upload(second.accessToken);
    expect(rejected.status).toBe(507);
    expect(count('snapshots')).toBe(1);
    expect(count('cloudsync_uploads')).toBe(1);
    expect(count('cloudsync_device_sequences')).toBe(1);
    await request(app).delete('/v1/cloudsync').set('Authorization', `Bearer ${first.accessToken}`);
    expect((await upload(second.accessToken)).status).toBe(201);
  });

  it('caps receipts while allowing safe retries at capacity', async () => {
    configure({ maxUploadReceiptsPerUser: 1 });
    const user = seed(), first = envelope();
    expect((await upload(user.accessToken, first)).status).toBe(201);
    expect((await upload(user.accessToken)).status).toBe(507);
    expect((await upload(user.accessToken, first)).status).toBe(200);
    expect(count('cloudsync_uploads')).toBe(1);
  });

  it('bounds device watermarks and does not discard them on deletion', async () => {
    configure({ maxDevicesPerUser: 1 });
    const user = seed();
    expect((await upload(user.accessToken, envelope('one'), 1)).status).toBe(201);
    await request(app).delete('/v1/cloudsync').set('Authorization', `Bearer ${user.accessToken}`);
    expect((await upload(user.accessToken, envelope('two'), 1)).body).toEqual({ error: 'device_limit' });
    expect((await upload(user.accessToken, envelope('one'))).body).toEqual({ error: 'missing_upload_sequence' });
    expect(count('cloudsync_device_sequences')).toBe(1);
  });

  it('expires receipts without resurrecting deleted backups or resetting revisions', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    configure({ maxUploadAgeSeconds: 10 });
    const user = seed(), sequenced = envelope(), legacy = envelope('legacy');
    expect((await upload(user.accessToken, sequenced, 5)).body.revision).toBe(1);
    expect((await upload(user.accessToken, legacy)).body.revision).toBe(2);
    await request(app).delete('/v1/cloudsync').set('Authorization', `Bearer ${user.accessToken}`);
    vi.setSystemTime(Date.now() + 400_000);
    expect((await upload(user.accessToken, sequenced, 5)).body).toEqual({ error: 'upload_expired' });
    expect((await upload(user.accessToken, legacy)).body).toEqual({ error: 'upload_expired' });
    expect(count('cloudsync_uploads')).toBe(0);
    expect(count('snapshots')).toBe(0);
    configure({ maxUploadAgeSeconds: 1000 });
    expect((await upload(user.accessToken, legacy)).body).toEqual({ error: 'upload_expired' });
    expect((await upload(user.accessToken, envelope(), 4)).body).toEqual({ error: 'stale_upload' });
    expect((await upload(user.accessToken, envelope(), 6)).body.revision).toBe(3);
  });

  it('retains receipts through the allowed future-clock boundary', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    configure({ maxUploadAgeSeconds: 10 });
    const user = seed(), value = envelope();
    value.createdAt = new Date(Date.now() + 300_000).toISOString();
    expect((await upload(user.accessToken, value)).status).toBe(201);
    await request(app).delete('/v1/cloudsync').set('Authorization', `Bearer ${user.accessToken}`);
    vi.setSystemTime(Date.now() + 309_000);
    expect((await upload(user.accessToken, value)).status).toBe(200);
    vi.setSystemTime(Date.now() + 61_000);
    expect((await upload(user.accessToken, value)).body).toEqual({ error: 'upload_expired' });
    expect(count('snapshots')).toBe(0);
  });

  it('rejects future upload times before persisting any state', async () => {
    const user = seed(), value = envelope();
    value.createdAt = new Date(Date.now() + 600_000).toISOString();
    expect((await upload(user.accessToken, value)).body).toEqual({ error: 'invalid_upload_time' });
    expect(count('cloudsync_uploads')).toBe(0);
  });

  it('caps refresh records while retaining unexpired replay tombstones', async () => {
    configure({ maxRefreshTokensPerUser: 2 });
    const user = seed();
    const rotated = await request(app).post('/v1/auth/refresh').send({ refreshToken: user.refreshToken });
    expect(rotated.status).toBe(200);
    expect((await request(app).post('/v1/auth/refresh').send({ refreshToken: rotated.body.refreshToken })).status).toBe(507);
    expect(count('refresh_tokens')).toBe(2);
    expect((await request(app).post('/v1/auth/refresh').send({ refreshToken: user.refreshToken })).body).toEqual({ error: 'refresh_token_reused' });
    expect((await request(app).post('/v1/auth/refresh').send({ refreshToken: rotated.body.refreshToken })).status).toBe(401);
  });

  it('removes expired refresh tokens and bounds and expires audit history', async () => {
    configure({ maxAuditEvents: 2 });
    const user = seed();
    database.prepare('UPDATE refresh_tokens SET expires_at = 1 WHERE token_hash = ?').run(hashToken(user.refreshToken));
    for (let index = 0; index < 4; index++) expect((await upload(user.accessToken)).status).toBe(201);
    expect(count('audit_events')).toBe(2);
    configure({}); // Startup maintenance also runs after a restart.
    expect(count('refresh_tokens')).toBe(0);
    database.prepare("UPDATE audit_events SET created_at = '2000-01-01T00:00:00.000Z'").run();
    configure({});
    expect(count('audit_events')).toBe(0);
  });

  it('returns a sanitized quota error at the SQLite page limit without partial writes', async () => {
    const size = database.pragma('page_size', { simple: true }) as number;
    const pages = database.pragma('page_count', { simple: true }) as number;
    configure({ maxDatabaseBytes: (pages + 8) * size });
    const user = seed(), value = envelope();
    value.cipher.ciphertext = 'A'.repeat(128 * 1024);
    const response = await upload(user.accessToken, value);
    expect(response.status).toBe(507);
    expect(response.body).toEqual({ error: 'storage_quota_exceeded' });
    expect(count('snapshots')).toBe(0);
    expect(count('cloudsync_uploads')).toBe(0);
    expect((await request(app).get('/v1/health')).status).toBe(200);
  });

  it('rate limits authenticated operations by account', async () => {
    configure({ userRequestsPerMinute: 1 });
    const user = seed();
    expect((await upload(user.accessToken)).status).toBe(201);
    expect((await upload(user.accessToken)).status).toBe(429);
  });

  it('migrates legacy databases once and preserves bytes, revisions, and receipts', () => {
    const directory = mkdtempSync(join(tmpdir(), 'cloudsync-migration-'));
    const path = join(directory, 'legacy.sqlite');
    const value = envelope(), encoded = JSON.stringify(value);
    const legacy = new Database(path);
    legacy.exec(readFileSync(new URL('../migrations/001_init.sql', import.meta.url), 'utf8'));
    legacy.prepare('INSERT INTO users VALUES (?,?,?,?)').run('legacy', 'legacy@example.test', dummyPasswordHash, new Date().toISOString());
    legacy.prepare('INSERT INTO snapshots VALUES (?,?,?,?,?)').run(value.backupId, 'legacy', 7, encoded, new Date().toISOString());
    legacy.prepare('INSERT INTO cloudsync_uploads VALUES (?,?,?,?)').run('legacy', value.backupId, 'hash', 9);
    legacy.close();
    try {
      for (let index = 0; index < 2; index++) {
        const migrated = openDatabase(path);
        try {
          expect(migrated.prepare('SELECT last_revision, retained_bytes FROM cloudsync_account_state').get())
            .toEqual({ last_revision: 9, retained_bytes: Buffer.byteLength(encoded) });
          expect((migrated.prepare('SELECT accepted_at FROM cloudsync_uploads').get() as any).accepted_at).toBeGreaterThan(0);
        } finally { migrated.close(); }
      }
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
});
