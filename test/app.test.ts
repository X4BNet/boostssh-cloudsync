import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { openDatabase, type SqliteDatabase } from '../src/database.js';

const config = loadConfig({ databasePath: ':memory:', jwtSecret: 'test-secret-that-is-at-least-32-characters' });
let database: SqliteDatabase;
let app: ReturnType<typeof createApp>;

async function register(email = 'user@example.com') {
  const response = await request(app).post('/v1/auth/register').send({ email, password: 'long-test-password' });
  expect(response.status).toBe(202);
  const login = await request(app).post('/v1/auth/login').send({ email, password: 'long-test-password' });
  expect(login.status).toBe(200);
  return login.body as { accessToken: string; refreshToken: string };
}

function envelope(backupId: string) {
  return {
    formatVersion: 2,
    schemaVersion: 1,
    backupId,
    deviceId: 'device-1',
    createdAt: new Date().toISOString(),
    kdf: { name: 'argon2id', salt: 'YWJjZA==', memoryKiB: 65536, iterations: 3, parallelism: 1 },
    cipher: { name: 'AES-256-GCM', nonce: 'YWJjZA==', ciphertext: 'ZW5jcnlwdGVk' }
  };
}

beforeEach(() => {
  database = openDatabase(':memory:');
  app = createApp(database, config);
});
afterEach(() => database.close());

describe('authentication', () => {
  it('registers, logs in, and rotates refresh tokens', async () => {
    const initial = await register();
    const login = await request(app).post('/v1/auth/login').send({ email: 'USER@example.com', password: 'long-test-password' });
    expect(login.status).toBe(200);
    const refreshed = await request(app).post('/v1/auth/refresh').send({ refreshToken: initial.refreshToken });
    expect(refreshed.status).toBe(200);
    expect(refreshed.body.refreshToken).not.toBe(initial.refreshToken);
    const replay = await request(app).post('/v1/auth/refresh').send({ refreshToken: initial.refreshToken });
    expect(replay.status).toBe(401);
    const familyRevoked = await request(app).post('/v1/auth/refresh').send({ refreshToken: refreshed.body.refreshToken });
    expect(familyRevoked.status).toBe(401);
  });

  it('does not reveal whether an account exists during login', async () => {
    await register();
    const response = await request(app).post('/v1/auth/login').send({ email: 'missing@example.com', password: 'long-test-password' });
    expect(response.status).toBe(401);
    expect(response.body).toEqual({ error: 'invalid_credentials' });
  });

  it('revokes the complete refresh-token family on logout', async () => {
    const initial = await register();
    const rotated = await request(app).post('/v1/auth/refresh').send({ refreshToken: initial.refreshToken });
    expect(rotated.status).toBe(200);
    expect((await request(app).post('/v1/auth/logout').send({ refreshToken: rotated.body.refreshToken })).status).toBe(204);
    expect((await request(app).post('/v1/auth/refresh').send({ refreshToken: rotated.body.refreshToken })).status).toBe(401);
  });

  it('rejects missing, malformed, and refresh tokens at protected routes', async () => {
    const user = await register();
    expect((await request(app).get('/v1/cloudsync/latest')).status).toBe(401);
    expect((await request(app).get('/v1/cloudsync/latest').set('Authorization', 'Bearer malformed')).status).toBe(401);
    expect((await request(app).get('/v1/cloudsync/latest').set('Authorization', `Bearer ${user.refreshToken}`)).status).toBe(401);
  });
});

describe('CloudSync', () => {
  it('stores and returns only the authenticated user snapshot', async () => {
    const user = await register();
    const second = await register('second@example.com');
    const upload = await request(app).put('/v1/cloudsync/latest').set('Authorization', `Bearer ${user.accessToken}`).send(envelope('00000000-0000-4000-8000-000000000001'));
    expect(upload.status).toBe(201);
    expect(upload.body.revision).toBe(1);
    const latest = await request(app).get('/v1/cloudsync/latest').set('Authorization', `Bearer ${user.accessToken}`);
    expect(latest.status).toBe(200);
    expect(latest.body.envelope.backupId).toBe('00000000-0000-4000-8000-000000000001');
    const isolated = await request(app).get('/v1/cloudsync/latest').set('Authorization', `Bearer ${second.accessToken}`);
    expect(isolated.status).toBe(404);
  });

  it('uses server upload order and retains ten snapshots', async () => {
    const user = await register();
    for (let index = 1; index <= 12; index++) {
      const id = `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`;
      const response = await request(app).put('/v1/cloudsync/latest').set('Authorization', `Bearer ${user.accessToken}`).send(envelope(id));
      expect(response.body.revision).toBe(index);
    }
    const count = database.prepare('SELECT COUNT(*) AS count FROM snapshots').get() as { count: number };
    expect(count.count).toBe(10);
    const latest = await request(app).get('/v1/cloudsync/latest').set('Authorization', `Bearer ${user.accessToken}`);
    expect(latest.body.revision).toBe(12);
  });

  it('rejects malformed envelopes and deletes backups', async () => {
    const user = await register();
    const malformed = await request(app).put('/v1/cloudsync/latest').set('Authorization', `Bearer ${user.accessToken}`).send({ plaintext: 'secret' });
    expect(malformed.status).toBe(400);
    await request(app).put('/v1/cloudsync/latest').set('Authorization', `Bearer ${user.accessToken}`).send(envelope('00000000-0000-4000-8000-000000000001'));
    expect((await request(app).delete('/v1/cloudsync').set('Authorization', `Bearer ${user.accessToken}`)).status).toBe(204);
    expect((await request(app).get('/v1/cloudsync/latest').set('Authorization', `Bearer ${user.accessToken}`)).status).toBe(404);
  });

  it('rejects duplicate backup ids without replacing the accepted snapshot', async () => {
    const user = await register();
    const value = envelope('00000000-0000-4000-8000-000000000001');
    expect((await request(app).put('/v1/cloudsync/latest').set('Authorization', `Bearer ${user.accessToken}`).send(value)).status).toBe(201);
    value.deviceId = 'changed-device';
    expect((await request(app).put('/v1/cloudsync/latest').set('Authorization', `Bearer ${user.accessToken}`).send(value)).status).toBe(409);
    const latest = await request(app).get('/v1/cloudsync/latest').set('Authorization', `Bearer ${user.accessToken}`);
    expect(latest.body.envelope.deviceId).toBe('device-1');
  });

  it('returns the same revision when a committed upload response is lost', async () => {
    const user = await register();
    const value = envelope('00000000-0000-4000-8000-000000000001');
    const upload = () => request(app).put('/v1/cloudsync/latest')
      .set('Authorization', `Bearer ${user.accessToken}`).set('X-CloudSync-Sequence', '1').send(value);
    const first = await upload();
    const retry = await upload();
    expect(first.status).toBe(201);
    expect(retry.status).toBe(200);
    expect(retry.body).toEqual(first.body);
    expect((database.prepare('SELECT COUNT(*) AS count FROM snapshots').get() as any).count).toBe(1);
    expect((database.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE event = 'cloudsync.upload'").get() as any).count).toBe(1);
  });

  it('never lets an older delayed device upload replace a newer snapshot', async () => {
    const user = await register();
    const newer = envelope('00000000-0000-4000-8000-000000000002');
    const older = envelope('00000000-0000-4000-8000-000000000001');
    const send = (value: ReturnType<typeof envelope>, sequence: string) => request(app).put('/v1/cloudsync/latest')
      .set('Authorization', `Bearer ${user.accessToken}`).set('X-CloudSync-Sequence', sequence).send(value);
    expect((await send(newer, '2')).status).toBe(201);
    const delayed = await send(older, '1');
    expect(delayed.status).toBe(409);
    expect(delayed.body.error).toBe('stale_upload');
    expect((await send(older, '2')).status).toBe(409);
    const latest = await request(app).get('/v1/cloudsync/latest').set('Authorization', `Bearer ${user.accessToken}`);
    expect(latest.body.envelope.backupId).toBe(newer.backupId);
    expect((await send({ ...older, deviceId: 'device-2' }, '1')).status).toBe(201);
  });

  it('retains retry receipts and ordering after snapshot pruning and deletion', async () => {
    app = createApp(database, { ...config, snapshotLimit: 1 });
    const user = await register();
    const old = envelope('00000000-0000-4000-8000-000000000001');
    const latest = envelope('00000000-0000-4000-8000-000000000003');
    const send = (value: ReturnType<typeof envelope>, sequence: string) => request(app).put('/v1/cloudsync/latest')
      .set('Authorization', `Bearer ${user.accessToken}`).set('X-CloudSync-Sequence', sequence).send(value);
    await send(old, '1');
    await send(latest, '3');
    const retry = await send(old, '1');
    expect(retry.status).toBe(200);
    expect(retry.body.revision).toBe(1);
    expect((await request(app).get('/v1/cloudsync/latest').set('Authorization', `Bearer ${user.accessToken}`)).body.envelope.backupId).toBe(latest.backupId);
    await request(app).delete('/v1/cloudsync').set('Authorization', `Bearer ${user.accessToken}`);
    expect((await send(old, '1')).status).toBe(200);
    const neverAccepted = envelope('00000000-0000-4000-8000-000000000002');
    expect((await send(neverAccepted, '2')).status).toBe(409);
    expect((await request(app).get('/v1/cloudsync/latest').set('Authorization', `Bearer ${user.accessToken}`)).status).toBe(404);
    expect((await send(neverAccepted, '4')).body.revision).toBe(3);
  });

  it('keeps upload receipts private to their account', async () => {
    const first = await register();
    const second = await register('second@example.com');
    const value = envelope('00000000-0000-4000-8000-000000000001');
    await request(app).put('/v1/cloudsync/latest').set('Authorization', `Bearer ${first.accessToken}`).send(value);
    const replay = await request(app).put('/v1/cloudsync/latest').set('Authorization', `Bearer ${second.accessToken}`).send(value);
    expect(replay.status).toBe(409);
    expect(replay.body.revision).toBeUndefined();
    expect((await request(app).get('/v1/cloudsync/latest').set('Authorization', `Bearer ${second.accessToken}`)).status).toBe(404);
  });

  it('rejects malformed sequence headers without storing the envelope', async () => {
    const user = await register();
    for (const sequence of ['0', '-1', '1.5', 'NaN', '9007199254740992', '1e3']) {
      const result = await request(app).put('/v1/cloudsync/latest').set('Authorization', `Bearer ${user.accessToken}`)
        .set('X-CloudSync-Sequence', sequence).send(envelope('00000000-0000-4000-8000-000000000001'));
      expect(result.status).toBe(400);
    }
    expect((database.prepare('SELECT COUNT(*) AS count FROM snapshots').get() as any).count).toBe(0);
  });

  it('enforces request quotas before parsing envelope content', async () => {
    const limited = createApp(database, { ...config, maxBackupBytes: 2048 });
    const user = await request(limited).post('/v1/auth/register').send({ email: 'quota@example.com', password: 'long-test-password' });
    expect(user.status).toBe(202);
    const login = await request(limited).post('/v1/auth/login').send({ email: 'quota@example.com', password: 'long-test-password' });
    const oversized = { ...envelope('00000000-0000-4000-8000-000000000001'), padding: 'x'.repeat(4096) };
    expect((await request(limited).put('/v1/cloudsync/latest').set('Authorization', `Bearer ${login.body.accessToken}`).send(oversized)).status).toBe(413);
    const count = database.prepare('SELECT COUNT(*) AS count FROM snapshots').get() as { count: number };
    expect(count.count).toBe(0);
  });

  it('keeps audit records free of credentials and envelope contents', async () => {
    const user = await register('audit@example.com');
    await request(app).put('/v1/cloudsync/latest').set('Authorization', `Bearer ${user.accessToken}`).send(envelope('00000000-0000-4000-8000-000000000001'));
    const serialized = JSON.stringify(database.prepare('SELECT * FROM audit_events').all());
    expect(serialized).not.toContain('audit@example.com');
    expect(serialized).not.toContain('long-test-password');
    expect(serialized).not.toContain(user.accessToken);
    expect(serialized).not.toContain('ZW5jcnlwdGVk');
  });

  it('preserves accounts and encrypted snapshots across a database restart', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'boostssh-cloudsync-'));
    const path = join(directory, 'cloudsync.sqlite');
    const persistentConfig = { ...config, databasePath: path };
    let persistent = openDatabase(path);
    try {
      let persistentApp = createApp(persistent, persistentConfig);
      const user = await request(persistentApp).post('/v1/auth/register').send({ email: 'restart@example.com', password: 'long-test-password' });
      expect(user.status).toBe(202);
      const login = await request(persistentApp).post('/v1/auth/login').send({ email: 'restart@example.com', password: 'long-test-password' });
      const savedEnvelope = envelope('00000000-0000-4000-8000-000000000001');
      await request(persistentApp).put('/v1/cloudsync/latest').set('Authorization', `Bearer ${login.body.accessToken}`).set('X-CloudSync-Sequence', '2').send(savedEnvelope);
      persistent.close();
      persistent = openDatabase(path);
      persistentApp = createApp(persistent, persistentConfig);
      const latest = await request(persistentApp).get('/v1/cloudsync/latest').set('Authorization', `Bearer ${login.body.accessToken}`);
      expect(latest.status).toBe(200);
      expect(latest.body.envelope.cipher.ciphertext).toBe('ZW5jcnlwdGVk');
      const retry = await request(persistentApp).put('/v1/cloudsync/latest').set('Authorization', `Bearer ${login.body.accessToken}`)
        .set('X-CloudSync-Sequence', '2').send(savedEnvelope);
      expect(retry.status).toBe(200);
      expect(retry.body.revision).toBe(1);
      const stale = await request(persistentApp).put('/v1/cloudsync/latest').set('Authorization', `Bearer ${login.body.accessToken}`)
        .set('X-CloudSync-Sequence', '1').send(envelope('00000000-0000-4000-8000-000000000002'));
      expect(stale.status).toBe(409);
    } finally {
      persistent.close();
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
