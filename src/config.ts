export interface Config {
  databasePath: string;
  jwtSecret: string;
  accessTokenSeconds: number;
  refreshTokenSeconds: number;
  snapshotLimit: number;
  maxBackupBytes: number;
  registrationEnabled: boolean;
  trustedProxies: string[];
  authWindowSeconds: number;
  authIpLimit: number;
  authAccountLimit: number;
  passwordHashConcurrency: number;
  rateLimitMaxEntries: number;
  userRequestsPerMinute: number;
  maxUsers: number;
  maxUserStorageBytes: number;
  maxSnapshotStorageBytes: number;
  maxDatabaseBytes: number;
  maxUploadReceiptsPerUser: number;
  maxDevicesPerUser: number;
  maxRefreshTokensPerUser: number;
  maxAuditEvents: number;
  auditRetentionSeconds: number;
  maxUploadAgeSeconds: number;
  maxClockSkewSeconds: number;
}

export function loadConfig(overrides: Partial<Config> = {}): Config {
  const number = (name: string, fallback: number) => process.env[name] === undefined ? fallback : Number(process.env[name]);
  const enabled = process.env.REGISTRATION_ENABLED ?? 'true';
  if (!['true', 'false'].includes(enabled)) throw new Error('REGISTRATION_ENABLED must be true or false');
  const config: Config = {
    databasePath: process.env.DATABASE_PATH ?? './data/cloudsync.sqlite',
    jwtSecret: process.env.JWT_SECRET ?? '',
    accessTokenSeconds: 15 * 60,
    refreshTokenSeconds: 30 * 24 * 60 * 60,
    snapshotLimit: 10,
    maxBackupBytes: 10 * 1024 * 1024,
    registrationEnabled: enabled === 'true',
    trustedProxies: (process.env.TRUSTED_PROXIES ?? '').split(',').map(value => value.trim()).filter(Boolean),
    authWindowSeconds: number('AUTH_WINDOW_SECONDS', 15 * 60),
    authIpLimit: number('AUTH_IP_LIMIT', 100),
    authAccountLimit: number('AUTH_ACCOUNT_LIMIT', 10),
    passwordHashConcurrency: number('PASSWORD_HASH_CONCURRENCY', 2),
    rateLimitMaxEntries: 10_000,
    userRequestsPerMinute: number('USER_REQUESTS_PER_MINUTE', 60),
    maxUsers: number('MAX_USERS', 100),
    maxUserStorageBytes: number('MAX_USER_STORAGE_BYTES', 50 * 1024 * 1024),
    maxSnapshotStorageBytes: number('MAX_SNAPSHOT_STORAGE_BYTES', 512 * 1024 * 1024),
    maxDatabaseBytes: number('MAX_DATABASE_BYTES', 768 * 1024 * 1024),
    maxUploadReceiptsPerUser: number('MAX_UPLOAD_RECEIPTS_PER_USER', 10_000),
    maxDevicesPerUser: number('MAX_DEVICES_PER_USER', 32),
    maxRefreshTokensPerUser: number('MAX_REFRESH_TOKENS_PER_USER', 10_000),
    maxAuditEvents: number('MAX_AUDIT_EVENTS', 10_000),
    auditRetentionSeconds: number('AUDIT_RETENTION_SECONDS', 30 * 24 * 60 * 60),
    maxUploadAgeSeconds: number('MAX_UPLOAD_AGE_SECONDS', 30 * 24 * 60 * 60),
    maxClockSkewSeconds: 300,
    ...overrides
  };
  for (const [key, value] of Object.entries(config)) {
    if (typeof value === 'number' && (!Number.isSafeInteger(value) || value <= 0 || value > 2 ** 31 - 1)) {
      throw new Error(`${key} must be a positive integer no greater than 2147483647`);
    }
  }
  if (typeof config.registrationEnabled !== 'boolean') throw new Error('registrationEnabled must be boolean');
  return config;
}
