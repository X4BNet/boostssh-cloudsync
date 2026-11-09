export interface Config {
  databasePath: string;
  jwtSecret: string;
  accessTokenSeconds: number;
  refreshTokenSeconds: number;
  snapshotLimit: number;
  maxBackupBytes: number;
}

export function loadConfig(overrides: Partial<Config> = {}): Config {
  return {
    databasePath: process.env.DATABASE_PATH ?? './data/cloudsync.sqlite',
    jwtSecret: process.env.JWT_SECRET ?? '',
    accessTokenSeconds: 15 * 60,
    refreshTokenSeconds: 30 * 24 * 60 * 60,
    snapshotLimit: 10,
    maxBackupBytes: 10 * 1024 * 1024,
    ...overrides
  };
}
