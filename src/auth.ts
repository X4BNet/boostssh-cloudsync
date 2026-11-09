import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { RequestHandler } from 'express';
import type { Config } from './config.js';
import type { SqliteDatabase } from './database.js';
import { HttpError } from './security.js';

// Public, non-account hash with the same Argon2 cost as real credentials.
export const dummyPasswordHash = '$argon2id$v=19$m=65536,p=1,t=3$hfkRmP9WUYQZOwrzKaUHgQ$HIfm9XklQKNdYCPwghPmxw9UQ71yiNiVPLO6KakrJRA';

export interface AuthenticatedRequest {
  userId: string;
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export function issueTokens(database: SqliteDatabase, config: Config, userId: string, familyId = randomUUID()) {
  database.prepare('DELETE FROM refresh_tokens WHERE expires_at <= ?').run(Math.floor(Date.now() / 1000));
  const count = database.prepare('SELECT COUNT(*) AS count FROM refresh_tokens WHERE user_id = ?').get(userId) as { count: number };
  if (count.count >= config.maxRefreshTokensPerUser) throw new HttpError(507, 'refresh_token_limit');
  const accessToken = jwt.sign({ typ: 'access' }, config.jwtSecret, { subject: userId, expiresIn: config.accessTokenSeconds });
  const refreshToken = randomBytes(48).toString('base64url');
  database.prepare(`INSERT INTO refresh_tokens(token_hash, family_id, user_id, expires_at)
    VALUES (?, ?, ?, ?)`).run(hashToken(refreshToken), familyId, userId, Math.floor(Date.now() / 1000) + config.refreshTokenSeconds);
  return { accessToken, refreshToken, expiresIn: config.accessTokenSeconds };
}

export const requireAuth = (config: Config): RequestHandler => (request, response, next) => {
  const value = request.header('authorization');
  if (!value?.startsWith('Bearer ')) {
    response.status(401).json({ error: 'unauthorized' });
    return;
  }
  try {
    const payload = jwt.verify(value.slice(7), config.jwtSecret);
    if (typeof payload === 'string' || payload.typ !== 'access' || !payload.sub) throw new Error('invalid token');
    response.locals.auth = { userId: payload.sub } satisfies AuthenticatedRequest;
    next();
  } catch {
    response.status(401).json({ error: 'unauthorized' });
  }
};

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 1 });
}

export async function verifyPassword(hash: string, password: string): Promise<boolean> {
  try { return await argon2.verify(hash, password); } catch { return false; }
}
