import type { ErrorRequestHandler, RequestHandler } from 'express';
import { createHash } from 'node:crypto';

export class HttpError extends Error {
  constructor(public readonly status: number, public readonly code: string, public readonly retryAfter?: number) {
    super(code);
  }
}

/** Fixed windows with a hard key cap; a full map refuses new keys until expiry. */
export class RateLimiter {
  private readonly entries = new Map<string, { count: number; resetAt: number }>();
  private nextSweep = 0;
  constructor(private readonly limit: number, private readonly windowSeconds: number, private readonly maxEntries: number) {}

  consume(key: string): number {
    const now = Date.now();
    let entry = this.entries.get(key);
    if (entry && entry.resetAt <= now) { this.entries.delete(key); entry = undefined; }
    if (!entry) {
      if (this.entries.size >= this.maxEntries) {
        if (now >= this.nextSweep) {
          for (const [storedKey, stored] of this.entries) if (stored.resetAt <= now) this.entries.delete(storedKey);
          this.nextSweep = now + 1000;
        }
        if (this.entries.size >= this.maxEntries) return this.windowSeconds;
      }
      entry = { count: 0, resetAt: now + this.windowSeconds * 1000 };
      this.entries.set(key, entry);
    }
    if (entry.count >= this.limit) return Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
    entry.count++;
    return 0;
  }
}

export const limitRequests = (limiter: RateLimiter, key: (request: Parameters<RequestHandler>[0], response: Parameters<RequestHandler>[1]) => string): RequestHandler =>
  (request, response, next) => {
    const retryAfter = limiter.consume(key(request, response));
    if (retryAfter) return next(new HttpError(429, 'rate_limited', retryAfter));
    next();
  };

export const accountRateKey = (email: string) => createHash('sha256').update(email).digest('hex');

/** Reject excess work immediately rather than creating an unbounded password queue. */
export class PasswordGate {
  private active = 0;
  constructor(private readonly limit: number) {}

  async run<T>(work: () => Promise<T>): Promise<T> {
    if (this.active >= this.limit) throw new HttpError(429, 'authentication_busy', 1);
    this.active++;
    try { return await work(); } finally { this.active--; }
  }
}

export const handleError: ErrorRequestHandler = (error: unknown, _request, response, next) => {
  if (response.headersSent) return next(error);
  if (error instanceof HttpError) {
    if (error.retryAfter) response.set('Retry-After', String(error.retryAfter));
    return response.status(error.status).json({ error: error.code });
  }
  const details = error as { type?: string; code?: string } | null;
  const parserErrors: Record<string, [number, string]> = {
    'entity.parse.failed': [400, 'invalid_json'],
    'entity.too.large': [413, 'request_too_large'],
    'encoding.unsupported': [415, 'unsupported_encoding'],
    'charset.unsupported': [415, 'unsupported_charset'],
    'request.aborted': [400, 'invalid_request'],
    'request.size.invalid': [400, 'invalid_request']
  };
  const parserError = details?.type && parserErrors[details.type];
  if (parserError) return response.status(parserError[0]).json({ error: parserError[1] });
  if (details?.code === 'SQLITE_FULL') return response.status(507).json({ error: 'storage_quota_exceeded' });
  // Error messages, stacks and request data can contain passwords or token fragments.
  console.error(JSON.stringify({ event: 'request_error', code: 'internal_error' }));
  return response.status(500).json({ error: 'internal_error' });
};
