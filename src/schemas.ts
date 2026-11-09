import { z } from 'zod';

const base64 = z.string().min(1).regex(/^[A-Za-z0-9+/]+={0,2}$/);

export const credentialsSchema = z.object({
  email: z.email().transform((value) => value.trim().toLowerCase()),
  password: z.string().min(12).max(1024)
}).strict();

export const refreshSchema = z.object({ refreshToken: z.string().min(32).max(1024) }).strict();

export const envelopeSchema = z.object({
  formatVersion: z.literal(2),
  schemaVersion: z.number().int().min(1),
  backupId: z.uuid(),
  deviceId: z.string().min(1).max(200),
  createdAt: z.iso.datetime(),
  kdf: z.object({
    name: z.literal('argon2id'),
    salt: base64,
    memoryKiB: z.literal(65536),
    iterations: z.literal(3),
    parallelism: z.literal(1)
  }).strict(),
  cipher: z.object({
    name: z.literal('AES-256-GCM'),
    nonce: base64,
    ciphertext: base64
  }).strict()
}).strict();

export type CloudSyncEnvelope = z.infer<typeof envelopeSchema>;
