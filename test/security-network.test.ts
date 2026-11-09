import { fork } from 'node:child_process';
import { once } from 'node:events';
import { connect } from 'node:net';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
import { expect, it } from 'vitest';

async function withServer(check: (port: number, stderr: () => string) => Promise<void>) {
  const child = fork(fileURLToPath(new URL('./fixtures/security-server.ts', import.meta.url)), {
    execArgv: ['--import', 'tsx'], silent: true, env: { ...process.env, NODE_ENV: 'production' }
  });
  let stderr = '';
  child.stderr!.setEncoding('utf8');
  child.stderr!.on('data', chunk => { stderr += chunk; });
  const exit = once(child, 'exit');
  const deadline = setTimeout(() => child.kill(), 8000);
  try {
    const [ready] = await Promise.race([
      once(child, 'message'), exit.then(() => { throw new Error('Regression server exited before startup'); })
    ]);
    await check((ready as { port: number }).port, () => stderr);
    expect(child.exitCode).toBeNull();
  } finally {
    if (child.connected) child.send('stop');
    await exit;
    clearTimeout(deadline);
  }
  expect(child.exitCode).toBe(0);
  expect(stderr).not.toContain('CANARY9');
  expect(stderr).not.toContain('Unhandled');
}

it('survives the original delayed compressed-body attack in a separate process', async () => {
  await withServer(async port => {
    const first = Buffer.concat([gzipSync('{"a":1}'), Buffer.from([0])]);
    const trailing = Buffer.alloc(100 * 1024, 0x58);
    const socket = connect(port, '127.0.0.1');
    socket.on('error', () => {});
    try {
      await once(socket, 'connect');
      const response = once(socket, 'data');
      socket.write(`POST /v1/auth/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: ${first.length + trailing.length}\r\n\r\n`);
      socket.write(first);
      const [data] = await response;
      expect(data.toString()).toMatch(/^HTTP\/1\.1 415 /);
      const closed = once(socket, 'close');
      socket.end(trailing);
      await closed;
      expect((await fetch(`http://127.0.0.1:${port}/v1/health`)).status).toBe(200);
    } finally { socket.destroy(); }
  });
}, 10_000);

it('keeps malformed credential fragments out of production stderr', async () => {
  await withServer(async (port, stderr) => {
    for (const body of ['{"password":CANARY9}', '{"refreshToken":CANARY9}']) {
      const response = await fetch(`http://127.0.0.1:${port}/v1/auth/login`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body
      });
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({ error: 'invalid_json' });
    }
    expect(stderr()).toBe('');
  });
}, 10_000);
