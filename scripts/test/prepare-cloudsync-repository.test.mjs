import assert from 'node:assert/strict';
import test from 'node:test';
import { prepareRepository } from '../prepare-cloudsync-repository.mjs';

function mockRequest(responses) {
  const calls = [];
  const request = async (url, options) => {
    calls.push({ url, ...options });
    assert.ok(responses.length, 'Unexpected Docker Hub request');
    const [status, data = {}] = responses.shift();
    return new Response(JSON.stringify(data), { status });
  };
  return { request, calls };
}

test('creates the intended public repository with its README and verifies anonymous access', async () => {
  const mock = mockRequest([[200, { access_token: 'bearer' }], [404], [201], [200, { is_private: false }]]);
  await prepareRepository({ token: 'secret', readme: '# CloudSync', request: mock.request });
  assert.equal(mock.calls[0].url, 'https://hub.docker.com/v2/auth/token');
  assert.deepEqual(JSON.parse(mock.calls[0].body), { identifier: 'x4bnet', secret: 'secret' });
  assert.equal(mock.calls[1].url, 'https://hub.docker.com/v2/namespaces/x4bnet/repositories/boostssh-cloudsync');
  assert.equal(mock.calls[2].url, 'https://hub.docker.com/v2/namespaces/x4bnet/repositories');
  assert.equal(mock.calls[2].method, 'POST');
  const body = JSON.parse(mock.calls[2].body);
  assert.equal(body.namespace, 'x4bnet');
  assert.equal(body.name, 'boostssh-cloudsync');
  assert.equal(body.is_private, false);
  assert.equal(body.full_description, '# CloudSync');
  assert.equal(mock.calls[2].headers.Authorization, 'Bearer bearer');
  assert.equal(mock.calls[3].headers.Authorization, undefined);
  assert.equal(mock.calls[3].url, 'https://hub.docker.com/v2/namespaces/x4bnet/repositories/boostssh-cloudsync');
});

test('existing public repository needs no write', async () => {
  const mock = mockRequest([[200, { access_token: 'bearer' }], [200, { is_private: false }], [200, { is_private: false }]]);
  await prepareRepository({ token: 'secret', readme: '', request: mock.request });
  assert.deepEqual(mock.calls.map(call => call.method), ['POST', 'GET', 'GET']);
});

test('a configured publishing identity does not change the target namespace', async () => {
  const mock = mockRequest([[200, { access_token: 'bearer' }], [404], [201], [200, { is_private: false }]]);
  await prepareRepository({ username: 'publisher', token: 'secret', readme: '', request: mock.request });
  assert.deepEqual(JSON.parse(mock.calls[0].body), { identifier: 'publisher', secret: 'secret' });
  assert.equal(JSON.parse(mock.calls[2].body).namespace, 'x4bnet');
  assert.equal(JSON.parse(mock.calls[2].body).name, 'boostssh-cloudsync');
});

test('an empty publishing identity fails before making a request', async () => {
  const mock = mockRequest([]);
  await assert.rejects(prepareRepository({ username: '', token: 'secret', request: mock.request }), /Missing DOCKERHUB_USERNAME/);
  assert.equal(mock.calls.length, 0);
});

test('a private repository blocks publication', async () => {
  const mock = mockRequest([[200, { access_token: 'bearer' }], [200, { is_private: true }]]);
  await assert.rejects(prepareRepository({ token: 'secret', request: mock.request }), /visibility to Public/);
});

test('missing credentials fail before making a request', async () => {
  const mock = mockRequest([]);
  await assert.rejects(prepareRepository({ request: mock.request }), /Missing DOCKERHUB_TOKEN/);
  assert.equal(mock.calls.length, 0);
});

test('authentication and repository failures stop publication without printing response secrets', async () => {
  for (const responses of [
    [[401, { secret: 'must-not-print' }]],
    [[200, {}]],
    [[200, { access_token: 'bearer' }], [403]],
    [[200, { access_token: 'bearer' }], [404], [403]],
    [[200, { access_token: 'bearer' }], [200, { is_private: false }], [404]]
  ]) {
    const mock = mockRequest(responses);
    await assert.rejects(prepareRepository({ token: 'secret', request: mock.request }), error => {
      assert.doesNotMatch(error.message, /must-not-print/);
      return true;
    });
  }
});

test('concurrent creation is accepted only if the repository is publicly readable', async () => {
  for (const status of [400, 409]) {
    const mock = mockRequest([[200, { access_token: 'bearer' }], [404], [status], [200, { is_private: false }]]);
    await prepareRepository({ token: 'secret', request: mock.request });
  }
});

test('creation denied to a publishing token explains the one-time repository setup', async () => {
  const mock = mockRequest([[200, { access_token: 'bearer' }], [404], [403, { detail: 'must-not-print' }]]);
  await assert.rejects(prepareRepository({ token: 'secret', request: mock.request }), error => {
    assert.match(error.message, /HTTP 403/);
    assert.match(error.message, /Create x4bnet\/boostssh-cloudsync as Public in Docker Hub, then rerun CI/);
    assert.doesNotMatch(error.message, /must-not-print/);
    return true;
  });
  assert.equal(mock.calls.length, 3);
});
