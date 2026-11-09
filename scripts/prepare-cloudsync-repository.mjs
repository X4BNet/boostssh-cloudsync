import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const api = 'https://hub.docker.com/v2';
const repositories = '/namespaces/x4bnet/repositories';
const repository = `${repositories}/boostssh-cloudsync`;

// Only this public image repository is managed here; GitHub visibility is separate.
export async function prepareRepository({ token, readme, request = fetch }) {
  if (!token) throw new Error('Missing DOCKERHUB_TOKEN Actions secret for publishing to x4bnet/boostssh-cloudsync');
  const call = async (path, { method = 'GET', body, bearer } = {}) => {
    const response = await request(`${api}${path}`, {
      method,
      headers: {
        ...(body ? { 'Content-Type': 'application/json' } : {}),
        ...(bearer ? { Authorization: `Bearer ${bearer}` } : {})
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
      signal: AbortSignal.timeout(30_000)
    });
    return response;
  };
  const check = (response, operation) => {
    // Never print authentication responses or request bodies containing credentials.
    if (!response.ok) throw new Error(`Docker Hub ${operation} failed (HTTP ${response.status})`);
  };

  const login = await call('/auth/token', {
    // Authenticate as the publishing user, independently of the target namespace.
    method: 'POST', body: { identifier: 'splitice', secret: token }
  });
  check(login, 'authentication');
  const { access_token: bearer } = await login.json();
  if (!bearer) throw new Error('Docker Hub did not return an access token');
  const existing = await call(repository, { bearer });
  if (existing.status === 404) {
    const created = await call(repositories, {
      method: 'POST', bearer,
      body: {
        namespace: 'x4bnet', name: 'boostssh-cloudsync', registry: 'docker.io',
        is_private: false,
        description: 'Self-hosted BoostSSH CloudSync server for client-encrypted backups.',
        full_description: readme
      }
    });
    if (created.status === 403) {
      throw new Error('Docker Hub repository creation failed (HTTP 403). '
        + 'Create x4bnet/boostssh-cloudsync as Public in Docker Hub, then rerun CI. '
        + 'The DOCKERHUB_TOKEN may allow image pushes without repository creation.');
    }
    // Another branch build may have created the same repository concurrently.
    if (![400, 409].includes(created.status)) check(created, 'repository creation');
  } else {
    check(existing, 'repository lookup');
    if ((await existing.json()).is_private !== false) {
      throw new Error('Set x4bnet/boostssh-cloudsync visibility to Public in Docker Hub before publishing');
    }
  }
  // Anonymous access verifies the repository is public, independently of our token.
  const published = await call(repository);
  check(published, 'public repository verification');
  if ((await published.json()).is_private !== false) throw new Error('Docker Hub repository must be public');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await prepareRepository({
      token: process.env.DOCKERHUB_TOKEN,
      readme: await readFile(new URL('../README.md', import.meta.url), 'utf8')
    });
    console.log('Verified public Docker Hub repository: x4bnet/boostssh-cloudsync');
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
