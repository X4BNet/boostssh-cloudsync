# BoostSSH CloudSync server

CloudSync is the optional self-hosted synchronization service for BoostSSH. It
stores opaque, client-encrypted backup envelopes in SQLite. Encryption and
decryption happen on the client. The storage API receives neither the derived
backup key nor backup plaintext. Account-only sync derives its key on-device
from the account password. Account passwords are sent over HTTPS for
authentication and stored as Argon2id hashes; a server that captures those
passwords can derive backup keys. See [the client trust model](https://github.com/X4BNet/android-boostssh/blob/main/docs/CLOUDSYNC.md).

## Docker image

The image is published to [x4bnet/boostssh-cloudsync on Docker Hub](https://hub.docker.com/r/x4bnet/boostssh-cloudsync).
It runs Node.js 24 on Debian Bookworm as the unprivileged `node` user (UID/GID
1000), exposes HTTP on port `3000`, and stores the database at
`/data/cloudsync.sqlite`. CI builds and tests the `linux/amd64` image.

### Quick start with Docker Compose

From the repository root, copy `.env.example` to `.env`. Generate a
secret, then set `JWT_SECRET` in `.env` to that value:

```sh
docker run --rm node:24-bookworm-slim node -e "console.log(require('node:crypto').randomBytes(48).toString('base64url'))"
```

Start the published image:

```sh
docker compose pull
docker compose up -d
docker compose ps
curl --fail http://127.0.0.1:3000/v1/health
```

The health endpoint returns `{"status":"ok"}`. The Compose service binds only to
`127.0.0.1:3000`. Put a TLS reverse proxy in front of it and configure BoostSSH
with the public HTTPS server URL. See the
[client and protocol documentation](https://github.com/X4BNet/android-boostssh/blob/main/docs/CLOUDSYNC.md).

### Run without a source checkout

Create a file named `.env` containing a generated `JWT_SECRET` as above, then run:

```sh
docker volume create cloudsync-data
docker run -d --name cloudsync --restart unless-stopped \
  --env-file .env \
  --mount type=volume,src=cloudsync-data,dst=/data \
  --publish 127.0.0.1:3000:3000 \
  x4bnet/boostssh-cloudsync:latest
```

The command uses POSIX shell line continuations; in PowerShell, run it on one
line or replace each trailing `\` with a backtick. A fresh named volume receives
the image's `/data` ownership automatically. If using a host bind mount instead,
make the directory writable by UID/GID 1000.

### Kubernetes example

The [Kubernetes manifest](kubernetes/statefulset.yaml) deploys one CloudSync
replica with a persistent volume claim. Create the JWT secret before applying
the manifest:

```sh
kubectl create secret generic cloudsync \
  --from-literal=JWT_SECRET="$(openssl rand -base64 48 | tr -d '\n')"
kubectl apply -f kubernetes/statefulset.yaml
```

The `cloudsync` Service is internal to the cluster. Put an HTTPS ingress or
reverse proxy in front of it and forward traffic to `cloudsync:3000`. Keep the
StatefulSet at one replica: SQLite and its ReadWriteOnce volume are intended for
a single server instance. The PVC is retained when the StatefulSet is removed;
back it up while the server is stopped, as described in
[Updates and backups](#updates-and-backups). The cluster needs a default
StorageClass, or you can set one in the manifest. For production, pin the image
to a version tag or digest instead of `latest`.

The init container sets the mounted data directory to UID/GID 1000, matching
the unprivileged server process. It needs permission to run as root with only
`CAP_CHOWN`; on clusters that prohibit this or on volumes that disallow
`chown` (such as some root-squashed NFS exports), configure the volume's
ownership for UID/GID 1000 and remove that init container. The pod's `fsGroup`
is also set to 1000.

### Image tags

| Source of CI run | Published tags |
| --- | --- |
| Push or manual run on `main` | `latest`, `git-<full-40-character-commit-SHA>` |
| Push or manual run on another branch | `branch-<branch-name>`, `git-<full-40-character-commit-SHA>` |
| Git tag, for example `v1.2.3` | `v1.2.3`, `git-<full-40-character-commit-SHA>` |
| Pull request | Build and smoke test only; no publishing or Docker Hub credentials |

Tags follow the x4b-site convention: `latest` tracks the default branch, and
release tags keep their Git tag spelling, including a leading `v`. Characters
unsupported in Docker tags, such as `/`, become `-`. Git tags do not normally
move `latest`; reserve the Git tag name `latest` for that purpose if needed.
The package.json version alone does not publish a version tag.

Set `CLOUDSYNC_TAG` in `.env` to a version or `git-...` tag to select a particular
build in Compose. Tags can be republished by rerunning CI; use an image digest
(`x4bnet/boostssh-cloudsync@sha256:...`) when you need immutable image content.

### Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `JWT_SECRET` | Required | At least 32 characters; generate a random deployment secret. |
| `DATABASE_PATH` | `/data/cloudsync.sqlite` in Docker; `./data/cloudsync.sqlite` locally | SQLite database file. Keep it on persistent storage. |
| `PORT` | `3000` | HTTP listener port; update port mappings if overriding it. |
| `CLOUDSYNC_TAG` | `latest` | Compose image selection only; not a server setting. |

The server listens on `0.0.0.0` inside the container. The image includes a
health check against `/v1/health`, and graceful shutdown closes SQLite. Logs go
to stdout/stderr; inspect them with `docker compose logs --tail=100 cloudsync`.
Health reports HTTP availability; it is not a database integrity check.

The following limits are currently fixed in the server configuration:

- Access tokens expire after 15 minutes; refresh tokens expire after 30 days.
- Refresh tokens rotate on use. Reusing an old token revokes its token family.
- The JSON request limit is 10 MiB, including encoded envelope metadata.
- The last 10 snapshot revisions per account are retained. Clients retrieve
  only the latest snapshot; there is no history API.
- Account registration is open, passwords must contain at least 12 characters,
  and the server has no built-in rate limiting. Apply access restrictions and
  rate limits at the reverse proxy as appropriate for your deployment.

### Updates and backups

Set the desired `CLOUDSYNC_TAG`, then run `docker compose pull` and
`docker compose up -d`. Back up before upgrading. To roll back, restore the
previous image tag and, if a database migration requires it, the matching backup.

Back up the entire `cloudsync-data` volume, which contains accounts, password
hashes, hashed refresh tokens, encrypted snapshots, and audit events. Compose
normally prefixes its volume name with the project name. SQLite uses WAL mode:
stop the service with `docker compose stop cloudsync` before copying the volume,
then start it again with `docker compose start cloudsync`. For online backups,
use SQLite's backup API rather than copying a live database file alone.

Restore into a stopped service's data volume and preserve UID/GID 1000 ownership.
Keep the JWT secret separately. Rotating it invalidates existing access tokens;
stored refresh tokens can still obtain new access tokens. It does not change
snapshot encryption. The client passphrase remains necessary to decrypt a
backup. `docker compose down` retains the volume; adding `--volumes` deletes it.

## API

All request and response bodies use JSON. Snapshot routes require
`Authorization: Bearer <accessToken>`.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/health` | Unauthenticated health check. |
| `POST` | `/v1/auth/register` | Register with `email` and `password`; returns access and refresh tokens. |
| `POST` | `/v1/auth/login` | Authenticate with `email` and `password`. |
| `POST` | `/v1/auth/refresh` | Exchange `refreshToken` for a rotated token pair. |
| `POST` | `/v1/auth/logout` | Revoke the family associated with `refreshToken`. |
| `GET` | `/v1/cloudsync/latest` | Read the caller's latest encrypted envelope, revision, and receipt time. |
| `PUT` | `/v1/cloudsync/latest` | Store a version 2 encrypted envelope and assign a revision. |
| `DELETE` | `/v1/cloudsync` | Delete all of the caller's retained snapshots. |

Envelopes carry Argon2id parameters and AES-256-GCM ciphertext. The server
validates the envelope structure but cannot authenticate or decrypt its contents;
the client does that. Retrying an identical backup ID returns `200` with its
original revision without changing the latest snapshot; reusing an ID with
different contents returns `409`. A missing snapshot returns `404`. Accounts
cannot read or modify other accounts' snapshots.

Current Android clients send a persisted, increasing `X-CloudSync-Sequence`
header for each device. A request older than the last accepted sequence for that
account and device returns `409` (`stale_upload`). Upgrade the server with the
client to protect against delayed requests arriving after newer backups. Older
clients without the header retain upload-order behavior. Small upload receipts
(ciphertext hashes and revisions) and sequence counters survive ciphertext
retention and deletion, so retries cannot restore deleted or superseded data.

## Local development

Use Node.js 24 and npm. Native dependencies (`better-sqlite3` and `argon2`) may
require a compiler toolchain if no prebuilt binary is available.

```powershell
npm ci
npm test
npm run build
$env:JWT_SECRET = node -e "console.log(require('node:crypto').randomBytes(48).toString('base64url'))"
npm run dev
```

`npm run dev` does not load `.env` automatically. Export the environment as above,
or run the compiled service with `node --env-file=.env dist/server.js`.

To build and run your local source using the same Compose configuration:

```sh
docker build -t x4bnet/boostssh-cloudsync:local .
```

Set `CLOUDSYNC_TAG=local` in `.env`, then run
`docker compose up -d --pull never`. The Dockerfile compiles TypeScript and
includes only production dependencies in the runtime image.

## CI publishing setup

The repository's [CI workflow](.github/workflows/ci.yml)
runs server tests, compiles TypeScript, builds the container, and checks health,
account registration, and login after recreating the container with the same
SQLite volume. It publishes that tested image on pushes and manual runs in
`X4BNet/boostssh-cloudsync`. Both CI and workflow validation use GitHub-hosted
`ubuntu-latest` runners.

Before the first publishing run, configure the `X4BNet/boostssh-cloudsync` GitHub Actions repository secret
`DOCKERHUB_TOKEN` with a **splitice** Docker Hub personal access token that has
Read & Write permissions for `x4bnet/boostssh-cloudsync`. The publishing account must have
write access to the `x4bnet` namespace. Create `x4bnet/boostssh-cloudsync` as **Public** in
Docker Hub before running CI; image push permissions do not necessarily allow
repository creation through the Hub API. Add this README as its repository overview.
If the repository is missing, CI attempts to create it and upload this README as
its initial overview, but a token without creation permission will receive HTTP 403.
Create the public repository through Docker Hub and rerun CI in that case. CI verifies
anonymous repository access before pushing. If the repository already exists as
private, set its visibility to Public in Docker Hub first. Existing repository
overviews are preserved. GitHub source repository visibility is managed separately.

Run the Docker publishing checks locally on Linux from the repository root:

```sh
node --test scripts/test/prepare-cloudsync-repository.test.mjs
docker build -t boostssh-cloudsync:ci .
IMAGE=boostssh-cloudsync:ci bash scripts/test-cloudsync-container.sh
```

The container check removes its disposable container and SQLite volume when it exits.

This software is provided as-is. No support channel, support email, or
service-level commitment is offered.
