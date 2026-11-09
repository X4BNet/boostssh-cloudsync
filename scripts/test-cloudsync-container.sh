#!/usr/bin/env bash
set -euo pipefail

: "${IMAGE:?Set IMAGE to the container image to test}"
name="cloudsync-smoke-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$RANDOM"
volume="$name-data"
cleanup() {
  docker logs "$name" || true
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker volume create "$volume" >/dev/null
start_container() {
  docker run -d --name "$name" \
    --mount "type=volume,src=$volume,dst=/data" \
    --env JWT_SECRET=container-smoke-test-secret-at-least-32-characters \
    "$IMAGE" >/dev/null
}

wait_for_health() {
  for ((attempt = 0; attempt < 60; attempt++)); do
    if [ "$(docker inspect --format '{{.State.Health.Status}}' "$name")" = healthy ]; then
      return 0
    fi
    if [ "$(docker inspect --format '{{.State.Running}}' "$name")" != true ]; then
      break
    fi
    sleep 1
  done
  echo 'CloudSync did not become healthy' >&2
  return 1
}

authenticate() {
  docker exec --env AUTH_OPERATION="$1" "$name" node --input-type=module -e '
    const operation = process.env.AUTH_OPERATION;
    const response = await fetch(`http://127.0.0.1:3000/v1/auth/${operation}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "container@example.test", password: "container-test-password" })
    });
    const expected = operation === "register" ? 201 : 200;
    if (response.status !== expected) throw new Error(`${operation}: HTTP ${response.status}`);
    const tokens = await response.json();
    if (!tokens.accessToken || !tokens.refreshToken) throw new Error("Missing authentication tokens");
  '
}

start_container
wait_for_health
authenticate register
docker stop "$name" >/dev/null
docker rm "$name" >/dev/null
start_container
wait_for_health
authenticate login
echo 'Container health, authentication, and SQLite persistence checks passed'
