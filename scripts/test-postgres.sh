#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
container="agentshield-postgres-test-$$-${RANDOM}"
password="integration-$$-${RANDOM}"

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

command -v docker >/dev/null 2>&1 || { printf 'docker is required\n' >&2; exit 1; }

docker run --detach --rm \
  --name "$container" \
  --publish 127.0.0.1::5432 \
  --env POSTGRES_USER=agentshield \
  --env POSTGRES_PASSWORD="$password" \
  --env POSTGRES_DB=agentshield_test \
  postgres:16-alpine >/dev/null

for _ in {1..60}; do
  if docker exec "$container" pg_isready --username agentshield --dbname agentshield_test >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "$container" pg_isready --username agentshield --dbname agentshield_test >/dev/null

address="$(docker port "$container" 5432/tcp | head -n 1)"
port="${address##*:}"
export AGENTSHIELD_TEST_DATABASE_URL="postgres://agentshield:${password}@127.0.0.1:${port}/agentshield_test?sslmode=disable"
export AGENTSHIELD_DATABASE_URL="$AGENTSHIELD_TEST_DATABASE_URL"

cd "$repo_root"
printf 'PostgreSQL %s on 127.0.0.1:%s\n' "$(docker exec "$container" postgres --version | awk '{print $3}')" "$port"
go test -race -count=1 ./pkg/state ./pkg/api
printf 'PostgreSQL integration passed\n'
