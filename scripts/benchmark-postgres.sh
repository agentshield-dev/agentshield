#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
container="agentshield-postgres-benchmark-$$-${RANDOM}"
password="benchmark-$$-${RANDOM}"

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
  --env POSTGRES_DB=agentshield_benchmark \
  postgres:16-alpine >/dev/null

for _ in {1..60}; do
  if docker exec "$container" pg_isready --username agentshield --dbname agentshield_benchmark >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "$container" pg_isready --username agentshield --dbname agentshield_benchmark >/dev/null

address="$(docker port "$container" 5432/tcp | head -n 1)"
port="${address##*:}"
export AGENTSHIELD_TEST_DATABASE_URL="postgres://agentshield:${password}@127.0.0.1:${port}/agentshield_benchmark?sslmode=disable"

cd "$repo_root"
go test -run '^$' -bench '^BenchmarkPostgreSQL' -benchmem -count=5 ./pkg/state
