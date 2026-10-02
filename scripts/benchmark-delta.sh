#!/usr/bin/env bash
set -euo pipefail

before=${1:?before benchmark output is required}
after=${2:?after benchmark output is required}

median_metric() {
  local file=$1 benchmark=$2 unit=$3
  awk -v benchmark="$benchmark" -v unit="$unit" '
    $1 ~ ("^" benchmark "-[0-9]+$") {
      for (field = 2; field <= NF; field++) {
        if ($field == unit) print $(field - 1)
      }
    }
  ' "$file" | sort -n | awk '{ values[NR] = $1 } END {
    if (NR == 0) exit 1
    if (NR % 2 == 1) print values[(NR + 1) / 2]
    else print (values[NR / 2] + values[NR / 2 + 1]) / 2
  }'
}

delta() {
  awk -v before="$1" -v after="$2" 'BEGIN {
    if (before == 0) print "n/a"
    else printf "%+.1f%%", ((after - before) / before) * 100
  }'
}

printf '| Benchmark | Base ms/op | PR ms/op | Time | Base MB/op | PR MB/op | Memory | Base allocs/op | PR allocs/op | Allocations |\n'
printf '| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n'
awk '/^Benchmark/ { name=$1; sub(/-[0-9]+$/, "", name); print name }' "$after" | sort -u | while read -r benchmark; do
  before_ns=$(median_metric "$before" "$benchmark" ns/op || true)
  after_ns=$(median_metric "$after" "$benchmark" ns/op)
  before_bytes=$(median_metric "$before" "$benchmark" B/op || true)
  after_bytes=$(median_metric "$after" "$benchmark" B/op)
  before_allocs=$(median_metric "$before" "$benchmark" allocs/op || true)
  after_allocs=$(median_metric "$after" "$benchmark" allocs/op)
  time_delta=n/a
  memory_delta=n/a
  allocation_delta=n/a
  if [[ -n "$before_ns" ]]; then
    time_delta=$(delta "$before_ns" "$after_ns")
    memory_delta=$(delta "$before_bytes" "$after_bytes")
    allocation_delta=$(delta "$before_allocs" "$after_allocs")
  fi
  awk -v name="$benchmark" \
      -v before_ns="$before_ns" -v after_ns="$after_ns" -v time_delta="$time_delta" \
      -v before_bytes="$before_bytes" -v after_bytes="$after_bytes" -v memory_delta="$memory_delta" \
      -v before_allocs="$before_allocs" -v after_allocs="$after_allocs" -v allocation_delta="$allocation_delta" \
      'BEGIN {
        base_ms = before_ns == "" ? "n/a" : sprintf("%.2f", before_ns / 1000000)
        base_mb = before_bytes == "" ? "n/a" : sprintf("%.2f", before_bytes / 1048576)
        base_allocs = before_allocs == "" ? "n/a" : sprintf("%.0f", before_allocs)
        printf "| `%s` | %s | %.2f | %s | %s | %.2f | %s | %s | %.0f | %s |\n", name, base_ms, after_ns / 1000000, time_delta, base_mb, after_bytes / 1048576, memory_delta, base_allocs, after_allocs, allocation_delta
      }'
done
