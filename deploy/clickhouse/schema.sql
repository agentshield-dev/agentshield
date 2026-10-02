CREATE DATABASE IF NOT EXISTS agentshield;

CREATE TABLE IF NOT EXISTS agentshield.telemetry_events
(
    event_id String,
    observed_at DateTime64(3, 'UTC'),
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3),
    kind LowCardinality(String),
    plugin_id LowCardinality(String),
    subject_scheme_group LowCardinality(String),
    subject_scheme_version LowCardinality(String),
    subject_scheme_kind LowCardinality(String),
    subject_authority String,
    subject_key String,
    object_scheme_group LowCardinality(String),
    object_scheme_version LowCardinality(String),
    object_scheme_kind LowCardinality(String),
    object_authority String,
    object_key String,
    operation LowCardinality(String),
    outcome LowCardinality(String),
    coverage LowCardinality(String),
    count UInt64,
    properties Map(String, String),
    source_id LowCardinality(String),
    evidence_ids Array(String)
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMMDD(observed_at)
ORDER BY (toDate(observed_at), plugin_id, source_id, kind, event_id)
TTL observed_at + INTERVAL 30 DAY DELETE
-- AgentShield sends an insert_deduplication_token per batch. The window
-- enables token deduplication on this non-replicated table, which also keeps a
-- retried batch out of telemetry_rollup_minute_mv.
SETTINGS index_granularity = 8192, non_replicated_deduplication_window = 1000;

CREATE TABLE IF NOT EXISTS agentshield.telemetry_rollup_minute
(
    window_start DateTime('UTC'),
    plugin_id LowCardinality(String),
    kind LowCardinality(String),
    subject_scheme_group LowCardinality(String),
    subject_scheme_version LowCardinality(String),
    subject_scheme_kind LowCardinality(String),
    subject_authority String,
    subject_key String,
    object_scheme_group LowCardinality(String),
    object_scheme_version LowCardinality(String),
    object_scheme_kind LowCardinality(String),
    object_authority String,
    object_key String,
    operation LowCardinality(String),
    outcome LowCardinality(String),
    coverage LowCardinality(String),
    source_id LowCardinality(String),
    count UInt64
)
ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(window_start)
ORDER BY (
    window_start,
    plugin_id,
    source_id,
    kind,
    subject_scheme_group,
    subject_scheme_version,
    subject_scheme_kind,
    subject_authority,
    subject_key,
    object_scheme_group,
    object_scheme_version,
    object_scheme_kind,
    object_authority,
    object_key,
    operation,
    outcome,
    coverage
)
TTL window_start + INTERVAL 180 DAY DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS agentshield.telemetry_rollup_minute_mv
TO agentshield.telemetry_rollup_minute
AS
SELECT
    toStartOfMinute(observed_at) AS window_start,
    plugin_id,
    kind,
    subject_scheme_group,
    subject_scheme_version,
    subject_scheme_kind,
    subject_authority,
    subject_key,
    object_scheme_group,
    object_scheme_version,
    object_scheme_kind,
    object_authority,
    object_key,
    operation,
    outcome,
    coverage,
    source_id,
    sum(count) AS count
FROM agentshield.telemetry_events
GROUP BY
    window_start,
    plugin_id,
    kind,
    subject_scheme_group,
    subject_scheme_version,
    subject_scheme_kind,
    subject_authority,
    subject_key,
    object_scheme_group,
    object_scheme_version,
    object_scheme_kind,
    object_authority,
    object_key,
    operation,
    outcome,
    coverage,
    source_id;
