CREATE TABLE findings (
    finding_id text PRIMARY KEY CHECK (finding_id <> ''),
    analysis_id text NOT NULL CHECK (analysis_id <> ''),
    graph_sha256 text NOT NULL CHECK (graph_sha256 ~ '^[0-9a-f]{64}$'),
    category text NOT NULL CHECK (category <> ''),
    severity text NOT NULL CHECK (severity <> ''),
    model_uncertainty text NOT NULL,
    summary text NOT NULL CHECK (summary <> ''),
    signal_ids jsonb NOT NULL CHECK (jsonb_typeof(signal_ids) = 'array'),
    remediations jsonb NOT NULL CHECK (jsonb_typeof(remediations) = 'array'),
    affected_entity_ids jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(affected_entity_ids) = 'array'),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'invalidated')),
    invalidated_at timestamptz,
    invalidated_by_sequence bigint CHECK (invalidated_by_sequence > 0),
    invalidated_graph_sha256 text CHECK (invalidated_graph_sha256 ~ '^[0-9a-f]{64}$'),
    origin text NOT NULL DEFAULT 'agentic_investigation' CHECK (origin IN ('agentic_investigation', 'detection_rule')),
    detection_rule_id text,
    detection_rule_revision bigint,
    created_at timestamptz NOT NULL,
    CONSTRAINT findings_invalidation_consistent CHECK (
        (status = 'active' AND invalidated_at IS NULL AND invalidated_by_sequence IS NULL AND invalidated_graph_sha256 IS NULL)
        OR
        (status = 'invalidated' AND invalidated_at IS NOT NULL AND invalidated_by_sequence IS NOT NULL AND invalidated_graph_sha256 IS NOT NULL)
    ),
    CONSTRAINT findings_origin_consistent CHECK (
        (origin = 'agentic_investigation' AND model_uncertainty <> ''
            AND detection_rule_id IS NULL AND detection_rule_revision IS NULL)
        OR
        (origin = 'detection_rule' AND length(detection_rule_id) BETWEEN 1 AND 128
            AND detection_rule_revision > 0)
    )
);
CREATE INDEX findings_created_at_idx ON findings (created_at DESC, finding_id);
CREATE INDEX findings_active_affected_entities_idx ON findings USING gin (affected_entity_ids) WHERE status = 'active';
CREATE INDEX findings_detection_rule_idx ON findings (detection_rule_id, created_at DESC) WHERE detection_rule_id IS NOT NULL;

CREATE TABLE detector_rule_revisions (
    rule_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    definition jsonb NOT NULL,
    sha256 text NOT NULL CHECK (length(sha256) = 64),
    created_by text NOT NULL CHECK (length(created_by) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, revision)
);

CREATE TABLE detector_rulesets (
    id text PRIMARY KEY,
    sha256 text NOT NULL CHECK (length(sha256) = 64),
    created_by text NOT NULL CHECK (length(created_by) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE detector_ruleset_members (
    ruleset_id text NOT NULL REFERENCES detector_rulesets(id),
    rule_id text NOT NULL,
    rule_revision bigint NOT NULL,
    PRIMARY KEY (ruleset_id, rule_id),
    FOREIGN KEY (rule_id, rule_revision) REFERENCES detector_rule_revisions(rule_id, revision)
);

CREATE TABLE detector_activations (
    revision bigint PRIMARY KEY CHECK (revision > 0),
    ruleset_id text NOT NULL REFERENCES detector_rulesets(id),
    activated_by text NOT NULL CHECK (length(activated_by) BETWEEN 1 AND 128),
    activated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE detector_active_ruleset (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    activation_revision bigint NOT NULL REFERENCES detector_activations(revision)
);

CREATE TABLE detection_signals (
    signal_id text PRIMARY KEY CHECK (length(signal_id) BETWEEN 1 AND 256),
    through_sequence bigint NOT NULL CHECK (through_sequence >= 0),
    graph_sha256 text NOT NULL CHECK (length(graph_sha256) = 64),
    risk text NOT NULL CHECK (risk IN ('low', 'medium', 'high', 'critical')),
    reasons jsonb NOT NULL CHECK (jsonb_typeof(reasons) = 'array'),
    anchor_ids jsonb NOT NULL CHECK (jsonb_typeof(anchor_ids) = 'array'),
    window_start timestamptz NOT NULL,
    window_end timestamptz NOT NULL CHECK (window_end >= window_start),
    rule_id text CHECK (rule_id IS NULL OR length(rule_id) BETWEEN 1 AND 128),
    rule_revision bigint CHECK (rule_revision IS NULL OR rule_revision > 0),
    ruleset_digest text,
    investigation text NOT NULL CHECK (investigation IN ('investigated', 'queued', 'below_threshold', 'disabled', 'shadow', 'rule_finding')),
    recorded_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((rule_id IS NULL) = (rule_revision IS NULL))
);
CREATE INDEX detection_signals_recorded_at_idx ON detection_signals (recorded_at DESC, signal_id);
CREATE INDEX detection_signals_rule_idx ON detection_signals (rule_id, recorded_at DESC) WHERE rule_id IS NOT NULL;

CREATE TABLE investigation_jobs (
    job_id bigserial PRIMARY KEY,
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'retryable', 'completed', 'sampled_out', 'failed')),
    risk_rank smallint NOT NULL CHECK (risk_rank BETWEEN 1 AND 4),
    anchor_ids jsonb NOT NULL CHECK (jsonb_typeof(anchor_ids) = 'array'),
    fingerprint text NOT NULL CHECK (length(fingerprint) = 64),
    sample_key text NOT NULL CHECK (length(sample_key) = 64),
    first_sequence bigint NOT NULL CHECK (first_sequence > 0),
    last_sequence bigint NOT NULL CHECK (last_sequence >= first_sequence),
    request jsonb NOT NULL,
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    available_at timestamptz NOT NULL,
    admitted_at timestamptz,
    lease_owner text,
    lease_expires_at timestamptz,
    skip_reason text CHECK (skip_reason IS NULL OR length(skip_reason) BETWEEN 1 AND 64),
    outcome jsonb,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    CHECK ((status = 'running') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK ((status IN ('completed', 'sampled_out', 'failed')) = (completed_at IS NOT NULL)),
    CHECK ((status = 'sampled_out') = (skip_reason IS NOT NULL))
);
CREATE INDEX investigation_jobs_ready_idx ON investigation_jobs (risk_rank DESC, available_at, job_id) WHERE status IN ('queued', 'retryable');
CREATE INDEX investigation_jobs_expired_lease_idx ON investigation_jobs (lease_expires_at, job_id) WHERE status = 'running';
CREATE INDEX investigation_jobs_batching_idx ON investigation_jobs USING gin (anchor_ids) WHERE status = 'queued' AND admitted_at IS NULL;
CREATE INDEX investigation_jobs_admitted_idx ON investigation_jobs (admitted_at) WHERE admitted_at IS NOT NULL;
CREATE INDEX investigation_jobs_fingerprint_idx ON investigation_jobs (fingerprint, admitted_at) WHERE admitted_at IS NOT NULL;
CREATE INDEX investigation_jobs_terminal_idx ON investigation_jobs (completed_at) WHERE completed_at IS NOT NULL;
