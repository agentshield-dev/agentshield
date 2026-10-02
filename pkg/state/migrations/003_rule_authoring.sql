CREATE TABLE deployment_rule_jobs (
    job_id bigserial PRIMARY KEY,
    resource_id uuid NOT NULL,
    workload_context jsonb NOT NULL,
    context_sha256 text NOT NULL CHECK (length(context_sha256) = 64),
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'retryable', 'completed', 'failed')),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    available_at timestamptz NOT NULL DEFAULT now(),
    lease_owner text,
    lease_expires_at timestamptz,
    proposal jsonb,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    review_status text NOT NULL DEFAULT 'pending' CHECK (review_status IN ('pending', 'approved', 'rejected')),
    reviewed_by text CHECK (reviewed_by IS NULL OR length(reviewed_by) BETWEEN 1 AND 128),
    reviewed_at timestamptz,
    template_sha256 text NOT NULL DEFAULT '' CHECK (template_sha256 = '' OR template_sha256 ~ '^[0-9a-f]{64}$'),
    current_revision boolean NOT NULL DEFAULT false,
    requested_by text CHECK (requested_by IS NULL OR length(requested_by) BETWEEN 1 AND 128),
    requested_at timestamptz,
    CHECK ((status = 'running') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK ((status = 'completed') = (completed_at IS NOT NULL)),
    CONSTRAINT deployment_rule_jobs_review_consistent CHECK ((review_status = 'pending') = (reviewed_by IS NULL AND reviewed_at IS NULL)),
    CONSTRAINT deployment_rule_jobs_review_requires_proposal CHECK (review_status = 'pending' OR status = 'completed'),
    CONSTRAINT deployment_rule_jobs_request_consistent CHECK ((requested_by IS NULL) = (requested_at IS NULL))
);
CREATE UNIQUE INDEX deployment_rule_jobs_revision_idx ON deployment_rule_jobs (resource_id, template_sha256);
CREATE INDEX deployment_rule_jobs_ready_idx ON deployment_rule_jobs (available_at, job_id) WHERE status IN ('queued', 'retryable');
CREATE INDEX deployment_rule_jobs_expired_lease_idx ON deployment_rule_jobs (lease_expires_at, job_id) WHERE status = 'running';
CREATE INDEX deployment_rule_jobs_loadable_idx ON deployment_rule_jobs (resource_id) WHERE status = 'completed' AND review_status <> 'rejected';
