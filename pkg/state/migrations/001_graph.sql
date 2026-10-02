CREATE TABLE native_events (
    event_id text PRIMARY KEY,
    plugin_id text NOT NULL,
    source_id text NOT NULL,
    collection text NOT NULL,
    object_key text NOT NULL,
    source_revision text NOT NULL DEFAULT '',
    operation text NOT NULL,
    observed_at timestamptz NOT NULL,
    content_sha256 bytea NOT NULL CHECK (octet_length(content_sha256) = 32)
);
CREATE INDEX native_events_source_idx ON native_events (plugin_id, source_id, collection, observed_at DESC);

CREATE TABLE resource_identities (
    resource_id uuid PRIMARY KEY,
    scheme_group text NOT NULL,
    scheme_version text NOT NULL,
    scheme_kind text NOT NULL,
    authority_id text NOT NULL,
    immutable_key text NOT NULL,
    UNIQUE (scheme_group, scheme_version, scheme_kind, authority_id, immutable_key)
);

CREATE TABLE contributions (
    contribution_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    plugin_id text NOT NULL,
    source_id text NOT NULL,
    contribution_name text NOT NULL,
    UNIQUE (plugin_id, source_id, contribution_name)
);

CREATE TABLE contribution_versions (
    contribution_version_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    contribution_id bigint NOT NULL REFERENCES contributions(contribution_id),
    generation bigint NOT NULL CHECK (generation > 0),
    input_digest bytea NOT NULL CHECK (octet_length(input_digest) = 32),
    source_observed_at timestamptz NOT NULL,
    published_at timestamptz NOT NULL,
    ready boolean NOT NULL,
    source_health text NOT NULL CHECK (source_health IN ('healthy', 'degraded', 'stale', 'unknown')),
    status text NOT NULL CHECK (status IN ('active', 'degraded', 'stale', 'retired')),
    UNIQUE (contribution_id, generation)
);

CREATE TABLE contribution_heads (
    contribution_id bigint PRIMARY KEY REFERENCES contributions(contribution_id),
    active_contribution_version_id bigint NOT NULL REFERENCES contribution_versions(contribution_version_id),
    generation bigint NOT NULL CHECK (generation > 0),
    status text NOT NULL CHECK (status IN ('active', 'degraded', 'stale', 'retired')),
    updated_at timestamptz NOT NULL
);

CREATE TABLE resource_assertions (
    assertion_id text PRIMARY KEY CHECK (length(assertion_id) = 64),
    content_digest bytea NOT NULL UNIQUE CHECK (octet_length(content_digest) = 32),
    resource_id uuid NOT NULL REFERENCES resource_identities(resource_id),
    kind text NOT NULL,
    display_name text NOT NULL DEFAULT '',
    attributes jsonb NOT NULL DEFAULT '{}'::jsonb,
    plugin_id text NOT NULL,
    source_id text NOT NULL,
    rule_id text NOT NULL,
    evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX resource_assertions_resource_idx ON resource_assertions (resource_id);

CREATE TABLE facet_assertions (
    assertion_id text PRIMARY KEY CHECK (length(assertion_id) = 64),
    content_digest bytea NOT NULL UNIQUE CHECK (octet_length(content_digest) = 32),
    facet_id uuid NOT NULL,
    resource_id uuid NOT NULL REFERENCES resource_identities(resource_id),
    kind text NOT NULL,
    facet_key text NOT NULL,
    attributes jsonb NOT NULL DEFAULT '{}'::jsonb,
    plugin_id text NOT NULL,
    source_id text NOT NULL,
    rule_id text NOT NULL,
    evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX facet_assertions_facet_idx ON facet_assertions (facet_id);
CREATE INDEX facet_assertions_resource_idx ON facet_assertions (resource_id);

CREATE TABLE relationship_assertions (
    assertion_id text PRIMARY KEY CHECK (length(assertion_id) = 64),
    content_digest bytea NOT NULL UNIQUE CHECK (octet_length(content_digest) = 32),
    relationship_id uuid NOT NULL,
    subject_id uuid NOT NULL REFERENCES resource_identities(resource_id),
    object_id uuid NOT NULL REFERENCES resource_identities(resource_id),
    predicate text NOT NULL CHECK (predicate IN ('contains', 'instantiates', 'member-of', 'uses-identity', 'exposes', 'governed-by', 'communicates-with', 'runs-on', 'backed-by', 'executes')),
    qualifier text NOT NULL DEFAULT '',
    properties jsonb NOT NULL DEFAULT '{}'::jsonb,
    plugin_id text NOT NULL,
    source_id text NOT NULL,
    rule_id text NOT NULL,
    evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX relationship_assertions_relationship_idx ON relationship_assertions (relationship_id);
CREATE INDEX relationship_assertions_endpoints_idx ON relationship_assertions (subject_id, object_id);
CREATE INDEX relationship_assertions_predicate_idx ON relationship_assertions (predicate);

CREATE TABLE telemetry_assertions (
    assertion_id text PRIMARY KEY CHECK (length(assertion_id) = 64),
    content_digest bytea NOT NULL UNIQUE CHECK (octet_length(content_digest) = 32),
    telemetry_id uuid NOT NULL,
    event_id text NOT NULL,
    kind text NOT NULL,
    subject_id uuid NOT NULL REFERENCES resource_identities(resource_id),
    object_id uuid NOT NULL REFERENCES resource_identities(resource_id),
    operation text NOT NULL DEFAULT '',
    outcome text NOT NULL DEFAULT '',
    coverage text NOT NULL DEFAULT '',
    event_count bigint NOT NULL CHECK (event_count > 0),
    properties jsonb NOT NULL DEFAULT '{}'::jsonb,
    plugin_id text NOT NULL,
    source_id text NOT NULL,
    rule_id text NOT NULL,
    evidence_ids jsonb NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX telemetry_assertions_event_idx ON telemetry_assertions (telemetry_id);
CREATE INDEX telemetry_assertions_endpoints_idx ON telemetry_assertions (subject_id, object_id);

CREATE TABLE contribution_current_assertions (
    contribution_id bigint NOT NULL REFERENCES contributions(contribution_id) ON DELETE CASCADE,
    assertion_type text NOT NULL CHECK (assertion_type IN ('resource', 'facet', 'relationship', 'telemetry')),
    assertion_id text NOT NULL,
    PRIMARY KEY (contribution_id, assertion_type, assertion_id)
);
CREATE INDEX contribution_current_assertions_lookup_idx ON contribution_current_assertions (assertion_type, assertion_id);

CREATE TABLE current_resources (
    resource_id uuid PRIMARY KEY REFERENCES resource_identities(resource_id),
    kind text NOT NULL,
    display_name text NOT NULL DEFAULT '',
    attributes jsonb NOT NULL DEFAULT '{}'::jsonb,
    assertions jsonb NOT NULL DEFAULT '[]'::jsonb,
    updated_at timestamptz NOT NULL
);

CREATE TABLE current_facets (
    facet_id uuid PRIMARY KEY,
    resource_id uuid NOT NULL REFERENCES resource_identities(resource_id),
    kind text NOT NULL,
    facet_key text NOT NULL,
    attributes jsonb NOT NULL DEFAULT '{}'::jsonb,
    assertions jsonb NOT NULL DEFAULT '[]'::jsonb,
    resolution_status text NOT NULL CHECK (resolution_status IN ('resolved', 'unresolved')),
    updated_at timestamptz NOT NULL
);

CREATE TABLE current_relationships (
    relationship_id uuid PRIMARY KEY,
    subject_id uuid NOT NULL REFERENCES resource_identities(resource_id),
    object_id uuid NOT NULL REFERENCES resource_identities(resource_id),
    predicate text NOT NULL CHECK (predicate IN ('contains', 'instantiates', 'member-of', 'uses-identity', 'exposes', 'governed-by', 'communicates-with', 'runs-on', 'backed-by', 'executes')),
    qualifier text NOT NULL DEFAULT '',
    properties jsonb NOT NULL DEFAULT '{}'::jsonb,
    assertions jsonb NOT NULL DEFAULT '[]'::jsonb,
    resolution_status text NOT NULL CHECK (resolution_status IN ('resolved', 'unresolved')),
    updated_at timestamptz NOT NULL
);
CREATE INDEX current_relationships_subject_idx ON current_relationships (subject_id, predicate);
CREATE INDEX current_relationships_object_idx ON current_relationships (object_id, predicate);

CREATE TABLE unresolved_relationships (
    relationship_id uuid PRIMARY KEY REFERENCES current_relationships(relationship_id) ON DELETE CASCADE,
    first_seen_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE TABLE assertion_conflicts (
    resource_id uuid PRIMARY KEY REFERENCES resource_identities(resource_id),
    kinds jsonb NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE graph_manifests (
    manifest_id uuid PRIMARY KEY,
    created_at timestamptz NOT NULL,
    digest bytea NOT NULL UNIQUE CHECK (octet_length(digest) = 32),
    parent_id uuid REFERENCES graph_manifests(manifest_id),
    contribution_count integer NOT NULL,
    unresolved_relationship_count integer NOT NULL,
    conflict_count integer NOT NULL
);

CREATE TABLE graph_manifest_contributions (
    manifest_id uuid NOT NULL REFERENCES graph_manifests(manifest_id) ON DELETE CASCADE,
    contribution_id bigint NOT NULL REFERENCES contributions(contribution_id),
    contribution_version_id bigint NOT NULL REFERENCES contribution_versions(contribution_version_id),
    PRIMARY KEY (manifest_id, contribution_id)
);

CREATE TABLE graph_change_outbox (
    sequence bigint PRIMARY KEY,
    contribution_version_id bigint NOT NULL UNIQUE REFERENCES contribution_versions(contribution_version_id) ON DELETE CASCADE,
    payload jsonb NOT NULL
);

CREATE TABLE graph_change_sequence (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    value bigint NOT NULL CHECK (value >= 0)
);
INSERT INTO graph_change_sequence (value) VALUES (0);

CREATE TABLE reasoning_cursors (
    consumer_id text PRIMARY KEY CHECK (consumer_id <> ''),
    through_sequence bigint NOT NULL CHECK (through_sequence >= 0),
    graph_sha256 text NOT NULL CHECK (graph_sha256 <> ''),
    updated_at timestamptz NOT NULL
);

CREATE TABLE graph_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    digest bytea CHECK (digest IS NULL OR octet_length(digest) = 32),
    generated_at timestamptz
);
INSERT INTO graph_state (singleton, revision) VALUES (true, 0);
