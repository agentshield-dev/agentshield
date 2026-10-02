// Go encodes nil slices as null, so slice fields are List<T>; read them through list().
export type List<T> = readonly T[] | null | undefined;

export interface IdentityScheme {
	group: string;
	version: string;
	kind: string;
}

export interface IdentityClaim {
	scheme: IdentityScheme;
	authorityId: string;
	immutableKey: string;
}

export interface AssertionBase {
	pluginId: string;
	sourceId: string;
	ruleId: string;
	evidenceIds: List<string>;
	attributes?: Readonly<Record<string, string>>;
	properties?: Readonly<Record<string, string>>;
}

export interface ResourceAssertion extends AssertionBase {
	claim: IdentityClaim;
	kind: string;
	displayName?: string;
}

export interface RelationshipAssertion extends AssertionBase {
	subject: IdentityClaim;
	predicate: string;
	object: IdentityClaim;
	qualifier?: string;
}

export interface FacetAssertion extends AssertionBase {
	resource: IdentityClaim;
	kind: string;
	key: string;
}

export interface Resource {
	id: string;
	kind: string;
	identity: IdentityClaim;
	assertions: List<ResourceAssertion>;
}

export interface Relationship {
	id: string;
	subjectId: string;
	predicate: string;
	objectId: string;
	qualifier?: string;
	resolutionStatus?: string;
	assertions: List<RelationshipAssertion>;
}

export interface Facet {
	id: string;
	resourceId: string;
	kind: string;
	key: string;
	resolutionStatus?: string;
	assertions: List<FacetAssertion>;
}

export interface TelemetryEvent {
	id: string;
	eventId: string;
	kind: string;
	subjectId: string;
	objectId: string;
	operation?: string;
	outcome?: string;
	coverage?: string;
	count: number;
	properties?: Readonly<Record<string, string>>;
	pluginId: string;
	sourceId: string;
	ruleId: string;
	evidenceIds: List<string>;
}

export interface Snapshot {
	resources: List<Resource>;
	facets: List<Facet>;
	relationships: List<Relationship>;
	telemetry: List<TelemetryEvent>;
}

export interface GraphRecord {
	generatedAt: string;
	sha256: string;
	snapshot: Snapshot;
}

export interface SecurityPort {
	protocol: string;
	port: number;
}

export interface SecuritySemantics {
	version: string;
	class: string;
	domain: string;
	state: string;
	effect: string;
	scope: string;
	direction: string;
	coverage: string;
	protocols?: List<string>;
	ports?: List<SecurityPort>;
	configurationDigest?: string;
}

export interface RemediationTarget {
	entityId: string;
	identity: IdentityClaim;
	kind: string;
}

export interface Proposal {
	id: string;
	findingId: string;
	analysisId: string;
	graphSha256: string;
	intent: string;
	target: RemediationTarget;
	supportingIds: List<string>;
	evidenceIds: List<string>;
}

export type FindingOrigin = 'agentic_investigation' | 'detection_rule';

export interface Finding {
	id: string;
	origin: FindingOrigin;
	analysisId: string;
	graphSha256: string;
	category: string;
	severity: string;
	modelUncertainty?: string;
	detectionRuleId?: string;
	detectionRuleRevision?: number;
	summary: string;
	signalIds: List<string>;
	affectedEntityIds: List<string>;
	remediations: List<Proposal>;
	status: string;
	createdAt: string;
	invalidatedAt?: string;
	invalidatedBySequence?: number;
	invalidatedGraphSha256?: string;
}

export interface FindingsResponse {
	findings: List<Finding>;
	nextCursor?: string;
	total: number;
}

export interface Candidate {
	providerId: string;
	sourceId: string;
	actionId: string;
	mode: string;
}

export interface CandidatesResponse {
	candidates: List<Candidate>;
}

export interface Plan {
	id: string;
	proposalId: string;
	providerId: string;
	sourceId: string;
	actionId: string;
	mode: 'executable' | 'advisory-only';
	graphSha256: string;
	desiredSha256: string;
	advisory?: string;
}

export interface ProviderState {
	key: string;
	current?: unknown;
	prepared?: unknown;
}

export interface Preparation {
	id: string;
	planId: string;
	providerId: string;
	sourceId: string;
	actionId: string;
	successful: boolean;
	providerState?: List<ProviderState>;
}

export interface PrepareResponse {
	plan: Plan;
	preparation?: Preparation;
}

export interface ApproveResponse {
	planId: string;
	verification?: { satisfied: boolean };
	// Set when the write succeeded but verification failed or was unsatisfied.
	verificationError?: string;
}

export interface ManifestContribution {
	contributionId: number;
	pluginId: string;
	sourceId: string;
	name: string;
	generation: number;
	status: string;
	sourceObservedAt: string;
	publishedAt: string;
	ready: boolean;
	sourceHealth: string;
}

export interface Manifest {
	id: string;
	createdAt: string;
	digest: string;
	contributions: List<ManifestContribution>;
}

export interface OverviewResponse {
	graphSha256: string;
	generatedAt: string;
	counts: {
		resources: number;
		relationships: number;
		facets: number;
		telemetry: number;
		exposureFacts: number;
	};
	manifest: Manifest;
	activeFindings: List<Finding>;
	activeFindingsHasMore: boolean;
}

export interface ResourcesResponse {
	resources: List<Resource>;
	nextCursor?: string;
}

export interface RelationshipsResponse {
	relationships: List<Relationship>;
	nextCursor?: string;
}

export interface ResourceDetailResponse {
	resource: Resource;
	relationships: List<Relationship>;
	facets: List<Facet>;
	findings: List<Finding>;
}

export interface RelationshipDetailResponse {
	relationship: Relationship;
	subject: Resource;
	object: Resource;
}

export interface ExposureFact {
	id: string;
	ownerType: string;
	ownerId: string;
	resourceId?: string;
	subjectId?: string;
	objectId?: string;
	semantics: SecuritySemantics;
	pluginId: string;
	sourceId: string;
	ruleId: string;
	evidenceIds: List<string>;
}

export interface ExposuresResponse {
	exposures: List<ExposureFact>;
	nextCursor?: string;
}

// Detection rules and Deployment rule drafts (pkg/api rules.go).

export interface DetectorRule {
	id: string;
	revision: number;
	inputVersion: string;
	pluginId: string;
	workloadResourceId?: string;
	type: string;
	kind: string;
	expression: string;
	risk: string;
	reasons: List<string>;
	windowSeconds: number;
}

// Approved drafts run active; unreviewed drafts run in shadow mode, where matches are only recorded.
export type RuleMode = 'active' | 'shadow';

export interface WorkloadRule {
	rule: DetectorRule;
	mode: RuleMode;
}

export interface RulesResponse {
	activation: { revision: number; rulesetId: string } | null;
	rules: List<DetectorRule>;
	workloadRules: List<WorkloadRule>;
}

export type RuleDraftStatus = 'queued' | 'running' | 'retryable' | 'completed' | 'failed';
export type RuleReviewStatus = 'pending' | 'approved' | 'rejected';

// One Deployment rule authoring job, for one Pod template revision.
export interface RuleDraft {
	id: number;
	resourceId: string;
	templateSha256?: string;
	status: RuleDraftStatus;
	attemptCount: number;
	lastError?: string;
	reviewStatus: RuleReviewStatus;
	reviewedBy?: string;
	reviewedAt?: string;
	createdAt: string;
	completedAt?: string;
	ruleCount: number;
	requestedBy?: string;
	requestedAt?: string;
	currentRevision: boolean;
}

export interface RuleDraftToolCall {
	name: string;
	arguments?: unknown;
	result?: unknown;
	error?: string;
}

export interface RuleProposal {
	rationale: string;
	rules: List<{ rule: DetectorRule; rationale: string }>;
	toolCalls?: List<RuleDraftToolCall>;
}

export interface RuleDraftsResponse {
	drafts: List<RuleDraft>;
}

export interface RuleDraftResponse {
	draft: RuleDraft;
	proposal: RuleProposal | null;
}
