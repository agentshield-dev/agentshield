import type {
	Candidate,
	CandidatesResponse,
	ExposureFact,
	ExposuresResponse,
	Finding,
	FindingsResponse,
	GraphRecord,
	OverviewResponse,
	Plan,
	Preparation,
	PrepareResponse,
	Proposal,
	ProviderState,
	Relationship,
	RelationshipDetailResponse,
	RelationshipsResponse,
	Resource,
	ResourceDetailResponse,
	ResourcesResponse,
	RuleDraftResponse,
	RuleDraftsResponse,
	RulesResponse,
	Snapshot,
	WorkloadRule
} from '@/api/types';
import { label, list, securitySemantics } from '@/lib/model';
import { dataset, digest256, graphSha, minutesAfter } from './dataset';
import { authoredProposal, type RuleJob, seedRuleJobs } from './rules';

// An in-memory stand-in for the AgentShield HTTP API (pkg/api). It follows the real handlers'
// filtering, cursor paging, and error messages so the UI behaves as it does against the service.

export class ApiError extends Error {
	readonly status: number;

	constructor(status: number, action: string, message: string) {
		super(`${action}: ${message}`);
		this.status = status;
	}
}

export interface BackendConfig {
	// Added to every API response.
	latencyMs: number;
	// False models a service whose graph was never materialized: no graph and no findings.
	materialized: boolean;
	// False models a service started without discovery, which cannot execute remediations.
	remediations: boolean;
	// How long an approved remediation takes to show up as a graph change.
	settleMs: number;
	// False models a non-loopback service started without --rule-review-api: rule writes return 503.
	ruleReview: boolean;
	// How long a requested Deployment rule draft takes to be authored.
	authorMs: number;
}

const defaults: BackendConfig = {
	latencyMs: 0,
	materialized: true,
	remediations: true,
	settleMs: 2000,
	ruleReview: true,
	authorMs: 2000
};

export interface GraphEvent {
	sha256: string;
	generatedAt: string;
}

interface Session {
	findingId: string;
	proposal: Proposal;
	plan: Plan;
	preparation: Preparation;
	approved?: ApprovalResult;
}

interface ApprovalResult {
	planId: string;
	result: Record<string, unknown>;
	verification: { planId: string; satisfied: boolean } & Record<string, unknown>;
	verificationError?: string;
}

const providers: Record<string, Candidate[]> = {
	'network.declare-ingress-isolation': [
		{
			providerId: 'kubernetes',
			sourceId: 'demo-cluster',
			actionId: 'network-policy/v1',
			mode: 'executable'
		},
		{
			providerId: 'cilium',
			sourceId: 'demo-cluster',
			actionId: 'cilium-network-policy/v1',
			mode: 'executable'
		}
	],
	'transport.require-mutual-tls': [
		{
			providerId: 'istio',
			sourceId: 'demo-cluster',
			actionId: 'peer-authentication/v1',
			mode: 'executable'
		}
	],
	'gateway.prevent-route-delivery': [
		{
			providerId: 'gateway',
			sourceId: 'demo-edge',
			actionId: 'route-detach/v1',
			mode: 'advisory-only'
		}
	]
};

const encode = (text: string) =>
	btoa(text).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');

function decode(value: string, action: string, message: string): string {
	try {
		return atob(value.replaceAll('-', '+').replaceAll('_', '/'));
	} catch {
		throw new ApiError(400, action, message);
	}
}

function limitOf(params: URLSearchParams, action: string, fallback: number): number {
	const raw = params.get('limit');
	if (!raw) return fallback;
	const limit = Number(raw);
	if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
		throw new ApiError(400, action, 'limit must be between 1 and 100');
	}
	return limit;
}

// Pages an ID-ordered list; the cursor is the last ID of the previous page.
function paginate<T>(
	items: readonly T[],
	params: URLSearchParams,
	action: string,
	id: (item: T) => string
) {
	const limit = limitOf(params, action, 25);
	const cursor = params.get('cursor');
	let start = 0;
	if (cursor) {
		const after = decode(cursor, action, 'cursor is invalid');
		if (!after) throw new ApiError(400, action, 'cursor is invalid');
		const index = items.findIndex(item => id(item) > after);
		start = index < 0 ? items.length : index;
	}
	const end = Math.min(items.length, start + limit);
	const last = items[end - 1];
	return {
		page: items.slice(start, end),
		nextCursor: end < items.length && last !== undefined ? encode(id(last)) : undefined
	};
}

const namespaceOf = (resource: Resource) => {
	for (const assertion of list(resource.assertions)) {
		for (const name of ['namespace', 'kubernetes/namespace', 'istio/namespace']) {
			const value = assertion.attributes?.[name];
			if (value) return value;
		}
	}
	return '';
};

function searchText(resource: Resource): string {
	const parts = [
		resource.id,
		resource.kind,
		label(resource),
		namespaceOf(resource),
		resource.identity.authorityId,
		resource.identity.immutableKey
	];
	for (const assertion of list(resource.assertions)) {
		parts.push(assertion.pluginId, assertion.sourceId, assertion.ruleId);
		for (const [name, value] of Object.entries(assertion.attributes ?? {})) parts.push(name, value);
	}
	return parts.join(' ').toLowerCase();
}

function exposureFacts(snapshot: Snapshot): ExposureFact[] {
	const facts: ExposureFact[] = [];
	for (const relationship of list(snapshot.relationships)) {
		list(relationship.assertions).forEach((assertion, index) => {
			const decoded = securitySemantics(assertion);
			if (decoded?.class !== 'exposure') return;
			facts.push({
				id: `${relationship.id}:${index}`,
				ownerType: 'relationship',
				ownerId: relationship.id,
				subjectId: relationship.subjectId,
				objectId: relationship.objectId,
				semantics: decoded,
				pluginId: assertion.pluginId,
				sourceId: assertion.sourceId,
				ruleId: assertion.ruleId,
				evidenceIds: assertion.evidenceIds
			});
		});
	}
	for (const facet of list(snapshot.facets)) {
		list(facet.assertions).forEach((assertion, index) => {
			const decoded = securitySemantics(assertion);
			if (decoded?.class !== 'exposure') return;
			facts.push({
				id: `${facet.id}:${index}`,
				ownerType: 'facet',
				ownerId: facet.id,
				resourceId: facet.resourceId,
				semantics: decoded,
				pluginId: assertion.pluginId,
				sourceId: assertion.sourceId,
				ruleId: assertion.ruleId,
				evidenceIds: assertion.evidenceIds
			});
		});
	}
	return facts.sort((left, right) => (left.id < right.id ? -1 : left.id > right.id ? 1 : 0));
}

const newestFirst = (left: Finding, right: Finding) =>
	left.createdAt === right.createdAt
		? left.id < right.id
			? 1
			: -1
		: left.createdAt < right.createdAt
			? 1
			: -1;

export class FakeBackend {
	config: BackendConfig = { ...defaults };
	private revision = 1;
	private sequence = 5;
	private findings: Finding[] = [];
	private sessions = new Map<string, Session>();
	private listeners = new Set<(event: GraphEvent) => void>();
	private timers = new Set<ReturnType<typeof setTimeout>>();
	private ruleJobs: RuleJob[] = [];

	constructor() {
		this.reset();
	}

	// Restores the demo environment and default behavior; stories call this before each render.
	reset(): void {
		for (const timer of this.timers) clearTimeout(timer);
		this.timers.clear();
		this.listeners.clear();
		this.sessions.clear();
		this.config = { ...defaults };
		this.revision = 1;
		this.sequence = 5;
		this.findings = structuredClone(dataset.findings);
		this.ruleJobs = seedRuleJobs();
	}

	configure(change: Partial<BackendConfig>): void {
		this.config = { ...this.config, ...change };
	}

	replaceFindings(findings: readonly Finding[]): void {
		for (const timer of this.timers) clearTimeout(timer);
		this.timers.clear();
		this.sessions.clear();
		this.revision++;
		this.sequence++;
		this.findings = structuredClone(findings).map(item => ({
			...item,
			graphSha256: this.sha,
			remediations: list(item.remediations).map(proposal => ({
				...proposal,
				graphSha256: this.sha
			}))
		}));
		this.notify();
	}

	private get snapshot(): Snapshot {
		return dataset.snapshot;
	}

	private requireGraph(action: string): Snapshot {
		if (!this.config.materialized) throw new ApiError(503, action, 'graph is not materialized');
		return this.snapshot;
	}

	private get sha(): string {
		return graphSha(this.revision);
	}

	private get generatedAt(): string {
		return minutesAfter(this.revision);
	}

	// What a new stream subscriber learns first: undefined until a graph exists.
	currentEvent(): GraphEvent | undefined {
		return this.config.materialized
			? { sha256: this.sha, generatedAt: this.generatedAt }
			: undefined;
	}

	subscribe(listener: (event: GraphEvent) => void): () => void {
		this.listeners.add(listener);
		return () => this.listeners.delete(listener);
	}

	private notify(): void {
		const event = this.currentEvent();
		if (!event) return;
		for (const listener of this.listeners) {
			try {
				listener(event);
			} catch {
				this.listeners.delete(listener);
			}
		}
	}

	// Announces a new graph revision to every open event stream.
	publish(): void {
		this.revision++;
		this.notify();
	}

	// Records a new active finding and publishes the revision that produced it.
	raiseFinding(summary: string): Finding {
		const created: Finding = {
			id: `finding:sha256:${digest256(`raised/${this.revision}/${summary}`)}`,
			origin: 'agentic_investigation',
			analysisId: `analysis:sha256:${digest256(`raised-analysis/${this.revision}`)}`,
			graphSha256: graphSha(this.revision + 1),
			category: 'possible_lateral_path',
			severity: 'high',
			modelUncertainty: 'medium',
			summary,
			signalIds: [`signal:sha256:${digest256(`raised-signal/${this.revision}/${summary}`)}`],
			affectedEntityIds: [],
			remediations: [],
			status: 'active',
			createdAt: minutesAfter(this.revision)
		};
		this.findings.push(created);
		this.publish();
		return created;
	}

	graph(): GraphRecord {
		return {
			generatedAt: this.generatedAt,
			sha256: this.sha,
			snapshot: this.requireGraph('load graph')
		};
	}

	overview(): OverviewResponse {
		const snapshot = this.requireGraph('load graph overview');
		const active = this.findings.filter(item => item.status === 'active').sort(newestFirst);
		return {
			graphSha256: this.sha,
			generatedAt: this.generatedAt,
			counts: {
				resources: list(snapshot.resources).length,
				relationships: list(snapshot.relationships).length,
				facets: list(snapshot.facets).length,
				telemetry: list(snapshot.telemetry).length,
				exposureFacts: exposureFacts(snapshot).length
			},
			manifest: {
				id: `manifest-${this.revision}`,
				createdAt: this.generatedAt,
				digest: digest256(`manifest/${this.revision}`),
				contributions: dataset.contributions
			},
			activeFindings: active.slice(0, 5),
			activeFindingsHasMore: active.length > 5
		};
	}

	resources(params: URLSearchParams): ResourcesResponse {
		const snapshot = this.requireGraph('load resources');
		const query = (params.get('q') ?? '').trim().toLowerCase();
		const kind = (params.get('kind') ?? '').trim();
		const scope = (params.get('namespace') ?? '').trim();
		const items = list(snapshot.resources).filter(
			resource =>
				(!kind || resource.kind === kind) &&
				(!scope || namespaceOf(resource) === scope) &&
				(!query || searchText(resource).includes(query))
		);
		const { page, nextCursor } = paginate(items, params, 'query resources', item => item.id);
		return { resources: page, nextCursor };
	}

	resource(id: string): ResourceDetailResponse {
		const snapshot = this.requireGraph('load resource');
		const resource = list(snapshot.resources).find(item => item.id === id);
		if (!resource) throw new ApiError(404, 'load resource', 'resource not found');
		const related = this.findings
			.filter(item => list(item.affectedEntityIds).includes(id))
			.sort(newestFirst);
		return {
			resource,
			relationships: list(snapshot.relationships).filter(
				item => item.subjectId === id || item.objectId === id
			),
			facets: list(snapshot.facets).filter(item => item.resourceId === id),
			findings: related.slice(0, 100)
		};
	}

	relationships(params: URLSearchParams): RelationshipsResponse {
		const snapshot = this.requireGraph('load relationships');
		const query = (params.get('q') ?? '').trim().toLowerCase();
		const predicate = (params.get('predicate') ?? '').trim();
		const endpoint = (params.get('resourceId') ?? '').trim();
		const items = list(snapshot.relationships).filter(
			(item: Relationship) =>
				(!predicate || item.predicate === predicate) &&
				(!endpoint || item.subjectId === endpoint || item.objectId === endpoint) &&
				(!query ||
					`${item.id} ${item.predicate} ${item.subjectId} ${item.objectId} ${item.qualifier ?? ''}`
						.toLowerCase()
						.includes(query))
		);
		const { page, nextCursor } = paginate(items, params, 'query relationships', item => item.id);
		return { relationships: page, nextCursor };
	}

	relationship(id: string): RelationshipDetailResponse {
		const snapshot = this.requireGraph('load relationship');
		const relationship = list(snapshot.relationships).find(item => item.id === id);
		if (!relationship) throw new ApiError(404, 'load relationship', 'relationship not found');
		const subject = list(snapshot.resources).find(item => item.id === relationship.subjectId);
		const object = list(snapshot.resources).find(item => item.id === relationship.objectId);
		if (!subject || !object) {
			throw new ApiError(409, 'load relationship', 'relationship endpoint is unresolved');
		}
		return { relationship, subject, object };
	}

	exposures(params: URLSearchParams): ExposuresResponse {
		const action = 'query exposure facts';
		const state = (params.get('state') ?? '').trim();
		const coverage = (params.get('coverage') ?? '').trim();
		const resourceId = (params.get('resourceId') ?? '').trim();
		if (state && !['declared', 'observed', 'unknown'].includes(state)) {
			throw new ApiError(400, action, 'exposure state is invalid');
		}
		if (coverage && !['complete', 'partial', 'unknown'].includes(coverage)) {
			throw new ApiError(400, action, 'exposure coverage is invalid');
		}
		const facts = exposureFacts(this.requireGraph('load exposure facts')).filter(
			fact =>
				(!state || fact.semantics.state === state) &&
				(!coverage || fact.semantics.coverage === coverage) &&
				(!resourceId ||
					fact.resourceId === resourceId ||
					fact.subjectId === resourceId ||
					fact.objectId === resourceId)
		);
		const { page, nextCursor } = paginate(facts, params, action, item => item.id);
		return { exposures: page, nextCursor };
	}

	queryFindings(params: URLSearchParams): FindingsResponse {
		const action = 'query findings';
		const limit = limitOf(params, action, 50);
		const status = params.get('status') ?? '';
		if (status && status !== 'active' && status !== 'invalidated') {
			throw new ApiError(400, action, 'finding status is invalid');
		}
		const severity = params.get('severity') ?? '';
		const category = params.get('category') ?? '';
		const entity = params.get('affectedEntityId') ?? '';
		const matching = this.config.materialized
			? this.findings
					.filter(
						item =>
							(!status || item.status === status) &&
							(!severity || item.severity === severity) &&
							(!category || item.category === category) &&
							(!entity || list(item.affectedEntityIds).includes(entity))
					)
					.sort(newestFirst)
			: [];
		const cursor = params.get('cursor');
		let rest = matching;
		if (cursor) {
			const bad = () => new ApiError(400, action, 'finding cursor is invalid');
			let parsed: { createdAt?: string; id?: string };
			try {
				parsed = JSON.parse(decode(cursor, action, 'finding cursor is invalid'));
			} catch {
				throw bad();
			}
			const { createdAt, id } = parsed;
			if (!createdAt || !id) throw bad();
			rest = matching.filter(
				item => item.createdAt < createdAt || (item.createdAt === createdAt && item.id < id)
			);
		}
		const page = rest.slice(0, limit);
		const last = page[page.length - 1];
		return {
			findings: page,
			total: matching.length,
			nextCursor:
				rest.length > limit && last
					? encode(JSON.stringify({ createdAt: last.createdAt, id: last.id }))
					: undefined
		};
	}

	finding(id: string): Finding {
		const found = this.config.materialized ? this.findings.find(item => item.id === id) : undefined;
		if (!found) throw new ApiError(404, 'load finding', 'finding not found');
		return found;
	}

	private proposal(
		findingId: string,
		proposalId: string
	): { finding: Finding; proposal: Proposal } {
		const finding = this.finding(findingId);
		if (finding.status !== 'active') {
			throw new ApiError(409, 'load finding remediation', 'finding is no longer active');
		}
		const proposal = list(finding.remediations).find(item => item.id === proposalId);
		if (!proposal) {
			throw new ApiError(
				404,
				'load finding remediation',
				`proposal "${proposalId}" was not found on finding`
			);
		}
		return { finding, proposal };
	}

	private requireExecutor(action: string): void {
		if (!this.config.remediations)
			throw new ApiError(503, action, 'live remediation is unavailable');
	}

	candidates(findingId: string, proposalId: string): CandidatesResponse {
		const { proposal } = this.proposal(findingId, proposalId);
		this.requireExecutor('enumerate remediation actions');
		return { candidates: providers[proposal.intent] ?? [] };
	}

	prepare(findingId: string, proposalId: string, body: unknown): PrepareResponse {
		const { proposal } = this.proposal(findingId, proposalId);
		this.requireExecutor('prepare remediation');
		const selection = (typeof body === 'object' && body !== null ? body : {}) as Record<
			string,
			unknown
		>;
		const [providerId, sourceId, actionId] = ['providerId', 'sourceId', 'actionId'].map(name => {
			const value = selection[name];
			return typeof value === 'string' ? value.trim() : '';
		});
		if (!providerId || !sourceId || !actionId) {
			throw new ApiError(
				400,
				'prepare remediation',
				'providerId, sourceId, and actionId are required'
			);
		}
		const candidate = (providers[proposal.intent] ?? []).find(
			item =>
				item.providerId === providerId && item.sourceId === sourceId && item.actionId === actionId
		);
		if (!candidate) {
			throw new ApiError(
				409,
				'plan remediation',
				`action ${providerId}/${sourceId}/${actionId} is not registered for ${proposal.intent}`
			);
		}
		const identity = `${proposal.id}/${providerId}/${sourceId}/${actionId}`;
		const plan: Plan = {
			id: `plan:sha256:${digest256(`plan/${identity}`)}`,
			proposalId: proposal.id,
			providerId,
			sourceId,
			actionId,
			mode: candidate.mode === 'advisory-only' ? 'advisory-only' : 'executable',
			graphSha256: proposal.graphSha256,
			desiredSha256: digest256(`desired/${identity}`)
		};
		if (plan.mode === 'advisory-only') {
			return {
				plan: {
					...plan,
					advisory:
						'Review the route attachment and detach it through the owning gateway configuration.'
				}
			};
		}
		const preparation: Preparation = {
			id: `preparation:sha256:${digest256(`preparation/${identity}`)}`,
			planId: plan.id,
			providerId,
			sourceId,
			actionId,
			successful: true,
			providerState: this.desiredState(actionId, proposal)
		};
		this.sessions.set(plan.id, { findingId, proposal, plan, preparation });
		return { plan, preparation };
	}

	approve(findingId: string, proposalId: string, body: unknown): ApprovalResult {
		const { proposal } = this.proposal(findingId, proposalId);
		this.requireExecutor('approve remediation');
		const planId =
			typeof body === 'object' && body !== null && 'planId' in body ? String(body.planId) : '';
		const session = this.sessions.get(planId);
		if (!session || session.findingId !== findingId || session.proposal.id !== proposal.id) {
			throw new ApiError(409, 'approve remediation', 'matching prepared remediation was not found');
		}
		if (session.approved) return session.approved;
		const { plan, preparation } = session;
		const executed = `execution:sha256:${digest256(`execution/${plan.id}`)}`;
		session.approved = {
			planId: plan.id,
			result: {
				id: executed,
				planId: plan.id,
				proposalId: proposal.id,
				providerId: plan.providerId,
				sourceId: plan.sourceId,
				actionId: plan.actionId,
				preparationId: preparation.id,
				successful: true,
				providerState: preparation.providerState
			},
			verification: {
				planId: plan.id,
				providerId: plan.providerId,
				sourceId: plan.sourceId,
				actionId: plan.actionId,
				executionResultId: executed,
				satisfied: true
			}
		};
		// Discovery observes the new policy, so the graph changes and the finding stops applying.
		const timer = setTimeout(() => this.settle(findingId), this.config.settleMs);
		this.timers.add(timer);
		return session.approved;
	}

	private settle(findingId: string): void {
		const finding = this.findings.find(item => item.id === findingId);
		if (finding?.status !== 'active') return;
		this.revision++;
		this.sequence++;
		finding.status = 'invalidated';
		finding.invalidatedAt = this.generatedAt;
		finding.invalidatedBySequence = this.sequence;
		finding.invalidatedGraphSha256 = this.sha;
		this.notify();
	}

	private desiredState(actionId: string, proposal: Proposal): ProviderState[] {
		const target = list(this.snapshot.resources).find(item => item.id === proposal.target.entityId);
		const attributes = list(target?.assertions)[0]?.attributes ?? {};
		const namespace = attributes['kubernetes/namespace'] ?? 'default';
		const app = attributes['kubernetes/label/app'] ?? attributes['kubernetes/name'] ?? 'workload';
		const selector = { matchLabels: { app } };
		switch (actionId) {
			case 'network-policy/v1':
				return [
					{
						key: `networkpolicy/${namespace}/agentshield-isolate-${app}`,
						prepared: {
							apiVersion: 'networking.k8s.io/v1',
							kind: 'NetworkPolicy',
							metadata: { name: `agentshield-isolate-${app}`, namespace },
							spec: { podSelector: selector, policyTypes: ['Ingress'], ingress: [] }
						}
					}
				];
			case 'cilium-network-policy/v1':
				return [
					{
						key: `ciliumnetworkpolicy/${namespace}/agentshield-isolate-${app}`,
						prepared: {
							apiVersion: 'cilium.io/v2',
							kind: 'CiliumNetworkPolicy',
							metadata: { name: `agentshield-isolate-${app}`, namespace },
							spec: {
								endpointSelector: selector,
								ingress: [
									{
										fromEndpoints: [
											{ matchLabels: { 'k8s:io.kubernetes.pod.namespace': namespace } }
										]
									}
								]
							}
						}
					}
				];
			default:
				return [
					{
						key: `peerauthentication/${namespace}/agentshield-${app}`,
						current: { mode: 'PERMISSIVE' },
						prepared: {
							apiVersion: 'security.istio.io/v1',
							kind: 'PeerAuthentication',
							metadata: { name: `agentshield-${app}`, namespace },
							spec: { selector, mtls: { mode: 'STRICT' } }
						}
					}
				];
		}
	}

	// Detection rules (pkg/api rules.go). Approved drafts load as active rules; the current
	// revision's unreviewed draft loads in shadow mode; rejected drafts are not loaded.
	rules(): RulesResponse {
		const workloadRules: WorkloadRule[] = [];
		const resources = new Set(this.ruleJobs.map(job => job.draft.resourceId));
		for (const resourceId of resources) {
			const jobs = this.ruleJobs.filter(
				job => job.draft.resourceId === resourceId && job.draft.status === 'completed'
			);
			const approved = jobs
				.filter(job => job.draft.reviewStatus === 'approved')
				.sort(
					(left, right) =>
						Number(right.draft.currentRevision) - Number(left.draft.currentRevision) ||
						right.draft.id - left.draft.id
				)[0];
			const shadow = jobs.find(
				job => job.draft.currentRevision && job.draft.reviewStatus === 'pending'
			);
			for (const [job, mode] of [
				[approved, 'active'],
				[shadow, 'shadow']
			] as const) {
				for (const item of list(job?.proposal?.rules))
					workloadRules.push({ rule: item.rule, mode });
			}
		}
		return { activation: { revision: 1, rulesetId: 'builtin/v1' }, rules: [], workloadRules };
	}

	ruleDrafts(): RuleDraftsResponse {
		return {
			drafts: [...this.ruleJobs].map(job => job.draft).sort((left, right) => right.id - left.id)
		};
	}

	private ruleJob(id: string, action: string): RuleJob {
		const job = this.ruleJobs.find(item => String(item.draft.id) === id);
		if (!job) throw new ApiError(404, action, 'Deployment rule authoring job not found');
		return job;
	}

	ruleDraft(id: string): RuleDraftResponse {
		const job = this.ruleJob(id, 'load rule draft');
		return { draft: job.draft, proposal: job.draft.status === 'completed' ? job.proposal : null };
	}

	private requireRuleReview(action: string): void {
		if (!this.config.ruleReview) {
			throw new ApiError(
				503,
				action,
				'rule review is disabled on a non-loopback listener; see --rule-review-api'
			);
		}
	}

	reviewRuleDraft(id: string, body: unknown): RuleDraftResponse {
		const job = this.ruleJob(id, 'review rule draft');
		this.requireRuleReview('review rule draft');
		const decision =
			typeof body === 'object' && body !== null && 'decision' in body ? body.decision : undefined;
		if (decision !== 'approved' && decision !== 'rejected') {
			throw new ApiError(400, 'review rule draft', 'decision must be approved or rejected');
		}
		if (job.draft.status !== 'completed') {
			throw new ApiError(
				409,
				'review rule draft',
				'Deployment rule job is not a completed proposal'
			);
		}
		job.draft = {
			...job.draft,
			reviewStatus: decision,
			reviewedBy: 'api/web-ui',
			reviewedAt: new Date().toISOString()
		};
		return this.ruleDraft(id);
	}

	requestRuleDraft(resourceId: string): RuleDraftResponse {
		this.requireRuleReview('regenerate rules');
		const job = this.ruleJobs.find(
			item => item.draft.resourceId === resourceId && item.draft.currentRevision
		);
		if (!job) {
			throw new ApiError(
				404,
				'regenerate rules',
				"Deployment rule authoring job not found for the Deployment's current revision"
			);
		}
		// Like the service, a queued or retrying draft is woken; only a running one conflicts.
		if (job.draft.status === 'running') {
			throw new ApiError(
				409,
				'regenerate rules',
				'Deployment rule authoring is already in progress'
			);
		}
		const requestedAt = new Date().toISOString();
		job.draft = {
			...job.draft,
			status: 'queued',
			attemptCount: 0,
			ruleCount: 0,
			reviewStatus: 'pending',
			reviewedBy: undefined,
			reviewedAt: undefined,
			completedAt: undefined,
			lastError: undefined,
			requestedBy: 'api/web-ui',
			requestedAt
		};
		job.proposal = null;
		const id = job.draft.id;
		const start = setTimeout(() => {
			this.timers.delete(start);
			job.draft = { ...job.draft, status: 'running', attemptCount: 1 };
		}, this.config.authorMs / 2);
		const finish = setTimeout(() => {
			this.timers.delete(finish);
			const proposal = authoredProposal(resourceId, id, 3);
			job.proposal = proposal;
			job.draft = {
				...job.draft,
				status: 'completed',
				completedAt: new Date().toISOString(),
				ruleCount: list(proposal.rules).length
			};
		}, this.config.authorMs);
		this.timers.add(start);
		this.timers.add(finish);
		return { draft: job.draft, proposal: null };
	}
}
