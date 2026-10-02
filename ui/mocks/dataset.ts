import type {
	Facet,
	FacetAssertion,
	Finding,
	IdentityClaim,
	IdentityScheme,
	ManifestContribution,
	Proposal,
	Relationship,
	RelationshipAssertion,
	Resource,
	ResourceAssertion,
	SecurityPort,
	Snapshot,
	TelemetryEvent
} from '@/api/types';

// A deterministic demo environment: a small shop on Kubernetes and Istio, observed by several
// discovery plugins, with the findings the reasoning pipeline would raise for it.

const CLUSTER = 'demo-cluster';
const NETWORK = 'demo-network';
const SEMANTICS_KEY = 'agentshield.io/security-semantics';
const BASE_TIME = Date.parse('2026-10-14T19:00:00.000Z');

const KUBERNETES: IdentityScheme = { group: 'kubernetes.io', version: 'v1', kind: 'Object' };
const DESTINATION: IdentityScheme = {
	group: 'agentshield.io',
	version: 'v1',
	kind: 'NetworkDestination'
};

export const minutesAgo = (minutes: number) => new Date(BASE_TIME - minutes * 60_000).toISOString();
export const minutesAfter = (minutes: number) =>
	new Date(BASE_TIME + minutes * 60_000).toISOString();

// A 128-bit hex digest (cyrb128). Identifiers only need to be stable, not secret.
function digest(input: string): string {
	let h1 = 1779033703;
	let h2 = 3144134277;
	let h3 = 1013904242;
	let h4 = 2773480762;
	for (let index = 0; index < input.length; index++) {
		const code = input.charCodeAt(index);
		h1 = h2 ^ Math.imul(h1 ^ code, 597399067);
		h2 = h3 ^ Math.imul(h2 ^ code, 2869860233);
		h3 = h4 ^ Math.imul(h3 ^ code, 951274213);
		h4 = h1 ^ Math.imul(h4 ^ code, 2716044179);
	}
	h1 = Math.imul(h3 ^ (h1 >>> 18), 597399067);
	h2 = Math.imul(h4 ^ (h2 >>> 22), 2869860233);
	h3 = Math.imul(h1 ^ (h3 >>> 17), 951274213);
	h4 = Math.imul(h2 ^ (h4 >>> 19), 2716044179);
	return [h1 ^ h2 ^ h3 ^ h4, h2 ^ h1, h3 ^ h1, h4 ^ h1]
		.map(value => (value >>> 0).toString(16).padStart(8, '0'))
		.join('');
}

export const digest256 = (input: string) => digest(input) + digest(`${input}#2`);

function uuid(...parts: string[]): string {
	const hex = digest(parts.join('\u0000'));
	return [
		hex.slice(0, 8),
		hex.slice(8, 12),
		hex.slice(12, 16),
		hex.slice(16, 20),
		hex.slice(20)
	].join('-');
}

export const graphSha = (revision: number) => digest256(`graph/${revision}`);

interface Source {
	pluginId: string;
	sourceId: string;
}

const kubernetes: Source = { pluginId: 'kubernetes', sourceId: CLUSTER };
const istio: Source = { pluginId: 'istio', sourceId: CLUSTER };
const cilium: Source = { pluginId: 'cilium', sourceId: CLUSTER };

export interface Entity {
	id: string;
	claim: IdentityClaim;
	kind: string;
	display: string;
	attributes: Record<string, string>;
	app: string;
	evidence: string;
}

function object(
	apiVersion: string,
	kind: string,
	namespace: string,
	name: string,
	app = ''
): Entity {
	const uid = uuid(CLUSTER, apiVersion, kind, namespace, name);
	const claim: IdentityClaim = {
		scheme: KUBERNETES,
		authorityId: CLUSTER,
		immutableKey: `${apiVersion}/${kind}/${uid}`.toLowerCase()
	};
	const attributes: Record<string, string> = {
		'kubernetes/api-version': apiVersion,
		'kubernetes/name': name,
		'kubernetes/spec-sha256': digest256(`spec/${uid}`)
	};
	if (namespace) attributes['kubernetes/namespace'] = namespace;
	if (app) attributes['kubernetes/label/app'] = app;
	const revision = 10000 + (Number.parseInt(digest(uid).slice(0, 5), 16) % 90000);
	return {
		id: uuid('resource', claim.immutableKey),
		claim,
		kind: `kubernetes/${kind.toLowerCase()}`,
		display: namespace ? `${namespace}/${name}` : name,
		attributes,
		app,
		evidence: `kubernetes:${claim.immutableKey}:${revision}:upsert`
	};
}

function destination(host: string): Entity {
	const claim: IdentityClaim = {
		scheme: DESTINATION,
		authorityId: NETWORK,
		immutableKey: `dns/${host}`
	};
	return {
		id: uuid('resource', claim.immutableKey),
		claim,
		kind: 'network/destination',
		display: host,
		attributes: { 'network/address': `dns/${host}`, 'istio/host': host },
		app: '',
		evidence: `istio:${digest(`destination/${host}`).slice(0, 16)}`
	};
}

interface SemanticsInput {
	class: 'exposure' | 'governance';
	domain: 'network-access' | 'transport-authentication';
	state: 'declared' | 'observed' | 'unknown';
	effect: string;
	scope: string;
	direction: string;
	coverage: 'complete' | 'partial' | 'unknown';
	protocols?: string[];
	ports?: SecurityPort[];
	config: string;
}

// Mirrors graph.WithSecuritySemantics: one JSON attribute with a fixed field order.
function semantics(
	input: SemanticsInput,
	extra: Record<string, string> = {}
): Record<string, string> {
	const value = {
		version: 'v1',
		class: input.class,
		domain: input.domain,
		state: input.state,
		effect: input.effect,
		scope: input.scope,
		direction: input.direction,
		coverage: input.coverage,
		protocols: input.protocols,
		ports: input.ports,
		configurationDigest: `sha256:${digest256(input.config)}`
	};
	return { ...extra, [SEMANTICS_KEY]: JSON.stringify(value) };
}

const tcp = (...ports: number[]): SecurityPort[] => ports.map(port => ({ protocol: 'TCP', port }));

function resourceOf(entity: Entity, source: Source, rule: string): Resource {
	const assertion: ResourceAssertion = {
		claim: entity.claim,
		kind: entity.kind,
		displayName: entity.display,
		attributes: entity.attributes,
		...source,
		ruleId: rule,
		evidenceIds: [entity.evidence]
	};
	return { id: entity.id, kind: entity.kind, identity: entity.claim, assertions: [assertion] };
}

function relationshipOf(
	source: Source,
	rule: string,
	subject: Entity,
	predicate: string,
	target: Entity,
	options: { qualifier?: string; properties?: Record<string, string>; evidence?: string[] } = {}
): Relationship {
	const qualifier = options.qualifier || undefined;
	const assertion: RelationshipAssertion = {
		subject: subject.claim,
		predicate,
		object: target.claim,
		qualifier,
		properties: options.properties,
		...source,
		ruleId: rule,
		evidenceIds: options.evidence ?? [subject.evidence, target.evidence]
	};
	return {
		id: uuid('relationship', subject.id, predicate, target.id, qualifier ?? ''),
		subjectId: subject.id,
		predicate,
		objectId: target.id,
		qualifier,
		assertions: [assertion]
	};
}

function facetOf(
	source: Source,
	rule: string,
	entity: Entity,
	kind: string,
	key: string,
	attributes: Record<string, string>,
	evidence: string[] = [entity.evidence]
): Facet {
	const assertion: FacetAssertion = {
		resource: entity.claim,
		kind,
		key,
		attributes,
		...source,
		ruleId: rule,
		evidenceIds: evidence
	};
	return {
		id: uuid('facet', entity.id, kind, key),
		resourceId: entity.id,
		kind,
		key,
		assertions: [assertion]
	};
}

const apps = [
	{ namespace: 'shop', name: 'frontend', account: 'frontend', replicas: 2, port: 80 },
	{ namespace: 'shop', name: 'cart', account: 'shop-backend', replicas: 2, port: 80 },
	{ namespace: 'shop', name: 'catalog', account: 'catalog', replicas: 1, port: 80 },
	{ namespace: 'shop', name: 'orders', account: 'shop-backend', replicas: 2, port: 80 },
	{ namespace: 'payments', name: 'ledger', account: 'ledger', replicas: 2, port: 9090 },
	{ namespace: 'payments', name: 'fraud', account: 'fraud', replicas: 1, port: 9090 },
	{
		namespace: 'istio-system',
		name: 'istio-ingressgateway',
		account: 'istio-ingressgateway',
		replicas: 1,
		port: 80
	}
] as const;

const key = (namespace: string, name: string) => `${namespace}/${name}`;

function buildWorld() {
	const namespaces = new Map<string, Entity>();
	for (const name of ['shop', 'payments', 'istio-system']) {
		namespaces.set(name, object('v1', 'Namespace', '', name));
	}
	const deployments = new Map<string, Entity>();
	const services = new Map<string, Entity>();
	const accounts = new Map<string, Entity>();
	const pods = new Map<string, Entity[]>();
	const objects: Entity[] = [...namespaces.values()];

	let podNumber = 0;
	for (const app of apps) {
		const id = key(app.namespace, app.name);
		const deployment = object('apps/v1', 'Deployment', app.namespace, app.name, app.name);
		const service = object('v1', 'Service', app.namespace, app.name, app.name);
		deployments.set(id, deployment);
		services.set(id, service);
		objects.push(deployment, service);
		const accountKey = key(app.namespace, app.account);
		if (!accounts.has(accountKey)) {
			const account = object('v1', 'ServiceAccount', app.namespace, app.account);
			accounts.set(accountKey, account);
			objects.push(account);
		}
		const replicas: Entity[] = [];
		for (let index = 0; index < app.replicas; index++) {
			const suffix = digest(`pod/${id}/${index}`);
			const pod = object(
				'v1',
				'Pod',
				app.namespace,
				`${app.name}-${suffix.slice(0, 9)}-${suffix.slice(9, 14)}`,
				app.name
			);
			pod.attributes['kubernetes/pod-ip'] =
				`10.8.${1 + Math.floor(podNumber / 200)}.${10 + (podNumber % 200)}`;
			podNumber++;
			replicas.push(pod);
			objects.push(pod);
		}
		pods.set(id, replicas);
	}

	const policies = new Map<string, Entity>();
	for (const [namespace, name] of [
		['shop', 'allow-frontend-ingress'],
		['payments', 'restrict-ledger']
	] as const) {
		const policy = object('networking.k8s.io/v1', 'NetworkPolicy', namespace, name);
		policies.set(key(namespace, name), policy);
		objects.push(policy);
	}
	const authentications = new Map<string, Entity>();
	for (const namespace of ['shop', 'payments']) {
		const authentication = object(
			'security.istio.io/v1',
			'PeerAuthentication',
			namespace,
			'default'
		);
		authentications.set(key(namespace, 'default'), authentication);
		objects.push(authentication);
	}
	const gateway = object('gateway.networking.k8s.io/v1', 'Gateway', 'shop', 'storefront');
	const route = object('gateway.networking.k8s.io/v1', 'HTTPRoute', 'shop', 'frontend');
	const ciliumPolicy = object('cilium.io/v2', 'CiliumNetworkPolicy', 'payments', 'fraud-ingress');
	const entries = new Map<string, Entity>();
	for (const [namespace, name] of [
		['payments', 'stripe-api'],
		['shop', 'partner-export']
	] as const) {
		const entry = object('networking.istio.io/v1', 'ServiceEntry', namespace, name);
		entries.set(key(namespace, name), entry);
		objects.push(entry);
	}
	objects.push(gateway, route, ciliumPolicy);

	return {
		namespaces,
		deployments,
		services,
		accounts,
		pods,
		objects,
		policies,
		authentications,
		gateway,
		route,
		ciliumPolicy,
		entries,
		stripe: destination('api.stripe.com'),
		partner: destination('export.partner-example.net')
	};
}

type World = ReturnType<typeof buildWorld>;

function kubernetesGraph(world: World) {
	const resources = world.objects.map(entity =>
		resourceOf(entity, kubernetes, 'kubernetes.object')
	);
	const relationships: Relationship[] = [];
	const facets: Facet[] = [];
	const rel = (
		rule: string,
		subject: Entity,
		predicate: string,
		target: Entity,
		qualifier = '',
		properties?: Record<string, string>
	) =>
		relationships.push(
			relationshipOf(kubernetes, rule, subject, predicate, target, { qualifier, properties })
		);

	for (const entity of world.objects) {
		const namespace = entity.attributes['kubernetes/namespace'];
		const container = namespace ? world.namespaces.get(namespace) : undefined;
		if (container) rel('kubernetes.namespace.contains', container, 'contains', entity);
	}

	for (const app of apps) {
		const id = key(app.namespace, app.name);
		const deployment = world.deployments.get(id) as Entity;
		const service = world.services.get(id) as Entity;
		const account = world.accounts.get(key(app.namespace, app.account)) as Entity;
		for (const pod of world.pods.get(id) ?? []) {
			rel('kubernetes.owner.instantiates', deployment, 'instantiates', pod);
			rel('kubernetes.pod.service-account', pod, 'uses-identity', account);
			rel('kubernetes.service.selector', service, 'exposes', pod, '', { basis: 'selector' });
		}
		const external = app.name === 'istio-ingressgateway';
		facets.push(
			facetOf(
				kubernetes,
				'kubernetes.service.exposure',
				service,
				'network-exposure',
				'service',
				semantics({
					class: 'exposure',
					domain: 'network-access',
					state: 'declared',
					effect: external ? 'external-addressable' : 'internal',
					scope: external ? 'external' : 'cluster',
					direction: 'ingress',
					coverage: 'complete',
					protocols: ['TCP'],
					ports: external ? tcp(80, 443) : tcp(app.port),
					config: `service/${id}`
				})
			)
		);
	}

	for (const [policyKey, appKey, port] of [
		['shop/allow-frontend-ingress', 'shop/frontend', 80],
		['payments/restrict-ledger', 'payments/ledger', 9090]
	] as const) {
		const policy = world.policies.get(policyKey) as Entity;
		const properties = semantics(
			{
				class: 'governance',
				domain: 'network-access',
				state: 'declared',
				effect: 'restrict',
				scope: 'workload',
				direction: 'ingress',
				coverage: 'complete',
				protocols: ['TCP'],
				ports: tcp(port),
				config: `networkpolicy/${policyKey}`
			},
			{
				directions: '["Ingress"]',
				'kubernetes/selector-basis': 'pod-labels',
				'kubernetes/membership-resolution': 'observed-label-match',
				'kubernetes/identity-assurance': 'none',
				'kubernetes/selector-empty': 'false'
			}
		);
		facets.push(
			facetOf(
				kubernetes,
				'kubernetes.networkpolicy.targeting',
				policy,
				'policy-targeting',
				'networkpolicy',
				properties
			)
		);
		for (const pod of world.pods.get(appKey) ?? []) {
			rel('kubernetes.networkpolicy.target', pod, 'governed-by', policy, '', properties);
		}
	}

	const { gateway, route } = world;
	const frontend = world.services.get('shop/frontend') as Entity;
	facets.push(
		facetOf(
			kubernetes,
			'kubernetes.gateway.exposure',
			gateway,
			'network-exposure',
			'gateway',
			semantics({
				class: 'exposure',
				domain: 'network-access',
				state: 'observed',
				effect: 'unknown',
				scope: 'gateway',
				direction: 'ingress',
				coverage: 'complete',
				protocols: ['HTTP', 'HTTPS'],
				ports: [
					{ protocol: 'HTTP', port: 80 },
					{ protocol: 'HTTPS', port: 443 }
				],
				config: 'gateway/shop/storefront'
			})
		),
		facetOf(
			kubernetes,
			'kubernetes.gateway.transport',
			gateway,
			'transport-posture',
			'gateway',
			semantics(
				{
					class: 'governance',
					domain: 'transport-authentication',
					state: 'declared',
					effect: 'permit',
					scope: 'gateway',
					direction: 'ingress',
					coverage: 'complete',
					config: 'gateway-transport/shop/storefront'
				},
				{
					'kubernetes/posture': 'mixed',
					'kubernetes/listener-modes': '["HTTP","TLS-Terminate"]',
					'kubernetes/listener-count': '2'
				}
			)
		),
		facetOf(
			kubernetes,
			'kubernetes.httproute.transport',
			route,
			'transport-posture',
			'parent-listeners',
			semantics(
				{
					class: 'governance',
					domain: 'transport-authentication',
					state: 'declared',
					effect: 'permit',
					scope: 'gateway',
					direction: 'ingress',
					coverage: 'partial',
					config: 'httproute-transport/shop/frontend'
				},
				{
					'kubernetes/posture': 'mixed',
					'kubernetes/parent-listener-modes': '["HTTP","TLS-Terminate"]',
					'kubernetes/resolved-listener-count': '2',
					'kubernetes/unresolved-parent-count': '1'
				}
			),
			[route.evidence, gateway.evidence]
		)
	);
	rel('kubernetes.gateway.parent', route, 'member-of', gateway, 'parent/storefront', {
		sectionName: ''
	});
	rel('kubernetes.httproute.backend', route, 'exposes', frontend, 'backend/frontend:80', {
		port: '80',
		weight: '1'
	});
	return { resources, relationships, facets };
}

function meshGraph(world: World) {
	const resources: Resource[] = [];
	const relationships: Relationship[] = [];
	const facets: Facet[] = [];

	for (const [target, entry] of [
		[world.stripe, world.entries.get('payments/stripe-api') as Entity],
		[world.partner, world.entries.get('shop/partner-export') as Entity]
	] as const) {
		resources.push(resourceOf(target, istio, 'istio.serviceentry-destination'));
		relationships.push(
			relationshipOf(istio, 'istio.serviceentry-exposes-host', entry, 'exposes', target, {
				qualifier: 'istio-serviceentry-host',
				properties: { semantic: 'istio-service-registry-declaration' },
				evidence: [target.evidence, entry.evidence]
			})
		);
	}

	for (const [policyKey, mode, effect, namespace] of [
		['shop/default', 'PERMISSIVE', 'permit', 'shop'],
		['payments/default', 'STRICT', 'require', 'payments']
	] as const) {
		const policy = world.authentications.get(policyKey) as Entity;
		const properties = semantics(
			{
				class: 'governance',
				domain: 'transport-authentication',
				state: 'declared',
				effect,
				scope: 'namespace',
				direction: 'ingress',
				coverage: 'complete',
				protocols: ['MTLS'],
				config: `peerauthentication/${policyKey}/${mode}`
			},
			{ 'declared-mode': mode, 'effective-mode-evaluated': 'false' }
		);
		for (const app of apps.filter(item => item.namespace === namespace)) {
			for (const pod of world.pods.get(key(app.namespace, app.name)) ?? []) {
				const evidence = [
					`istio:${digest(`peerauthentication/${pod.id}`).slice(0, 16)}`,
					pod.evidence,
					policy.evidence
				];
				facets.push(
					facetOf(
						istio,
						'istio.peer-authentication-facet',
						pod,
						'istio-mtls',
						`peerauthentication/${policy.display}`,
						{
							policy: policy.display,
							'declared-mode': mode,
							scope: 'namespace',
							'port-override-count': '0',
							'port-overrides-sha256': digest256('port-overrides/none'),
							'ambient-target': 'false',
							compatibility: 'supported',
							'effective-mode-evaluated': 'false'
						},
						evidence
					)
				);
				relationships.push(
					relationshipOf(istio, 'istio.peer-authentication-target', pod, 'governed-by', policy, {
						qualifier: 'istio-peer-authentication-namespace',
						properties,
						evidence
					})
				);
			}
		}
	}
	return { resources, relationships, facets };
}

const TELEMETRY_WINDOW = minutesAgo(5);

function telemetryGraph(world: World) {
	const service = (namespace: string, name: string) =>
		world.services.get(key(namespace, name)) as Entity;
	const edges: [Entity, Entity, string, string, 'complete' | 'partial', number, string][] = [
		[
			service('istio-system', 'istio-ingressgateway'),
			service('shop', 'frontend'),
			'communication',
			'GET /',
			'complete',
			51200,
			'http'
		],
		[
			service('shop', 'frontend'),
			service('shop', 'catalog'),
			'communication',
			'GET /products',
			'complete',
			18420,
			'http'
		],
		[
			service('shop', 'frontend'),
			service('shop', 'cart'),
			'communication',
			'POST /cart/items',
			'complete',
			9310,
			'http'
		],
		[
			service('shop', 'cart'),
			service('shop', 'orders'),
			'communication',
			'POST /orders',
			'complete',
			2750,
			'http'
		],
		[
			service('shop', 'orders'),
			service('shop', 'cart'),
			'communication',
			'GET /cart',
			'complete',
			2710,
			'http'
		],
		[
			service('shop', 'orders'),
			service('payments', 'ledger'),
			'communication',
			'POST /ledger/entries',
			'complete',
			2688,
			'http'
		],
		[
			service('payments', 'ledger'),
			service('payments', 'fraud'),
			'communication',
			'POST /score',
			'complete',
			2688,
			'http'
		],
		[
			service('payments', 'ledger'),
			world.stripe,
			'communication',
			'POST /v1/charges',
			'partial',
			2401,
			'https'
		],
		[
			service('shop', 'orders'),
			world.partner,
			'active-probe',
			'PUT /export',
			'partial',
			37,
			'https'
		]
	];
	const relationships: Relationship[] = [];
	const telemetry: TelemetryEvent[] = [];
	for (const [from, to, kind, operation, coverage, count, protocol] of edges) {
		const series = `series:${digest(`series/${from.id}/${to.id}/${operation}`).slice(0, 24)}`;
		const evidence = [`istio:${digest(`telemetry/${series}`).slice(0, 16)}`];
		relationships.push(
			relationshipOf(istio, 'telemetry.communication-edge-lease', from, 'communicates-with', to, {
				qualifier: 'telemetry-observed',
				properties: {
					'telemetry/lease-expires-at': minutesAfter(30),
					'telemetry/provider-plugin-id': istio.pluginId,
					'telemetry/provider-source-id': istio.sourceId
				},
				evidence
			})
		);
		telemetry.push({
			id: uuid('telemetry', istio.pluginId, istio.sourceId, series),
			eventId: series,
			kind,
			subjectId: from.id,
			objectId: to.id,
			operation,
			outcome: 'allowed',
			coverage,
			count,
			properties: {
				'network.protocol.name': protocol,
				'telemetry/window-start': TELEMETRY_WINDOW,
				'telemetry/first-seen': minutesAgo(4.9),
				'telemetry/last-seen': minutesAgo(0.15),
				'telemetry/source-id': istio.sourceId,
				'telemetry/provider-plugin-id': istio.pluginId
			},
			...istio,
			ruleId: 'telemetry.time-window-rollup',
			evidenceIds: evidence
		});
	}
	return { relationships, telemetry };
}

function ciliumGraph(world: World) {
	const { ciliumPolicy } = world;
	const relationships: Relationship[] = [];
	const facets: Facet[] = [
		facetOf(cilium, 'cilium.policy.cni', ciliumPolicy, 'cilium-cni-policy', ciliumPolicy.display, {
			'cilium/cni-rule-count': '1',
			'cilium/scope': 'namespace'
		})
	];
	const properties = semantics({
		class: 'governance',
		domain: 'network-access',
		state: 'declared',
		effect: 'restrict',
		scope: 'workload',
		direction: 'ingress',
		coverage: 'partial',
		protocols: ['TCP'],
		ports: tcp(9090),
		config: 'ciliumnetworkpolicy/payments/fraud-ingress'
	});
	for (const pod of world.pods.get('payments/fraud') ?? []) {
		relationships.push(
			relationshipOf(cilium, 'cilium.policy.selects-pod', pod, 'governed-by', ciliumPolicy, {
				properties
			})
		);
	}
	let index = 0;
	for (const namespaceApp of apps.filter(item => item.namespace === 'payments')) {
		for (const pod of world.pods.get(key(namespaceApp.namespace, namespaceApp.name)) ?? []) {
			facets.push(
				facetOf(
					cilium,
					'cilium.endpoint.cni',
					pod,
					'cilium-cni',
					'endpoint',
					semantics(
						{
							class: 'governance',
							domain: 'network-access',
							state: 'observed',
							effect: 'restrict',
							scope: 'workload',
							direction: 'ingress',
							coverage: 'partial',
							config: `endpoint/${pod.id}`
						},
						{
							'cilium/endpoint-id': String(1200 + index * 37),
							'cilium/security-identity': String(30100 + index),
							'cilium/state': 'ready',
							'cilium/policy-enabled': 'ingress'
						}
					)
				)
			);
			index++;
		}
	}
	return { relationships, facets };
}

interface ProposalSpec {
	intent:
		| 'network.declare-ingress-isolation'
		| 'transport.require-mutual-tls'
		| 'gateway.prevent-route-delivery';
	target: Entity;
}

interface FindingSpec {
	key: string;
	category: string;
	severity: 'critical' | 'high' | 'medium' | 'low';
	// Agentic investigation findings carry model uncertainty; detection rule findings carry their rule.
	uncertainty?: 'high' | 'medium' | 'low';
	rule?: { id: string; revision: number };
	summary: string;
	affected: Entity[];
	proposals?: ProposalSpec[];
	older?: boolean;
}

function findingSpecs(world: World): FindingSpec[] {
	const service = (namespace: string, name: string) =>
		world.services.get(key(namespace, name)) as Entity;
	const deployment = (namespace: string, name: string) =>
		world.deployments.get(key(namespace, name)) as Entity;
	const pod = (namespace: string, name: string, index: number) =>
		(world.pods.get(key(namespace, name)) as Entity[])[index] as Entity;
	const account = (namespace: string, name: string) =>
		world.accounts.get(key(namespace, name)) as Entity;
	const policy = (id: string) => world.policies.get(id) as Entity;
	const isolate = (target: Entity): ProposalSpec => ({
		intent: 'network.declare-ingress-isolation',
		target
	});
	const mtls = (target: Entity): ProposalSpec => ({
		intent: 'transport.require-mutual-tls',
		target
	});
	const shopAuthentication = world.authentications.get('shop/default') as Entity;
	const ingress = service('istio-system', 'istio-ingressgateway');
	const shopPods = apps
		.filter(app => app.namespace === 'shop')
		.flatMap(app => world.pods.get(key(app.namespace, app.name)) ?? []);

	const specs: FindingSpec[] = [
		{
			key: 'gateway-mixed-listeners',
			category: 'new_exposure',
			severity: 'high',
			uncertainty: 'low',
			summary:
				'Gateway shop/storefront exposes shop/frontend publicly and its listeners accept both HTTP and HTTPS.',
			affected: [world.gateway, world.route, service('shop', 'frontend')],
			proposals: [{ intent: 'gateway.prevent-route-delivery', target: world.route }]
		},
		{
			key: 'ingress-gateway-loadbalancer',
			category: 'new_exposure',
			severity: 'medium',
			uncertainty: 'low',
			summary:
				'Service istio-system/istio-ingressgateway is externally addressable on TCP 80 and 443.',
			affected: [ingress]
		},
		{
			key: 'orders-to-ledger-boundary',
			category: 'boundary_crossing',
			severity: 'high',
			uncertainty: 'low',
			summary: 'shop/orders calls payments/ledger across the shop to payments namespace boundary.',
			affected: [service('shop', 'orders'), service('payments', 'ledger')]
		},
		{
			key: 'gateway-into-shop-boundary',
			category: 'boundary_crossing',
			severity: 'low',
			uncertainty: 'medium',
			summary: 'istio-system/istio-ingressgateway initiates connections into the shop namespace.',
			affected: [ingress, service('shop', 'frontend')]
		},
		{
			key: 'orders-partner-egress',
			category: 'boundary_crossing',
			severity: 'high',
			uncertainty: 'medium',
			summary:
				'shop/orders sent PUT /export to export.partner-example.net, an external destination first observed in this window.',
			affected: [
				service('shop', 'orders'),
				world.partner,
				world.entries.get('shop/partner-export') as Entity
			]
		},
		{
			key: 'ledger-stripe-egress',
			category: 'boundary_crossing',
			severity: 'low',
			uncertainty: 'low',
			summary:
				'payments/ledger sends POST /v1/charges to api.stripe.com, which ServiceEntry payments/stripe-api declares.',
			affected: [
				service('payments', 'ledger'),
				world.stripe,
				world.entries.get('payments/stripe-api') as Entity
			]
		},
		{
			key: 'ledger-fraud-calls',
			category: 'unknown_security_effect',
			severity: 'low',
			uncertainty: 'low',
			summary: 'payments/ledger calls payments/fraud for every ledger write.',
			affected: [service('payments', 'ledger'), service('payments', 'fraud')]
		},
		{
			key: 'frontend-fanout',
			category: 'loss_of_governance',
			severity: 'low',
			uncertainty: 'low',
			summary:
				'shop/frontend calls shop/catalog and shop/cart; neither target has an ingress policy.',
			affected: [service('shop', 'frontend'), service('shop', 'catalog'), service('shop', 'cart')]
		},
		{
			key: 'catalog-no-netpol',
			category: 'loss_of_governance',
			severity: 'high',
			uncertainty: 'low',
			summary:
				'Pods behind shop/catalog are not selected by any NetworkPolicy, so any workload in the cluster can reach them.',
			affected: [deployment('shop', 'catalog'), pod('shop', 'catalog', 0)],
			proposals: [isolate(pod('shop', 'catalog', 0))]
		},
		{
			key: 'cart-no-netpol',
			category: 'loss_of_governance',
			severity: 'high',
			uncertainty: 'low',
			summary:
				'Pods behind shop/cart have no ingress policy but accept calls from frontend and orders.',
			affected: [deployment('shop', 'cart'), pod('shop', 'cart', 0), pod('shop', 'cart', 1)],
			proposals: [isolate(pod('shop', 'cart', 0)), isolate(pod('shop', 'cart', 1))]
		},
		{
			key: 'orders-no-netpol',
			category: 'loss_of_governance',
			severity: 'medium',
			uncertainty: 'low',
			summary:
				'Pods behind shop/orders have no ingress policy, and payments traffic originates here.',
			affected: [deployment('shop', 'orders'), pod('shop', 'orders', 0), pod('shop', 'orders', 1)],
			proposals: [isolate(pod('shop', 'orders', 0)), isolate(pod('shop', 'orders', 1))]
		},
		{
			key: 'shop-permissive-mtls',
			category: 'loss_of_governance',
			severity: 'medium',
			uncertainty: 'medium',
			summary:
				'PeerAuthentication shop/default is PERMISSIVE, so shop workloads accept plaintext connections.',
			affected: [
				shopAuthentication,
				deployment('shop', 'frontend'),
				deployment('shop', 'cart'),
				deployment('shop', 'orders'),
				deployment('shop', 'catalog')
			],
			proposals: [
				mtls(pod('shop', 'frontend', 0)),
				mtls(pod('shop', 'cart', 0)),
				mtls(pod('shop', 'orders', 0))
			]
		},
		{
			key: 'fraud-cilium-partial',
			category: 'loss_of_governance',
			severity: 'low',
			uncertainty: 'high',
			summary:
				'CiliumNetworkPolicy payments/fraud-ingress has partial coverage and its source is degraded, so enforcement on payments/fraud cannot be confirmed.',
			affected: [world.ciliumPolicy, pod('payments', 'fraud', 0)],
			proposals: [isolate(pod('payments', 'fraud', 0))]
		},
		{
			key: 'frontend-egress-open',
			category: 'loss_of_governance',
			severity: 'low',
			uncertainty: 'medium',
			summary:
				'NetworkPolicy shop/allow-frontend-ingress restricts ingress only; frontend egress is unrestricted.',
			affected: [
				policy('shop/allow-frontend-ingress'),
				pod('shop', 'frontend', 0),
				pod('shop', 'frontend', 1)
			]
		},
		{
			key: 'ledger-policy-broad',
			category: 'loss_of_governance',
			severity: 'medium',
			uncertainty: 'low',
			summary:
				'NetworkPolicy payments/restrict-ledger admits TCP 9090 from a wider set of sources than the observed caller.',
			affected: [policy('payments/restrict-ledger'), service('payments', 'ledger')],
			proposals: [isolate(pod('payments', 'ledger', 0))]
		},
		{
			key: 'cart-orders-shared-identity',
			category: 'identity_reuse',
			severity: 'medium',
			uncertainty: 'low',
			summary:
				'shop/cart and shop/orders run as ServiceAccount shop-backend, so their workload identities are indistinguishable.',
			affected: [
				account('shop', 'shop-backend'),
				deployment('shop', 'cart'),
				deployment('shop', 'orders')
			]
		},
		{
			key: 'ledger-replica-identity',
			category: 'identity_reuse',
			severity: 'low',
			uncertainty: 'high',
			summary:
				'Both payments/ledger replicas use one ServiceAccount, so compromising one replica yields the shared identity.',
			affected: [
				account('payments', 'ledger'),
				pod('payments', 'ledger', 0),
				pod('payments', 'ledger', 1)
			]
		},
		{
			key: 'public-path-to-ledger',
			category: 'possible_lateral_path',
			severity: 'high',
			uncertainty: 'medium',
			summary:
				'A path exists from the public gateway through frontend, cart, and orders to payments/ledger; only the last hop is governed by a NetworkPolicy.',
			affected: [
				ingress,
				service('shop', 'frontend'),
				service('shop', 'cart'),
				service('shop', 'orders'),
				service('payments', 'ledger')
			]
		},
		{
			key: 'cart-orders-cycle',
			category: 'possible_lateral_path',
			severity: 'medium',
			uncertainty: 'high',
			summary:
				'shop/cart and shop/orders call each other, so compromising either one exposes the other.',
			affected: [service('shop', 'cart'), service('shop', 'orders')]
		},
		{
			key: 'fraud-reachable-from-payments',
			category: 'possible_lateral_path',
			severity: 'medium',
			uncertainty: 'medium',
			summary:
				'payments/fraud accepts connections from any workload in payments; strict mTLS is the only caller restriction.',
			affected: [
				service('payments', 'fraud'),
				world.authentications.get('payments/default') as Entity,
				pod('payments', 'fraud', 0)
			],
			proposals: [isolate(pod('payments', 'fraud', 0))]
		},
		{
			key: 'gateway-effect-unknown',
			category: 'unknown_security_effect',
			severity: 'low',
			uncertainty: 'high',
			summary:
				'Gateway shop/storefront reports an unknown listener exposure effect, and HTTPRoute shop/frontend has an unresolved parent.',
			affected: [world.gateway, world.route]
		},
		{
			key: 'stripe-egress-unknown',
			category: 'unknown_security_effect',
			severity: 'low',
			uncertainty: 'high',
			summary:
				'ServiceEntry payments/stripe-api resolves to an external host, and its egress controls could not be evaluated.',
			affected: [world.entries.get('payments/stripe-api') as Entity, world.stripe]
		}
	];
	for (const target of shopPods) {
		specs.push({
			key: `permissive-${target.display}`,
			category: 'loss_of_governance',
			severity: target.app === 'cart' || target.app === 'orders' ? 'medium' : 'low',
			uncertainty: 'low',
			summary: `Pod ${target.display} accepts plaintext connections under PeerAuthentication shop/default (PERMISSIVE).`,
			affected: [target, shopAuthentication],
			proposals: [mtls(target)]
		});
	}
	const orders = deployment('shop', 'orders');
	specs.push({
		key: 'orders-rule-match',
		category: 'detection_rule_match',
		severity: 'medium',
		rule: { id: `deployment/${orders.id}/rule-1`, revision: 1 },
		summary: `Detection rule deployment/${orders.id}/rule-1 (revision 1) matched 1 new input(s): workload_rule_match`,
		affected: [orders]
	});
	specs.push(
		{
			key: 'route-plain-http',
			category: 'new_exposure',
			severity: 'medium',
			uncertainty: 'low',
			summary: 'HTTPRoute shop/frontend was reachable over plain HTTP.',
			affected: [world.route, service('shop', 'frontend')],
			older: true
		},
		{
			key: 'ledger-no-netpol',
			category: 'loss_of_governance',
			severity: 'high',
			uncertainty: 'low',
			summary: 'Pods behind payments/ledger had no NetworkPolicy.',
			affected: [deployment('payments', 'ledger'), pod('payments', 'ledger', 0)],
			proposals: [isolate(pod('payments', 'ledger', 0))],
			older: true
		},
		{
			key: 'catalog-to-fraud',
			category: 'possible_lateral_path',
			severity: 'medium',
			uncertainty: 'medium',
			summary: 'shop/catalog contacted payments/fraud directly.',
			affected: [service('shop', 'catalog'), service('payments', 'fraud')],
			older: true
		},
		{
			key: 'ledger-sidecar-unknown',
			category: 'unknown_security_effect',
			severity: 'low',
			uncertainty: 'high',
			summary: 'Sidecar coverage for payments/ledger could not be determined.',
			affected: [pod('payments', 'ledger', 0), pod('payments', 'ledger', 1)],
			older: true
		},
		{
			key: 'catalog-ledger-path',
			category: 'possible_lateral_path',
			severity: 'medium',
			uncertainty: 'medium',
			summary: 'shop/catalog could reach payments/ledger because both lacked ingress policy.',
			affected: [service('shop', 'catalog'), service('payments', 'ledger')],
			older: true
		}
	);
	return specs;
}

function buildFindings(specs: readonly FindingSpec[]): Finding[] {
	const current = graphSha(1);
	const earlier = graphSha(0);
	let active = 0;
	let older = 0;
	return specs.map(spec => {
		const id = `finding:sha256:${digest256(`finding/${spec.key}`)}`;
		const analysisId = `analysis:sha256:${digest256(`analysis/${Math.floor((spec.older ? older : active) / 6)}`)}`;
		const signalId = `signal:sha256:${digest256(`signal/${spec.key}`)}`;
		const graphSha256 = spec.older ? earlier : current;
		const remediations: Proposal[] = (spec.proposals ?? []).map(proposal => ({
			id: `proposal:sha256:${digest256(`proposal/${spec.key}/${proposal.intent}/${proposal.target.id}`)}`,
			findingId: id,
			analysisId,
			graphSha256,
			intent: proposal.intent,
			target: {
				entityId: proposal.target.id,
				identity: proposal.target.claim,
				kind: proposal.target.kind
			},
			supportingIds: [proposal.target.evidence, signalId].sort(),
			evidenceIds: [proposal.target.evidence]
		}));
		const createdAt = spec.older
			? minutesAgo(30 * 60 + older++ * 37)
			: minutesAgo(5 + active++ * 43);
		const finding: Finding = {
			id,
			origin: spec.rule ? 'detection_rule' : 'agentic_investigation',
			analysisId,
			graphSha256,
			category: spec.category,
			severity: spec.severity,
			summary: spec.summary,
			signalIds: [signalId],
			affectedEntityIds: spec.affected.map(entity => entity.id).sort(),
			remediations,
			status: spec.older ? 'invalidated' : 'active',
			createdAt
		};
		if (spec.rule) {
			finding.detectionRuleId = spec.rule.id;
			finding.detectionRuleRevision = spec.rule.revision;
		} else {
			finding.modelUncertainty = spec.uncertainty;
		}
		if (spec.older) {
			finding.invalidatedAt = minutesAgo(3);
			finding.invalidatedBySequence = 5;
			finding.invalidatedGraphSha256 = current;
		}
		return finding;
	});
}

function buildContributions(): ManifestContribution[] {
	const contribution = (
		contributionId: number,
		source: Source,
		name: string,
		status: string,
		ready: boolean,
		sourceHealth: string,
		observedMinutesAgo: number
	): ManifestContribution => ({
		contributionId,
		...source,
		name,
		generation: 1792004660662 + contributionId,
		status,
		sourceObservedAt: minutesAgo(observedMinutesAgo),
		publishedAt: minutesAgo(observedMinutesAgo - 0.2),
		ready,
		sourceHealth
	});
	return [
		contribution(
			5,
			{ pluginId: 'agentgateway', sourceId: 'demo-edge' },
			'routes',
			'stale',
			false,
			'stale',
			47
		),
		contribution(4, cilium, 'policies', 'degraded', true, 'degraded', 4),
		contribution(2, istio, 'mesh', 'active', true, 'healthy', 0.5),
		contribution(3, istio, 'telemetry', 'active', true, 'healthy', 0.3),
		contribution(1, kubernetes, 'objects', 'active', true, 'healthy', 0.4)
	];
}

const byId = <T extends { id: string }>(left: T, right: T) =>
	left.id < right.id ? -1 : left.id > right.id ? 1 : 0;

function buildDataset() {
	const world = buildWorld();
	const base = kubernetesGraph(world);
	const mesh = meshGraph(world);
	const telemetry = telemetryGraph(world);
	const policies = ciliumGraph(world);

	// The frontend Service is also asserted by Istio, so it carries two assertions.
	const frontend = world.services.get('shop/frontend') as Entity;
	const registry: ResourceAssertion = {
		claim: frontend.claim,
		kind: frontend.kind,
		displayName: frontend.display,
		attributes: { 'istio/host': 'frontend.shop.svc.cluster.local', 'istio/namespace': 'shop' },
		...istio,
		ruleId: 'istio.service-registry',
		evidenceIds: [`istio:${digest('service-registry/frontend').slice(0, 16)}`]
	};
	const resources = [...base.resources, ...mesh.resources].map(resource =>
		resource.id === frontend.id
			? { ...resource, assertions: [...(resource.assertions ?? []), registry] }
			: resource
	);

	const snapshot: Snapshot = {
		resources: resources.sort(byId),
		facets: [...base.facets, ...mesh.facets, ...policies.facets].sort(byId),
		relationships: [
			...base.relationships,
			...mesh.relationships,
			...telemetry.relationships,
			...policies.relationships
		].sort(byId),
		telemetry: telemetry.telemetry.sort(byId)
	};
	const specs = findingSpecs(world);
	const findings = buildFindings(specs);
	const findingByKey = new Map(specs.map((spec, index) => [spec.key, findings[index] as Finding]));
	return { snapshot, findings, findingByKey, contributions: buildContributions(), world };
}

export type Dataset = ReturnType<typeof buildDataset>;

export const dataset: Dataset = buildDataset();

export function finding(key: string): Finding {
	const found = dataset.findingByKey.get(key);
	if (!found) throw new Error(`unknown demo finding ${key}`);
	return found;
}
