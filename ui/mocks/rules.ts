import type { DetectorRule, RuleDraft, RuleProposal } from '@/api/types';
import { list } from '@/lib/model';
import { dataset, digest256, minutesAgo } from './dataset';

// Resource rule authoring jobs for the demo environment, shaped like pkg/api rules.go.

export interface RuleJob {
	draft: RuleDraft;
	proposal: RuleProposal | null;
}

interface Template {
	type: string;
	kind: string;
	expression: string;
	rationale: string;
}

const templates: readonly Template[] = [
	{
		type: 'relationship',
		kind: 'executes',
		expression: "process_class == 'shell'",
		rationale:
			'Interactive shell activity falls outside this workload’s observed baseline. kubectl exec debugging can also produce it.'
	},
	{
		type: 'relationship',
		kind: 'communicates-with',
		expression: "destination_ip_class == 'public' && destination_role == ''",
		rationale:
			'Public egress falls outside this workload’s observed baseline. New SaaS integrations can also produce it.'
	},
	{
		type: 'telemetry',
		kind: 'network-flow',
		expression: "operation == 'egress' && destination_role == 'control-plane-api'",
		rationale:
			'Kubernetes API access falls outside this workload’s observed baseline. Client libraries that read their own configuration can also produce it.'
	},
	{
		type: 'telemetry',
		kind: 'network-flow',
		expression: "outcome == 'dropped'",
		rationale:
			'Dropped flows from this workload may indicate probing or a broken dependency. Policy rollouts may also produce them.'
	}
];

export const deploymentIds = (): string[] =>
	list(dataset.snapshot.resources)
		.filter(resource => resource.kind === 'kubernetes/deployment')
		.map(resource => resource.id)
		.sort();

const templateFor = (resourceId: string) => digest256(`template/${resourceId}`);

// Drafts lead with the no-shell rule, then rotate through the others.
export function authoredProposal(resourceId: string, seed: number, count: number): RuleProposal {
	const others = templates.slice(1);
	const picked = [
		templates[0],
		...others.map((_, index) => others[(seed + index) % others.length])
	].slice(0, count);
	const rules = picked.map((template, index) => {
		const rule: DetectorRule = {
			id: `deployment/${resourceId}/template-${templateFor(resourceId).slice(0, 12)}/rule-${index + 1}`,
			revision: 1,
			inputVersion: 'v1',
			pluginId: '*',
			scopeResourceId: resourceId,
			type: template.type,
			kind: template.kind,
			expression: template.expression,
			risk: 'medium',
			reasons: ['resource_rule_match'],
			windowSeconds: 300
		};
		return { rule, rationale: template.rationale };
	});
	return {
		rationale:
			'The workload’s baseline shows a narrow runtime profile; each rule targets one deviation from it.',
		rules,
		context: {
			automountServiceAccountToken: false,
			podSecurityContext: { runAsNonRoot: true, seccompProfile: 'RuntimeDefault' },
			containers: [
				{
					type: 'container',
					name: 'api',
					image: 'registry.example/payments:v4',
					allowPrivilegeEscalation: false,
					readOnlyRootFilesystem: true,
					capabilitiesDropped: ['ALL'],
					ports: [{ name: 'https', containerPort: 8443, protocol: 'TCP' }]
				}
			],
			hostPathCount: 1,
			hostPathTypes: ['Socket'],
			references: [{ kind: 'Secret', usage: 'volume', count: 1 }]
		},
		toolCalls: [
			...rules.map(item => ({
				name: 'add_rule',
				arguments: {
					selector: `${item.rule.type}:${item.rule.kind}`,
					expression: item.rule.expression,
					rationale: item.rationale
				},
				result: { added: true }
			})),
			{ name: 'finish', arguments: { rationale: 'Rules recorded.' }, result: { finished: true } }
		]
	};
}

function job(
	id: number,
	resourceId: string,
	minutes: number,
	change: Partial<RuleDraft>
): RuleDraft {
	return {
		id,
		resourceId,
		contextSha256: templateFor(resourceId),
		status: 'queued',
		attemptCount: 0,
		reviewStatus: 'pending',
		createdAt: minutesAgo(minutes),
		ruleCount: 0,
		currentRevision: true,
		...change
	};
}

// The first Deployment has approved rules, the next two drafts await review, the fourth is
// retrying, the sixth failed, and the rest are queued, waiting for the baseline window.
export function seedRuleJobs(): RuleJob[] {
	return deploymentIds().map((resourceId, index) => {
		const id = index + 1;
		const minutes = 400 - index * 30;
		if (index <= 2) {
			const approved = index === 0;
			const authored = authoredProposal(resourceId, index, index === 1 ? 3 : 2);
			const proposal = approved
				? {
						...authored,
						approvedRuleIds: list(authored.rules).map(item => item.rule.id)
					}
				: authored;
			return {
				draft: job(id, resourceId, minutes, {
					status: 'completed',
					attemptCount: 1,
					completedAt: minutesAgo(minutes - 1),
					ruleCount: list(proposal.rules).length,
					...(approved
						? {
								reviewStatus: 'approved',
								reviewedBy: 'api/web-ui',
								reviewedAt: minutesAgo(minutes - 5)
							}
						: {})
				}),
				proposal
			};
		}
		if (index === 3) {
			return {
				draft: job(id, resourceId, minutes, {
					status: 'retryable',
					attemptCount: 1,
					lastError: 'model request timed out after 5m0s'
				}),
				proposal: null
			};
		}
		if (index === 5) {
			return {
				draft: job(id, resourceId, minutes, {
					status: 'failed',
					attemptCount: 8,
					lastError: 'model request failed: 400 Bad Request'
				}),
				proposal: null
			};
		}
		return { draft: job(id, resourceId, minutes, {}), proposal: null };
	});
}
