import type { DetectorRule, RuleDraft } from '@/api/types';

// The reviewer-facing state of a draft, combining authoring and review status.
export type DraftState =
	| 'queued'
	| 'authoring'
	| 'retrying'
	| 'failed'
	| 'review'
	| 'approved'
	| 'rejected';

export function draftState(draft: RuleDraft): DraftState {
	switch (draft.status) {
		case 'queued':
			return 'queued';
		case 'running':
			return 'authoring';
		case 'retryable':
			return 'retrying';
		case 'failed':
			return 'failed';
		default:
			return draft.reviewStatus === 'pending' ? 'review' : draft.reviewStatus;
	}
}

export const draftStateLabels: Record<DraftState, string> = {
	queued: 'queued',
	authoring: 'authoring',
	retrying: 'retrying',
	failed: 'failed',
	review: 'awaiting review',
	approved: 'approved',
	rejected: 'rejected'
};

export function draftBadge(state: DraftState): string {
	switch (state) {
		case 'review':
			return 'badge medium';
		case 'approved':
			return 'badge active';
		case 'retrying':
		case 'failed':
		case 'rejected':
			return 'badge high';
		default:
			return 'badge';
	}
}

// A failed draft is not authoring: the worker gave up until Author now is used.
export function isAuthoring(draft: RuleDraft): boolean {
	return draft.status !== 'completed' && draft.status !== 'failed';
}

export function ruleSelector(rule: DetectorRule): string {
	return `${rule.type}:${rule.kind}`;
}

// How often views refresh while a draft is being authored.
export const authoringPollMs = 3000;
