import { describe, expect, it } from 'vitest';
import { list } from '@/lib/model';
import { ApiError, FakeBackend } from '../mocks/backend';
import { demoScenario } from '../mocks/scenarios';

describe('demo scenarios', () => {
	it('requires explicit rule selection when approving a draft', () => {
		const backend = new FakeBackend();
		const draft = list(backend.ruleDrafts().drafts).find(
			item => item.status === 'completed' && item.reviewStatus === 'pending' && item.ruleCount > 0
		);
		if (!draft) throw new Error('expected a pending completed rule draft');
		let failure: unknown;
		try {
			backend.reviewRuleDraft(String(draft.id), { decision: 'approved' });
		} catch (error) {
			failure = error;
		}
		expect(failure).toBeInstanceOf(ApiError);
		expect((failure as ApiError).status).toBe(400);
		draft.currentRevision = false;
		const proposal = backend.ruleDraft(String(draft.id)).proposal;
		failure = undefined;
		try {
			backend.reviewRuleDraft(String(draft.id), {
				decision: 'approved',
				ruleIds: list(proposal?.rules).map(item => item.rule.id)
			});
		} catch (error) {
			failure = error;
		}
		expect(failure).toBeInstanceOf(ApiError);
		expect((failure as ApiError).status).toBe(409);
	});

	it('replaces findings and announces the updated graph', () => {
		const backend = new FakeBackend();
		const events: number[] = [];
		backend.subscribe(event => events.push(event.revision));

		backend.replaceFindings([demoScenario('catalog-ingress').finding]);

		const loaded = backend.queryFindings(new URLSearchParams());
		const findings = list(loaded.findings);
		expect(loaded.total).toBe(1);
		expect(findings[0]?.graphRevision).toBe(backend.graph().revision);
		expect(list(findings[0]?.remediations)[0]?.graphRevision).toBe(backend.graph().revision);
		expect(events).toEqual([backend.graph().revision]);

		backend.replaceFindings([]);
		expect(backend.queryFindings(new URLSearchParams()).total).toBe(0);
		expect(events).toHaveLength(2);
	});
});
