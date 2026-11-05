import { describe, expect, it } from 'vitest';
import { list } from '@/lib/model';
import { FakeBackend } from '../mocks/backend';
import { demoScenario } from '../mocks/scenarios';

describe('demo scenarios', () => {
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
