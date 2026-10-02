import { describe, expect, it } from 'vitest';
import { list } from '@/lib/model';
import { FakeBackend } from '../mocks/backend';
import { demoScenario } from '../mocks/scenarios';

describe('demo scenarios', () => {
	it('replaces findings and announces the updated graph', () => {
		const backend = new FakeBackend();
		const events: string[] = [];
		backend.subscribe(event => events.push(event.sha256));

		backend.replaceFindings([demoScenario('catalog-ingress').finding]);

		const loaded = backend.queryFindings(new URLSearchParams());
		const findings = list(loaded.findings);
		expect(loaded.total).toBe(1);
		expect(findings[0]?.graphSha256).toBe(backend.graph().sha256);
		expect(list(findings[0]?.remediations)[0]?.graphSha256).toBe(backend.graph().sha256);
		expect(events).toEqual([backend.graph().sha256]);

		backend.replaceFindings([]);
		expect(backend.queryFindings(new URLSearchParams()).total).toBe(0);
		expect(events).toHaveLength(2);
	});
});
