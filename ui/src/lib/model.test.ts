import { describe, expect, it } from 'vitest';
import { apiGroupMatches } from '@/lib/model';

describe('apiGroupMatches', () => {
	it('matches exact and wildcard API-group ownership', () => {
		expect(apiGroupMatches('example.io', 'example.io')).toBe(true);
		expect(apiGroupMatches('*.istio.io', 'networking.istio.io')).toBe(true);
		expect(apiGroupMatches('*.cilium.io', 'cilium.io')).toBe(true);
		expect(apiGroupMatches('*.istio.io', 'notistio.io')).toBe(false);
	});
});
