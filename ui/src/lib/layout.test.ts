import { describe, expect, it } from 'vitest';
import type { Relationship, Resource } from '@/api/types';
import { layoutGraph, wrapText } from '@/lib/layout';

function resource(id: string): Resource {
	return {
		id,
		kind: 'kubernetes/Service',
		identity: {
			scheme: { group: '', version: 'v1', kind: 'Service' },
			authorityId: 'c',
			immutableKey: id
		},
		assertions: []
	};
}

function relationship(subjectId: string, objectId: string): Relationship {
	return {
		id: `${subjectId}->${objectId}`,
		subjectId,
		predicate: 'routes-to',
		objectId,
		assertions: []
	};
}

function columns(resources: Resource[], relationships: Relationship[]): Record<string, number> {
	const { positions } = layoutGraph(resources, relationships);
	return Object.fromEntries([...positions].map(([id, box]) => [id, box.x]));
}

describe('layoutGraph', () => {
	const resources = ['gateway', 'route', 'service', 'pod', 'policy'].map(resource);
	const relationships = [
		relationship('gateway', 'route'),
		relationship('route', 'service'),
		relationship('service', 'pod'),
		relationship('policy', 'service')
	];

	it('places subjects in earlier columns than their objects', () => {
		const x = columns(resources, relationships);
		expect(x.gateway).toBeLessThan(x.route);
		expect(x.route).toBeLessThan(x.service);
		expect(x.service).toBeLessThan(x.pod);
		expect(x.policy).toBeLessThan(x.service);
	});

	it('is independent of input order', () => {
		const expected = layoutGraph(resources, relationships);
		expect(layoutGraph([...resources].reverse(), [...relationships].reverse())).toEqual(expected);
		expect(
			layoutGraph(
				[resources[2], resources[0], resources[4], resources[1], resources[3]],
				relationships
			)
		).toEqual(expected);
	});

	it('places every node of a cycle in adjacent columns, independent of input order', () => {
		const cycle = ['a', 'b', 'c'].map(resource);
		const edges = [relationship('a', 'b'), relationship('b', 'c'), relationship('c', 'a')];
		const layout = layoutGraph(cycle, edges);
		const x = columns(cycle, edges);
		expect(Object.keys(x)).toHaveLength(3);
		// Cycle members take the first column free of their placed neighbors: a, then b, then c.
		const pitch = x.b - x.a;
		expect(pitch).toBeGreaterThan(0);
		expect(x.c - x.b).toBe(pitch);
		expect(layoutGraph([...cycle].reverse(), [...edges].reverse())).toEqual(layout);
	});

	it('ignores self-loops and relationships to unknown resources', () => {
		const single = [resource('a')];
		const layout = layoutGraph(single, [relationship('a', 'a'), relationship('a', 'missing')]);
		expect([...layout.positions.keys()]).toEqual(['a']);
		expect(layout).toEqual(layoutGraph(single, []));
	});
});

describe('wrapText', () => {
	it('breaks long paths at a separator near the end of a line', () => {
		expect(wrapText('namespace/a-very-long-resource-name', 20)).toEqual([
			'namespace/a-very-',
			'long-resource-name'
		]);
	});

	it('returns one empty line for empty text', () => {
		expect(wrapText('', 10)).toEqual(['']);
	});
});
