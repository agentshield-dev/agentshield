import { createContext, type ReactNode, useContext, useMemo } from 'react';
import type { GraphRecord, Resource } from '@/api/types';
import { label, list } from '@/lib/model';

interface Graph {
	record: GraphRecord | undefined;
	resource(id: string): Resource | undefined;
	// Display name for id, falling back to the id when the resource is not in the graph.
	name(id: string): string;
	// "name · id" for a known resource, otherwise the bare id.
	reference(id: string | undefined): string;
}

const empty: Graph = {
	record: undefined,
	resource: () => undefined,
	name: id => id,
	reference: id => id || '—'
};

const GraphContext = createContext<Graph>(empty);

export function GraphProvider({
	record,
	children
}: {
	record: GraphRecord | undefined;
	children: ReactNode;
}) {
	const value = useMemo<Graph>(() => {
		const resources = new Map(list(record?.snapshot.resources).map(item => [item.id, item]));
		const resource = (id: string) => resources.get(id);
		return {
			record,
			resource,
			name: id => {
				const found = resource(id);
				return found ? label(found) : id;
			},
			reference: id => {
				if (!id) return '—';
				const found = resource(id);
				return found ? `${label(found)} · ${id}` : id;
			}
		};
	}, [record]);
	return <GraphContext value={value}>{children}</GraphContext>;
}

export function useGraph(): Graph {
	return useContext(GraphContext);
}
