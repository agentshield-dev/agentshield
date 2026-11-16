import { createContext, type ReactNode, useContext, useMemo } from 'react';
import type { GraphRecord, List, PluginMetadata, Resource } from '@/api/types';
import { apiGroupMatches, label, list, resourceAPIGroup, resourcePluginIDs } from '@/lib/model';

interface Graph {
	record: GraphRecord | undefined;
	resource(id: string): Resource | undefined;
	owners(resource: Resource): readonly PluginMetadata[];
	// Display name for id, falling back to the id when the resource is not in the graph.
	name(id: string): string;
	// "name · id" for a known resource, otherwise the bare id.
	reference(id: string | undefined): string;
}

const empty: Graph = {
	record: undefined,
	resource: () => undefined,
	owners: () => [],
	name: id => id,
	reference: id => id || '—'
};

const GraphContext = createContext<Graph>(empty);

export function GraphProvider({
	record,
	plugins,
	children
}: {
	record: GraphRecord | undefined;
	plugins: List<PluginMetadata>;
	children: ReactNode;
}) {
	const value = useMemo<Graph>(() => {
		const resources = new Map(list(record?.snapshot.resources).map(item => [item.id, item]));
		const pluginMetadata = new Map(list(plugins).map(item => [item.id, item]));
		const apiGroupOwners = list(plugins).flatMap(plugin =>
			list(plugin.ownedApiGroups).map(pattern => ({ pattern, plugin }))
		);
		const resource = (id: string) => resources.get(id);
		return {
			record,
			resource,
			owners: item => {
				const group = resourceAPIGroup(item) ?? '';
				const declared = apiGroupOwners
					.filter(owner => apiGroupMatches(owner.pattern, group))
					.map(owner => owner.plugin);
				if (declared?.length) return declared;
				const kindOwner = pluginMetadata.get(item.kind.split('/', 1)[0]);
				if (kindOwner) return [kindOwner];
				return resourcePluginIDs(item)
					.map(id => pluginMetadata.get(id))
					.filter((plugin): plugin is PluginMetadata => Boolean(plugin));
			},
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
	}, [record, plugins]);
	return <GraphContext value={value}>{children}</GraphContext>;
}

export function useGraph(): Graph {
	return useContext(GraphContext);
}
