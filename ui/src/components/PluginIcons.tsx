import type { Resource } from '@/api/types';
import agentgateway from '@/assets/plugin-icons/agentgateway.svg';
import aws from '@/assets/plugin-icons/aws.svg';
import cilium from '@/assets/plugin-icons/cilium.svg';
import falco from '@/assets/plugin-icons/falco.svg';
import istio from '@/assets/plugin-icons/istio.svg';
import kubernetes from '@/assets/plugin-icons/kubernetes.svg';
import { useGraph } from '@/lib/graph-context';

const sources: Readonly<Record<string, string>> = {
	agentgateway,
	aws,
	cilium,
	falco,
	istio,
	kubernetes
};

export function pluginIconSource(icon: string | undefined): string | undefined {
	return icon ? sources[icon] : undefined;
}

export function PluginIcons({ resource, fallback }: { resource: Resource; fallback: string }) {
	const graph = useGraph();
	const plugins = graph.owners(resource).filter(plugin => pluginIconSource(plugin?.icon));
	if (!plugins.length) return <span className="asset-glyph">{fallback}</span>;
	return (
		<span className="plugin-icons" aria-hidden="true">
			{plugins.map(plugin => (
				<img
					src={pluginIconSource(plugin?.icon)}
					alt=""
					title={plugin?.description}
					key={plugin?.id}
				/>
			))}
		</span>
	);
}
