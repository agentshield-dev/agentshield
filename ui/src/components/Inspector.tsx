import type { AssertionBase, Resource } from '@/api/types';
import { DetailRows } from '@/components/DetailRows';
import { WorkloadRules } from '@/components/WorkloadRules';
import { useGraph } from '@/lib/graph-context';
import type { Selection } from '@/lib/layout';
import { label, list, namespace } from '@/lib/model';

function AssertionBlock({ assertion }: { assertion: AssertionBase }) {
	const evidence = list(assertion.evidenceIds);
	const properties = assertion.properties ?? assertion.attributes;
	return (
		<div className="assertion">
			<dl className="detail-grid">
				<DetailRows
					value={{
						plugin: assertion.pluginId || '—',
						source: assertion.sourceId || '—',
						rule: assertion.ruleId || '—'
					}}
				/>
			</dl>
			{properties ? (
				<>
					<h3>Properties</h3>
					<dl className="detail-grid">
						<DetailRows value={properties} />
					</dl>
				</>
			) : null}
			{evidence.length ? (
				<>
					<h3>Evidence IDs</h3>
					<ul className="evidence-list">
						{evidence.map(id => (
							<li key={id}>{id}</li>
						))}
					</ul>
				</>
			) : null}
		</div>
	);
}

function Endpoint({ heading, id, resource }: { heading: string; id: string; resource?: Resource }) {
	const values = resource
		? { name: label(resource), kind: resource.kind || 'unknown', scope: namespace(resource), id }
		: { id };
	return (
		<div className="endpoint">
			<strong>{heading}</strong>
			<dl className="detail-grid">
				<DetailRows value={values} />
			</dl>
		</div>
	);
}

function Details({ selection }: { selection: Selection }) {
	const graph = useGraph();

	if (selection.type === 'resource') {
		const { item } = selection;
		const assertions = list(item.assertions);
		const facets = list(graph.record?.snapshot.facets).filter(
			facet => facet.resourceId === item.id
		);
		return (
			<>
				<section className="detail-section">
					<h3>Resource</h3>
					<dl className="detail-grid">
						<DetailRows
							value={{ kind: item.kind || 'unknown', namespace: namespace(item), id: item.id }}
						/>
					</dl>
				</section>
				<section className="detail-section">
					<h3>Identity claim</h3>
					<dl className="detail-grid">
						<DetailRows value={item.identity} keys={['scheme', 'authorityId', 'immutableKey']} />
					</dl>
				</section>
				<section className="detail-section">
					<h3>Assertions · {assertions.length}</h3>
					{assertions.length ? (
						assertions.map(assertion => (
							<AssertionBlock
								assertion={assertion}
								key={`${assertion.pluginId}/${assertion.sourceId}/${assertion.ruleId}`}
							/>
						))
					) : (
						<p className="muted">No assertions recorded.</p>
					)}
				</section>
				{item.kind === 'kubernetes/deployment' ? <WorkloadRules workloadId={item.id} /> : null}
				{facets.length ? (
					<section className="detail-section">
						<h3>Facets · {facets.length}</h3>
						{facets.map(facet => (
							<div className="assertion" key={facet.id}>
								<dl className="detail-grid">
									<DetailRows value={facet} />
								</dl>
							</div>
						))}
					</section>
				) : null}
			</>
		);
	}

	const { item } = selection;
	const assertions = list(item.assertions);
	return (
		<>
			<section className="detail-section">
				<h3>Relationship</h3>
				<dl className="detail-grid">
					<DetailRows
						value={{
							predicate: item.predicate || '—',
							qualifier: item.qualifier || '—',
							outcome: assertions[0]?.properties?.outcome || '—',
							subject: graph.reference(item.subjectId),
							object: graph.reference(item.objectId),
							id: item.id
						}}
					/>
				</dl>
			</section>
			<section className="detail-section">
				<h3>Endpoints</h3>
				<Endpoint heading="Subject" id={item.subjectId} resource={graph.resource(item.subjectId)} />
				<Endpoint heading="Object" id={item.objectId} resource={graph.resource(item.objectId)} />
			</section>
			<section className="detail-section">
				<h3>Assertions · {assertions.length}</h3>
				{assertions.length ? (
					assertions.map(assertion => (
						<AssertionBlock
							assertion={assertion}
							key={`${assertion.pluginId}/${assertion.sourceId}/${assertion.ruleId}`}
						/>
					))
				) : (
					<p className="muted">No assertions recorded.</p>
				)}
			</section>
		</>
	);
}

export function Inspector({
	selection,
	open,
	onClose
}: {
	selection: Selection | null;
	open: boolean;
	onClose(): void;
}) {
	const title = !selection
		? 'Nothing selected'
		: selection.type === 'resource'
			? label(selection.item)
			: selection.item.predicate || 'relationship';
	return (
		<aside className={open ? 'inspector open' : 'inspector'} aria-label="Selection details">
			<div className="inspector-head">
				<div>
					<span className="eyebrow">Selection</span>
					<h2>{title}</h2>
				</div>
				<button
					className="bare-button mobile-only"
					type="button"
					aria-label="Close details"
					onClick={onClose}
				>
					×
				</button>
			</div>
			<div className="detail-body">
				{selection ? (
					<Details selection={selection} />
				) : (
					<p className="muted">
						Select a resource or relationship to inspect identity, provenance, evidence, and facets.
					</p>
				)}
			</div>
		</aside>
	);
}
