import type {
	AssertionBase,
	List,
	RelationshipDetailResponse,
	ResourceDetailResponse
} from '@/api/types';
import { DetailRows } from '@/components/DetailRows';
import { useGraph } from '@/lib/graph-context';
import { allEvidence, label, list, securitySemantics } from '@/lib/model';

function Provenance({ assertions }: { assertions: List<AssertionBase> }) {
	const items = list(assertions);
	if (!items.length) return <p className="muted">No assertions recorded.</p>;
	return items.map(assertion => {
		const evidence = allEvidence([assertion]).length;
		return (
			<article
				className="provenance-row"
				key={`${assertion.pluginId}/${assertion.sourceId}/${assertion.ruleId}`}
			>
				<strong>
					{assertion.pluginId} · {assertion.sourceId}
				</strong>
				<small>{assertion.ruleId}</small>
				<span>
					{evidence} evidence reference{evidence === 1 ? '' : 's'}
				</span>
			</article>
		);
	});
}

export function ResourceRecord({
	response,
	onViewGraph
}: {
	response: ResourceDetailResponse;
	onViewGraph(id: string): void;
}) {
	const graph = useGraph();
	const { resource } = response;
	const assertions = list(resource.assertions);
	const attributes = Object.assign({}, ...assertions.map(assertion => assertion.attributes));
	const findings = list(response.findings);
	const relationships = list(response.relationships);
	const facets = list(response.facets);

	return (
		<>
			<header className="record-title">
				<div>
					<span className="eyebrow">{resource.kind}</span>
					<h2>{label(resource)}</h2>
					<p className="mono">{resource.id}</p>
				</div>
				<button className="button secondary" type="button" onClick={() => onViewGraph(resource.id)}>
					View graph
				</button>
			</header>
			<div className="record-grid">
				<section className="detail-panel">
					<h3>Stable identity</h3>
					<dl className="detail-grid record-fields">
						<DetailRows value={resource.identity} />
					</dl>
				</section>
				<section className="detail-panel">
					<h3>Current attributes</h3>
					<dl className="detail-grid record-fields">
						<DetailRows value={attributes} />
					</dl>
				</section>
			</div>
			<section className="record-section">
				<h3>Related findings · {findings.length}</h3>
				{findings.length ? (
					findings.map(finding => (
						<a
							className="linked-row"
							href={`#findings/${encodeURIComponent(finding.id)}`}
							key={finding.id}
						>
							<span>
								<strong>{finding.summary || finding.category}</strong>
								<small>
									{finding.severity} · {finding.status}
								</small>
							</span>
							<span aria-hidden="true">→</span>
						</a>
					))
				) : (
					<p className="muted">No findings reference this resource.</p>
				)}
			</section>
			<section className="record-section">
				<h3>Relationships · {relationships.length}</h3>
				{relationships.length ? (
					relationships.map(relationship => (
						<a
							className="linked-row"
							href={`#catalog/relationships/${encodeURIComponent(relationship.id)}`}
							key={relationship.id}
						>
							<span>
								<strong>{relationship.predicate}</strong>
								<small>
									{graph.reference(relationship.subjectId)} →{' '}
									{graph.reference(relationship.objectId)}
								</small>
							</span>
							<span aria-hidden="true">→</span>
						</a>
					))
				) : (
					<p className="muted">No resolved relationships.</p>
				)}
			</section>
			<section className="record-section">
				<h3>Facets · {facets.length}</h3>
				{facets.length ? (
					facets.map(facet => (
						<article className="provenance-row" key={facet.id}>
							<strong>
								{facet.kind} · {facet.key}
							</strong>
							<small className="mono">{facet.id}</small>
						</article>
					))
				) : (
					<p className="muted">No facets recorded.</p>
				)}
			</section>
			<section className="record-section">
				<h3>Provenance</h3>
				<Provenance assertions={assertions} />
			</section>
		</>
	);
}

export function RelationshipRecord({ response }: { response: RelationshipDetailResponse }) {
	const { relationship, subject, object } = response;
	const assertions = list(relationship.assertions);
	const semantics = assertions.map(securitySemantics).filter(item => item !== null);
	const evidence = allEvidence(assertions);

	return (
		<>
			<header className="record-title">
				<div>
					<span className="eyebrow">{relationship.predicate}</span>
					<h2>
						{label(subject)} → {label(object)}
					</h2>
					<p className="mono">{relationship.id}</p>
				</div>
			</header>
			<div className="relationship-path">
				<a href={`#catalog/resources/${encodeURIComponent(subject.id)}`}>
					<span>Subject</span>
					<strong>{label(subject)}</strong>
					<small>{subject.kind}</small>
				</a>
				<b>→</b>
				<a href={`#catalog/resources/${encodeURIComponent(object.id)}`}>
					<span>Object</span>
					<strong>{label(object)}</strong>
					<small>{object.kind}</small>
				</a>
			</div>
			<section className="record-section">
				<h3>Security semantics · {semantics.length}</h3>
				{semantics.length ? (
					semantics.map(item => (
						<dl className="semantic-grid" key={JSON.stringify(item)}>
							<DetailRows value={item} />
						</dl>
					))
				) : (
					<p className="muted">No provider-neutral security semantics are attached.</p>
				)}
			</section>
			<section className="record-section">
				<h3>Provenance</h3>
				<Provenance assertions={assertions} />
			</section>
			<section className="record-section">
				<h3>Evidence</h3>
				{evidence.length ? (
					<ul className="signal-list">
						{evidence.map(id => (
							<li key={id}>{id}</li>
						))}
					</ul>
				) : (
					<p className="muted">No evidence references recorded.</p>
				)}
			</section>
		</>
	);
}
