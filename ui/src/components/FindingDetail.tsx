import type { Finding } from '@/api/types';
import { RemediationItem } from '@/components/Remediation';
import { useGraph } from '@/lib/graph-context';
import { formatTime, initials, label, list } from '@/lib/model';

interface FindingDetailProps {
	finding: Finding;
	active: boolean;
	refresh: number;
	onViewGraph(id: string): void;
}

export function FindingDetail({ finding, active, refresh, onViewGraph }: FindingDetailProps) {
	const graph = useGraph();
	const affected = list(finding.affectedEntityIds);
	const signals = list(finding.signalIds);
	const remediations = list(finding.remediations);
	const invalidated = finding.status === 'invalidated';
	const ruleFinding = finding.origin === 'detection_rule';

	return (
		<>
			<header className="finding-title">
				<div>
					<span className="eyebrow">{finding.category}</span>
					<h2>{finding.summary || 'Security finding'}</h2>
				</div>
				<span className={`badge ${finding.status}`}>{finding.status}</span>
			</header>
			<p className="finding-summary">
				{ruleFinding
					? 'An active detection rule matched the graph change below; no model was involved.'
					: 'This finding is grounded in the graph snapshot and evidence references below.'}
			</p>
			{invalidated ? (
				<div className="stale-note">
					<strong>Historical finding.</strong> Invalidated{' '}
					{finding.invalidatedAt ? formatTime(finding.invalidatedAt) : 'after a later graph update'}
					{finding.invalidatedBySequence ? ` at sequence ${finding.invalidatedBySequence}` : ''}.
				</div>
			) : null}
			<dl className="finding-meta">
				<div>
					<dt>Severity</dt>
					<dd>{finding.severity}</dd>
				</div>
				<div>
					<dt>Source</dt>
					<dd>{ruleFinding ? 'Detection rule' : 'Agentic investigation'}</dd>
				</div>
				{ruleFinding ? (
					<div>
						<dt>Rule</dt>
						<dd className="mono" title={finding.detectionRuleId}>
							{finding.detectionRuleId} r{finding.detectionRuleRevision}
						</dd>
					</div>
				) : (
					<div>
						<dt>Uncertainty</dt>
						<dd>{finding.modelUncertainty || 'unknown'}</dd>
					</div>
				)}
				<div>
					<dt>Created</dt>
					<dd>{formatTime(finding.createdAt)}</dd>
				</div>
				<div>
					<dt>Graph digest</dt>
					<dd className="mono" title={finding.graphSha256 || 'unknown'}>
						{(finding.graphSha256 || 'unknown').slice(0, 12)}
					</dd>
				</div>
			</dl>
			<div className="detail-columns">
				<section className="detail-panel">
					<h3>Affected resources</h3>
					<div className="entity-list">
						{affected.length ? (
							affected.map(id => {
								const resource = graph.resource(id);
								return (
									<button
										className="entity-link"
										type="button"
										key={id}
										onClick={() => onViewGraph(id)}
									>
										<span className="asset-glyph" aria-hidden="true">
											{initials(resource?.kind, 'ID')}
										</span>
										<span>
											<strong>{resource ? label(resource) : id}</strong>
											<small>{resource?.kind || id}</small>
										</span>
										<span aria-hidden="true">→</span>
									</button>
								);
							})
						) : (
							<p className="muted">No affected resources recorded.</p>
						)}
					</div>
				</section>
				<section className="detail-panel">
					<h3>Evidence signals</h3>
					{signals.length ? (
						<ul className="signal-list">
							{signals.map(id => (
								<li key={id}>{id}</li>
							))}
						</ul>
					) : (
						<div className="signal-list">
							<p className="muted">No signal references recorded.</p>
						</div>
					)}
				</section>
			</div>
			<section className="remediation-list">
				<h3>Remediations</h3>
				{invalidated ? (
					<p className="muted">Actions are unavailable for an invalidated finding.</p>
				) : remediations.length ? (
					remediations.map(proposal => (
						<RemediationItem
							finding={finding}
							proposal={proposal}
							active={active}
							refresh={refresh}
							key={proposal.id}
						/>
					))
				) : (
					<p className="muted">No remediation was attached to this finding.</p>
				)}
			</section>
		</>
	);
}
