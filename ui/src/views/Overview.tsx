import { useApi } from '@/api/client';
import type { OverviewResponse } from '@/api/types';
import { EmptyState } from '@/components/EmptyState';
import { displayLabel, formatTime, list } from '@/lib/model';

export function Overview({
	active,
	refresh,
	demo = false
}: {
	active: boolean;
	refresh: number;
	demo?: boolean;
}) {
	const overview = useApi<OverviewResponse>(active ? '/api/v1/overview' : null, refresh);
	const { data, error } = overview;
	const loading = !data && !error;
	const contributions = list(data?.manifest.contributions);
	const findings = list(data?.activeFindings);
	const unhealthy = contributions.filter(item => !item.ready || item.sourceHealth !== 'healthy');
	const metrics = data
		? ([
				['Graph resources', data.counts.resources || 0],
				['Relationships', data.counts.relationships || 0],
				['Sources needing attention', unhealthy.length]
			] as const)
		: [];
	const failure = error ? (
		<EmptyState title="Overview unavailable" error>
			{error.message}
		</EmptyState>
	) : null;

	return (
		<section className="page-view overview-page" aria-label="Security overview" hidden={!active}>
			<header className="page-header">
				<div>
					<span className="eyebrow">{demo ? 'Sample environment' : 'Current environment'}</span>
					<h1>Security overview</h1>
					<p>
						{demo
							? 'A sample summary of graph inventory, recent findings, and source health.'
							: 'A live summary of graph inventory, recent findings, and source health.'}
					</p>
				</div>
				<a className="button primary" href="#findings">
					Review findings
				</a>
			</header>
			<section className="metric-grid" aria-label="Environment summary">
				{loading ? (
					<article className="metric-card">
						<span>{demo ? 'Loading sample environment…' : 'Loading current environment…'}</span>
					</article>
				) : (
					metrics.map(([name, value]) => (
						<article className="metric-card" key={name}>
							<span>{name}</span>
							<strong>{Number(value).toLocaleString()}</strong>
						</article>
					))
				)}
			</section>
			<div className="overview-dashboard">
				<section className="panel">
					<div className="panel-head">
						<div>
							<h2>Recent findings</h2>
							<p>Newest active findings</p>
						</div>
						<a className="text-link" href="#findings">
							View all →
						</a>
					</div>
					<div className="overview-list">
						{loading ? (
							<EmptyState title="Loading findings…" />
						) : failure ? (
							failure
						) : findings.length ? (
							<>
								{findings.map(finding => (
									<a
										className="overview-row"
										href={`#findings/${encodeURIComponent(finding.id)}`}
										key={finding.id}
									>
										<i className={`severity-marker ${finding.severity}`} />
										<span>
											<strong>{finding.summary || displayLabel(finding.category)}</strong>
											<small>
												{displayLabel(finding.category)} · {finding.severity}
											</small>
										</span>
										<span aria-hidden="true">→</span>
									</a>
								))}
								{data?.activeFindingsHasMore ? (
									<a className="text-link overview-more" href="#findings">
										More active findings →
									</a>
								) : null}
							</>
						) : (
							<EmptyState title="No active findings">
								No active findings were reported for the current graph.
							</EmptyState>
						)}
					</div>
				</section>
				<section className="panel">
					<div className="panel-head">
						<div>
							<h2>Discovery sources</h2>
							<p>Current source health and latest observations</p>
						</div>
					</div>
					<div className="source-list">
						{loading ? (
							<EmptyState title="Loading sources…" />
						) : failure ? (
							failure
						) : contributions.length ? (
							contributions.map(item => {
								const healthy = item.ready && item.sourceHealth === 'healthy';
								return (
									<article
										className="source-row"
										key={`${item.pluginId}/${item.sourceId}/${item.name}`}
									>
										<span className={`source-state ${healthy ? 'healthy' : 'attention'}`} />
										<span>
											<strong>
												{item.pluginId} · {item.sourceId}
											</strong>
											<small>
												{item.name} · observed {formatTime(item.sourceObservedAt)}
											</small>
										</span>
										<span className={`badge ${healthy ? 'active' : 'invalidated'}`}>
											{item.sourceHealth || (item.ready ? 'ready' : 'not ready')}
										</span>
									</article>
								);
							})
						) : (
							<EmptyState title="No discovery data">
								Sources have not published data for the current graph.
							</EmptyState>
						)}
					</div>
				</section>
			</div>
		</section>
	);
}
