import { type FormEvent, type ReactNode, useEffect, useState } from 'react';
import { useApi } from '@/api/client';
import type { Finding, FindingsResponse } from '@/api/types';
import { EmptyState } from '@/components/EmptyState';
import { FindingDetail } from '@/components/FindingDetail';
import { MetricCards } from '@/components/MetricCards';
import { Pagination } from '@/components/Pagination';
import { formatTime, list } from '@/lib/model';
import { useCursorPager } from '@/lib/pager';
import { navigate } from '@/lib/route';

interface Filters {
	status: string;
	severity: string;
	category: string;
	entity: string;
}

const defaultFilters: Filters = { status: 'active', severity: '', category: '', entity: '' };

function isDefault(filters: Filters): boolean {
	return (
		filters.status === 'active' &&
		!filters.severity &&
		!filters.category.trim() &&
		!filters.entity.trim()
	);
}

function findingsURL(filters: Filters, cursor: string): string {
	const query = new URLSearchParams({ limit: '20' });
	const fields: readonly (readonly [string, string])[] = [
		['status', filters.status],
		['severity', filters.severity],
		['category', filters.category],
		['affectedEntityId', filters.entity]
	];
	for (const [name, value] of fields) {
		if (value.trim()) query.set(name, value.trim());
	}
	if (cursor) query.set('cursor', cursor);
	return `/api/v1/findings?${query}`;
}

interface FindingsProps {
	active: boolean;
	refresh: number;
	selectedID: string | undefined;
	onTotal(total: number): void;
	onViewGraph(id: string): void;
}

export function Findings({ active, refresh, selectedID, onTotal, onViewGraph }: FindingsProps) {
	const [draft, setDraft] = useState(defaultFilters);
	const [applied, setApplied] = useState(defaultFilters);
	const [chosen, setChosen] = useState<string>();
	const pager = useCursorPager();
	const findings = useApi<FindingsResponse>(
		active ? findingsURL(applied, pager.cursor) : null,
		refresh
	);
	const { data, error } = findings;
	const items = list(data?.findings);
	// Metrics and the selected finding stay on the previous page's data until the next page arrives.
	const page = data ?? findings.latest;
	const shown = list(page?.findings);
	const defaultQuery = isDefault(applied);

	useEffect(() => {
		if (data && defaultQuery) onTotal(data.total);
	}, [data, defaultQuery, onTotal]);

	// A deep-linked finding wins; otherwise keep the last clicked finding while it is on the page.
	const currentID = selectedID ?? (shown.some(item => item.id === chosen) ? chosen : shown[0]?.id);
	const detail = useApi<Finding>(
		active && selectedID ? `/api/v1/findings/${encodeURIComponent(selectedID)}` : null,
		refresh
	);
	const finding = detail.data ?? shown.find(item => item.id === currentID);

	function apply(event: FormEvent) {
		event.preventDefault();
		setApplied(draft);
		pager.reset();
	}

	function clear() {
		setDraft(defaultFilters);
		setApplied(defaultFilters);
		pager.reset();
	}

	function choose(id: string) {
		setChosen(id);
		navigate(`findings/${encodeURIComponent(id)}`);
	}

	const metrics = page
		? ([
				['Active on page', shown.filter(item => item.status === 'active').length],
				[
					'Critical or high',
					shown.filter(item => item.severity === 'critical' || item.severity === 'high').length
				],
				['Affected resources', new Set(shown.flatMap(item => list(item.affectedEntityIds))).size],
				[
					'Proposed actions',
					shown.reduce((count, item) => count + list(item.remediations).length, 0)
				]
			] as const)
		: [];

	let detailPane: ReactNode;
	if (finding) {
		detailPane = (
			<FindingDetail
				finding={finding}
				active={active}
				refresh={refresh}
				onViewGraph={onViewGraph}
			/>
		);
	} else if (detail.error) {
		detailPane = (
			<EmptyState title="Finding unavailable" error>
				{detail.error.message}
			</EmptyState>
		);
	} else if (selectedID) {
		detailPane = <EmptyState title="Loading finding…" />;
	} else if (error) {
		detailPane = (
			<EmptyState title="No finding selected">
				Refresh or adjust the filters to try again.
			</EmptyState>
		);
	} else if (data) {
		detailPane = (
			<EmptyState title="No finding selected">
				Finding evidence and graph context will appear here.
			</EmptyState>
		);
	} else {
		detailPane = (
			<EmptyState title="Select a finding">
				Review its evidence, graph context, and available remediations.
			</EmptyState>
		);
	}

	return (
		<section className="page-view findings-page" aria-label="Security findings" hidden={!active}>
			<header className="page-header">
				<div>
					<span className="eyebrow">Prioritized risk</span>
					<h1>Findings</h1>
					<p>
						Evidence-backed risks from the current environment graph, ordered by recency and ready
						for investigation.
					</p>
				</div>
			</header>
			<MetricCards label="Finding summary" metrics={metrics} />
			<form className="filter-bar" aria-label="Filter findings" onSubmit={apply}>
				<label className="select">
					<span>Status</span>
					<select
						value={draft.status}
						onChange={event => setDraft({ ...draft, status: event.target.value })}
					>
						<option value="active">Active</option>
						<option value="">All statuses</option>
						<option value="invalidated">Invalidated</option>
					</select>
				</label>
				<label className="select">
					<span>Severity</span>
					<select
						value={draft.severity}
						onChange={event => setDraft({ ...draft, severity: event.target.value })}
					>
						<option value="">All severities</option>
						<option value="critical">Critical</option>
						<option value="high">High</option>
						<option value="medium">Medium</option>
						<option value="low">Low</option>
					</select>
				</label>
				<label className="search">
					<span aria-hidden="true">⌕</span>
					<input
						type="search"
						placeholder="Category"
						autoComplete="off"
						aria-label="Finding category"
						value={draft.category}
						onChange={event => setDraft({ ...draft, category: event.target.value })}
					/>
				</label>
				<label className="search entity-search">
					<span aria-hidden="true">⌕</span>
					<input
						type="search"
						placeholder="Affected entity ID"
						autoComplete="off"
						aria-label="Affected entity ID"
						value={draft.entity}
						onChange={event => setDraft({ ...draft, entity: event.target.value })}
					/>
				</label>
				<button className="button primary" type="submit">
					Apply filters
				</button>
				<button className="button secondary" type="button" onClick={clear}>
					Clear
				</button>
			</form>
			<div className="findings-layout panel">
				<section className="finding-list-shell" aria-label="Finding list">
					<div className="panel-head">
						<div>
							<h2>Ranked findings</h2>
							<p>
								{error
									? 'Query failed'
									: data
										? `${items.length.toLocaleString()} finding${items.length === 1 ? '' : 's'} on this page`
										: 'Loading findings'}
							</p>
						</div>
					</div>
					<div className="finding-list">
						{error ? (
							<EmptyState title="Findings unavailable" error>
								{error.message}
							</EmptyState>
						) : !data ? (
							<EmptyState title="Loading findings…">
								Querying the current findings index.
							</EmptyState>
						) : items.length ? (
							items.map(item => (
								<button
									className={`finding-row${finding?.id === item.id ? ' active' : ''}`}
									type="button"
									key={item.id}
									onClick={() => choose(item.id)}
								>
									<i className={`severity-marker ${item.severity}`} />
									<span>
										<span className="finding-row-top">
											<strong>{item.summary || item.category}</strong>
											<span className={`badge ${item.status}`}>{item.status}</span>
										</span>
										<p>{item.category}</p>
										<small>
											{item.severity} · {formatTime(item.createdAt)}
										</small>
									</span>
								</button>
							))
						) : (
							<EmptyState title="No matching findings">
								Adjust the filters or include invalidated findings.
							</EmptyState>
						)}
					</div>
					<Pagination label="Finding pages" subject="findings" pager={pager} state={findings} />
				</section>
				<article className="finding-detail">{detailPane}</article>
			</div>
		</section>
	);
}
