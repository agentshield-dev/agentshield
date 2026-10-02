import { type ReactNode, useEffect, useState } from 'react';
import { useApi } from '@/api/client';
import type { DetectorRule, RuleDraftsResponse, RuleMode, RulesResponse } from '@/api/types';
import { EmptyState } from '@/components/EmptyState';
import { MetricCards } from '@/components/MetricCards';
import { RuleDraftDetail } from '@/components/RuleDraftDetail';
import { useGraph } from '@/lib/graph-context';
import { formatTime, list } from '@/lib/model';
import { navigate } from '@/lib/route';
import {
	authoringPollMs,
	type DraftState,
	draftBadge,
	draftState,
	draftStateLabels,
	isAuthoring,
	ruleSelector
} from '@/lib/rules';

type RulesTab = 'active' | 'drafts';

const tabs: readonly { id: RulesTab; title: string }[] = [
	{ id: 'active', title: 'Loaded rules' },
	{ id: 'drafts', title: 'Drafts' }
];

const draftFilters: readonly { value: string; title: string; states: readonly DraftState[] }[] = [
	{ value: '', title: 'All drafts', states: [] },
	{ value: 'review', title: 'Awaiting review', states: ['review'] },
	{ value: 'progress', title: 'In progress', states: ['queued', 'authoring', 'retrying'] },
	{ value: 'failed', title: 'Failed', states: ['failed'] },
	{ value: 'approved', title: 'Approved', states: ['approved'] },
	{ value: 'rejected', title: 'Rejected', states: ['rejected'] }
];

// A loaded rule: a Deployment rule in active or shadow mode, or an operator ruleset rule.
interface LoadedRule {
	key: string;
	rule: DetectorRule;
	mode: RuleMode | 'ruleset';
}

function modeBadge(mode: LoadedRule['mode']): string {
	return mode === 'active' ? 'badge active' : mode === 'shadow' ? 'badge medium' : 'badge';
}

function LoadedRuleDetail({
	item,
	onViewGraph
}: {
	item: LoadedRule;
	onViewGraph(id: string): void;
}) {
	const graph = useGraph();
	const workload = item.rule.workloadResourceId;
	return (
		<>
			<header className="finding-title">
				<div>
					<span className="eyebrow">{ruleSelector(item.rule)}</span>
					<h2>{workload ? graph.name(workload) : 'All workloads'}</h2>
				</div>
				<span className={modeBadge(item.mode)}>{item.mode}</span>
			</header>
			<p className="finding-summary">
				{item.mode === 'shadow'
					? 'An unreviewed draft: matches are recorded as signals but do not become findings until the draft is approved.'
					: item.mode === 'active'
						? 'An approved Deployment rule: matches become findings.'
						: 'A rule from the active operator ruleset.'}
			</p>
			<dl className="finding-meta">
				<div>
					<dt>Risk</dt>
					<dd>{item.rule.risk}</dd>
				</div>
				<div>
					<dt>Window</dt>
					<dd>{item.rule.windowSeconds}s</dd>
				</div>
				<div>
					<dt>Reasons</dt>
					<dd>{list(item.rule.reasons).join(', ') || '—'}</dd>
				</div>
				<div>
					<dt>Rule ID</dt>
					<dd className="mono" title={item.rule.id}>
						{item.rule.id.split('/').at(-1)}
					</dd>
				</div>
			</dl>
			<section className="approval-preview" aria-label="Rule expression">
				<h3>Expression</h3>
				<pre>{item.rule.expression}</pre>
			</section>
			{workload ? (
				<div className="remediation-actions">
					<button className="button secondary" type="button" onClick={() => onViewGraph(workload)}>
						View workload
					</button>
				</div>
			) : null}
		</>
	);
}

interface RulesProps {
	active: boolean;
	refresh: number;
	parts: readonly string[];
	onAwaitingReview(count: number): void;
	onViewGraph(id: string): void;
}

export function Rules({ active, refresh, parts, onAwaitingReview, onViewGraph }: RulesProps) {
	const graph = useGraph();
	const [search, setSearch] = useState('');
	const [draftFilter, setDraftFilter] = useState('');
	const [changes, setChanges] = useState(0);
	const tab: RulesTab = parts[1] === 'drafts' ? 'drafts' : 'active';
	const selectedID = active ? parts[2] : undefined;
	const key = refresh + changes;
	const loaded = useApi<RulesResponse>(active ? '/api/v1/rules' : null, key);
	const drafts = useApi<RuleDraftsResponse>(active ? '/api/v1/rule-drafts' : null, key);
	const allDrafts = list(drafts.data?.drafts);
	const authoring = allDrafts.some(isAuthoring);
	const awaiting = allDrafts.filter(draft => draftState(draft) === 'review').length;

	useEffect(() => {
		if (drafts.data) onAwaitingReview(awaiting);
	}, [drafts.data, awaiting, onAwaitingReview]);

	// Refresh while any draft is being authored, so progress and new drafts appear.
	useEffect(() => {
		if (!active || !authoring) return;
		const timer = window.setInterval(() => setChanges(value => value + 1), authoringPollMs);
		return () => window.clearInterval(timer);
	}, [active, authoring]);

	// Like the other views, an inactive view renders no records.
	if (!active) return <section className="page-view" aria-label="Detection rules" hidden />;

	const workloadName = (id: string | undefined) => (id ? graph.name(id) : 'All workloads');
	const matches = (id: string | undefined) =>
		!search.trim() || workloadName(id).toLowerCase().includes(search.trim().toLowerCase());
	const states = draftFilters.find(item => item.value === draftFilter)?.states ?? [];
	const loadedRules: LoadedRule[] = [
		...list(loaded.data?.workloadRules).map(item => ({
			key: `${item.mode}/${item.rule.id}`,
			rule: item.rule,
			mode: item.mode
		})),
		...list(loaded.data?.rules).map(rule => ({
			key: `ruleset/${rule.id}`,
			rule,
			mode: 'ruleset' as const
		}))
	].filter(item => matches(item.rule.workloadResourceId));
	const shownDrafts = allDrafts.filter(
		draft => matches(draft.resourceId) && (!states.length || states.includes(draftState(draft)))
	);

	const selectedRule =
		tab === 'active'
			? (loadedRules.find(item => item.key === selectedID) ?? loadedRules[0])
			: undefined;
	const selectedDraft =
		tab === 'drafts'
			? (allDrafts.find(draft => String(draft.id) === selectedID) ?? shownDrafts[0])
			: undefined;
	const workloadRules = list(loaded.data?.workloadRules);
	const metrics = [
		['Active rules', workloadRules.filter(item => item.mode === 'active').length],
		['Shadow rules', workloadRules.filter(item => item.mode === 'shadow').length],
		['Drafts awaiting review', awaiting],
		['Authoring in progress', allDrafts.filter(isAuthoring).length]
	] as const;
	const listState = tab === 'active' ? loaded : drafts;

	let detailPane: ReactNode;
	if (tab === 'active' && selectedRule) {
		detailPane = <LoadedRuleDetail item={selectedRule} onViewGraph={onViewGraph} />;
	} else if (tab === 'drafts' && selectedDraft) {
		detailPane = (
			<RuleDraftDetail
				draftId={selectedDraft.id}
				active={active}
				refresh={key}
				onChanged={() => setChanges(value => value + 1)}
				onViewGraph={onViewGraph}
			/>
		);
	} else if (listState.error) {
		detailPane = (
			<EmptyState title="Rules unavailable" error>
				{listState.error.message}
			</EmptyState>
		);
	} else if (!listState.data) {
		detailPane = <EmptyState title="Loading rules…" />;
	} else {
		detailPane = (
			<EmptyState title={tab === 'active' ? 'No rule selected' : 'No draft selected'}>
				{tab === 'active'
					? 'Deployment drafts run in shadow mode until approved.'
					: 'Drafts appear when the AI author processes a Deployment.'}
			</EmptyState>
		);
	}

	let rows: ReactNode;
	if (listState.error) {
		rows = (
			<EmptyState title="Rules unavailable" error>
				{listState.error.message}
			</EmptyState>
		);
	} else if (!listState.data) {
		rows = <EmptyState title="Loading rules…" />;
	} else if (tab === 'active') {
		rows = loadedRules.length ? (
			loadedRules.map(item => (
				<button
					className={`finding-row${selectedRule?.key === item.key ? ' active' : ''}`}
					type="button"
					key={item.key}
					onClick={() => navigate(`rules/active/${encodeURIComponent(item.key)}`)}
				>
					<i className={`severity-marker ${item.rule.risk}`} />
					<span>
						<span className="finding-row-top">
							<strong>{workloadName(item.rule.workloadResourceId)}</strong>
							<span className={modeBadge(item.mode)}>{item.mode}</span>
						</span>
						<p className="mono">{item.rule.expression}</p>
						<small>
							{ruleSelector(item.rule)} · {item.rule.risk}
						</small>
					</span>
				</button>
			))
		) : (
			<EmptyState title="No loaded rules">
				Deployment drafts appear here in shadow mode once authored.
			</EmptyState>
		);
	} else {
		rows = shownDrafts.length ? (
			shownDrafts.map(draft => {
				const state = draftState(draft);
				return (
					<button
						className={`finding-row${selectedDraft?.id === draft.id ? ' active' : ''}`}
						type="button"
						key={draft.id}
						onClick={() => navigate(`rules/drafts/${draft.id}`)}
					>
						<i className={`severity-marker${state === 'review' ? ' medium' : ''}`} />
						<span>
							<span className="finding-row-top">
								<strong>{graph.name(draft.resourceId)}</strong>
								<span className={draftBadge(state)}>{draftStateLabels[state]}</span>
							</span>
							<p>
								Draft #{draft.id} ·{' '}
								{isAuthoring(draft)
									? 'no rules yet'
									: `${draft.ruleCount} rule${draft.ruleCount === 1 ? '' : 's'}`}
								{draft.currentRevision ? '' : ' · previous revision'}
							</p>
							<small>
								{draft.requestedBy ? 'manual' : 'new Pod template'} ·{' '}
								{formatTime(draft.requestedAt ?? draft.createdAt)}
							</small>
						</span>
					</button>
				);
			})
		) : (
			<EmptyState title="No matching drafts">Adjust the workload or status filter.</EmptyState>
		);
	}

	const activation = loaded.data?.activation;
	return (
		<section className="page-view findings-page" aria-label="Detection rules">
			<header className="page-header">
				<div>
					<span className="eyebrow">Detection</span>
					<h1>Rules</h1>
					<p>
						Deployment rules drafted by the AI author. Drafts run in shadow mode, recording matches
						only, until an operator approves them.
					</p>
				</div>
			</header>
			<MetricCards label="Rule summary" metrics={metrics} />
			<div className="toolrow panel catalog-controls">
				<div className="collection-tabs" role="tablist" aria-label="Rule records">
					{tabs.map(item => (
						<button
							className={tab === item.id ? 'active' : undefined}
							type="button"
							role="tab"
							aria-selected={tab === item.id}
							key={item.id}
							onClick={() => navigate(`rules/${item.id}`)}
						>
							{item.title}
						</button>
					))}
				</div>
				<label className="search">
					<span aria-hidden="true">⌕</span>
					<input
						type="search"
						placeholder="Workload"
						autoComplete="off"
						aria-label="Filter by workload"
						value={search}
						onChange={event => setSearch(event.target.value)}
					/>
				</label>
				{tab === 'drafts' ? (
					<label>
						Status
						<select value={draftFilter} onChange={event => setDraftFilter(event.target.value)}>
							{draftFilters.map(item => (
								<option value={item.value} key={item.value}>
									{item.title}
								</option>
							))}
						</select>
					</label>
				) : null}
			</div>
			<div className="findings-layout panel">
				<section
					className="finding-list-shell"
					aria-label={tab === 'active' ? 'Loaded rule list' : 'Draft list'}
				>
					<div className="panel-head">
						<div>
							<h2>{tab === 'active' ? 'Loaded rules' : 'Authoring drafts'}</h2>
							<p>
								{tab === 'active'
									? `${loadedRules.length} rule${loadedRules.length === 1 ? '' : 's'}${
											activation
												? ` · ruleset ${activation.rulesetId} revision ${activation.revision}`
												: ''
										}`
									: `${shownDrafts.length} draft${shownDrafts.length === 1 ? '' : 's'}`}
							</p>
						</div>
					</div>
					<div className="finding-list">{rows}</div>
				</section>
				<article className="finding-detail">{detailPane}</article>
			</div>
		</section>
	);
}
