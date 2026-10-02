import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { ApiState } from '@/api/client';
import type { GraphRecord, Relationship, Resource } from '@/api/types';
import { GraphCanvas } from '@/components/GraphCanvas';
import { Inspector } from '@/components/Inspector';
import { useGraph } from '@/lib/graph-context';
import {
	emptyLayout,
	fitTransform,
	layoutGraph,
	readableTransform,
	type Selection,
	type Transform,
	zoomTransform
} from '@/lib/layout';
import { label, list, namespace, unique } from '@/lib/model';

const OVERVIEW_PAGE_SIZE = 24;

interface Filters {
	search: string;
	kind: string;
	scope: string;
	predicate: string;
}

const noFilters: Filters = { search: '', kind: '', scope: '', predicate: '' };

interface ExplorerProps {
	active: boolean;
	loaded: ApiState<GraphRecord>;
	reconnecting: boolean;
	pendingEntity: string | null;
	onPendingHandled(): void;
}

// Resources listed before a node is chosen. A predicate filter keeps only resources that sit on
// a relationship with that predicate whose both ends also pass the other filters.
function overviewResources(
	resources: readonly Resource[],
	relationships: readonly Relationship[],
	filters: Filters
): Resource[] {
	const query = filters.search.trim().toLowerCase();
	const matched = resources.filter(resource => {
		const searchable =
			`${label(resource)} ${resource.id} ${resource.kind} ${namespace(resource)} ${JSON.stringify(resource.identity || {})}`.toLowerCase();
		return (
			(!query || searchable.includes(query)) &&
			(!filters.kind || (resource.kind || 'unknown') === filters.kind) &&
			(!filters.scope || namespace(resource) === filters.scope)
		);
	});
	if (!filters.predicate) return matched;
	const matchedIDs = new Set(matched.map(resource => resource.id));
	const endpointIDs = new Set<string>();
	for (const relation of relationships) {
		if ((relation.predicate || 'unknown') !== filters.predicate) continue;
		if (!matchedIDs.has(relation.subjectId) || !matchedIDs.has(relation.objectId)) continue;
		endpointIDs.add(relation.subjectId);
		endpointIDs.add(relation.objectId);
	}
	return matched.filter(resource => endpointIDs.has(resource.id));
}

export function Explorer({
	active,
	loaded,
	reconnecting,
	pendingEntity,
	onPendingHandled
}: ExplorerProps) {
	const graph = useGraph();
	const { record } = graph;
	const [root, setRoot] = useState<string | null>(null);
	const [selected, setSelected] = useState<Selection | null>(null);
	const [inspectorOpen, setInspectorOpen] = useState(false);
	const [overviewPage, setOverviewPage] = useState(0);
	const [filters, setFilters] = useState(noFilters);
	const [showLabels, setShowLabels] = useState(false);
	const [transform, setTransform] = useState<Transform>({ x: 20, y: 20, scale: 1 });
	const [reframe, setReframe] = useState(0);
	const svg = useRef<SVGSVGElement>(null);
	const neighborhood = root !== null;

	function clear() {
		setRoot(null);
		setSelected(null);
		setInspectorOpen(false);
	}

	// When a live update replaces the graph, keep the open neighborhood and selection pointing at
	// the new objects, or clear them if the root resource is gone.
	const [shownRecord, setShownRecord] = useState(record);

	const resources = list(record?.snapshot.resources);
	const relationships = list(record?.snapshot.relationships);
	if (record !== shownRecord) {
		setShownRecord(record);
		if (root !== null) {
			const nextRoot = resources.find(item => item.id === root);
			if (!nextRoot) {
				clear();
			} else {
				setSelected(current => {
					if (current?.type === 'relationship') {
						const next = relationships.find(item => item.id === current.item.id);
						if (next) return { type: 'relationship', item: next };
					}
					return { type: 'resource', item: nextRoot };
				});
			}
		}
	}
	const kinds = useMemo(() => unique(resources.map(item => item.kind || 'unknown')), [resources]);
	const scopes = useMemo(() => unique(resources.map(namespace)), [resources]);
	const predicates = useMemo(
		() => unique(relationships.map(item => item.predicate || 'unknown')),
		[relationships]
	);
	// Drop filter values that no longer exist in the current graph instead of showing nothing.
	const effective: Filters = {
		search: filters.search,
		kind: kinds.includes(filters.kind) ? filters.kind : '',
		scope: scopes.includes(filters.scope) ? filters.scope : '',
		predicate: predicates.includes(filters.predicate) ? filters.predicate : ''
	};

	// The canvas draws only the selected root and its direct neighbors, which keeps layout and
	// label placement small regardless of graph size.
	const shown = useMemo(() => {
		if (root === null) return { resources: [], relationships: [] };
		const ids = new Set([root]);
		for (const relation of relationships) {
			if (relation.subjectId === root || relation.objectId === root) {
				ids.add(relation.subjectId);
				ids.add(relation.objectId);
			}
		}
		return {
			resources: resources.filter(item => ids.has(item.id)),
			relationships: relationships.filter(item => ids.has(item.subjectId) && ids.has(item.objectId))
		};
	}, [root, resources, relationships]);
	const layout = useMemo(
		() => (neighborhood ? layoutGraph(shown.resources, shown.relationships) : emptyLayout),
		[neighborhood, shown]
	);

	const matched = useMemo(
		() =>
			neighborhood
				? []
				: overviewResources(resources, relationships, {
						search: effective.search,
						kind: effective.kind,
						scope: effective.scope,
						predicate: effective.predicate
					}).sort((left, right) => {
						const key = (item: Resource) =>
							`${item.kind}\u0000${namespace(item)}\u0000${label(item)}`;
						return key(left).localeCompare(key(right));
					}),
		[
			neighborhood,
			resources,
			relationships,
			effective.search,
			effective.kind,
			effective.scope,
			effective.predicate
		]
	);
	const pageCount = Math.max(1, Math.ceil(matched.length / OVERVIEW_PAGE_SIZE));
	const page = Math.min(overviewPage, pageCount - 1);
	const pageStart = page * OVERVIEW_PAGE_SIZE;
	const pageResources = matched.slice(pageStart, pageStart + OVERVIEW_PAGE_SIZE);

	const select = useCallback((selection: Selection) => {
		setSelected(selection);
		if (selection.type === 'resource') {
			setRoot(selection.item.id);
			setReframe(count => count + 1);
		}
		setInspectorOpen(true);
	}, []);

	const viewport = () => svg.current?.getBoundingClientRect();
	const fitToView = () => {
		const rect = viewport();
		if (rect) setTransform(fitTransform(rect, layout));
	};
	const zoom = useCallback((factor: number, centerX?: number, centerY?: number) => {
		const rect = svg.current?.getBoundingClientRect();
		if (!rect) return;
		setTransform(current =>
			zoomTransform(current, factor, centerX ?? rect.width / 2, centerY ?? rect.height / 2)
		);
	}, []);

	// biome-ignore lint/correctness/useExhaustiveDependencies: only reframe when requested
	useLayoutEffect(() => {
		const rect = viewport();
		if (!neighborhood || !rect) return;
		const focus =
			selected?.type === 'resource' ? (layout.positions.get(selected.item.id) ?? null) : null;
		setTransform(readableTransform(rect, layout, focus));
	}, [reframe]);

	useEffect(() => {
		if (!neighborhood) return;
		const onResize = () => setReframe(count => count + 1);
		window.addEventListener('resize', onResize);
		return () => window.removeEventListener('resize', onResize);
	}, [neighborhood]);

	// biome-ignore lint/correctness/useExhaustiveDependencies: only on entering the view; clearing pendingEntity must not refit
	useEffect(() => {
		if (!active) return;
		if (pendingEntity) {
			const resource = graph.resource(pendingEntity);
			onPendingHandled();
			if (resource) select({ type: 'resource', item: resource });
		} else if (neighborhood) {
			fitToView();
		}
	}, [active]);

	function setFilter(change: Partial<Filters>) {
		setFilters({ ...filters, ...change });
		setOverviewPage(0);
	}

	let message = '';
	if (!record) {
		message = loaded.error
			? reconnecting
				? 'Waiting for graph updates…'
				: `Graph unavailable. ${loaded.error.message}`
			: 'Loading current graph…';
	} else if (neighborhood && !shown.resources.length) {
		message = 'No resources match the current filters.';
	}

	const visibleCount = !record
		? ''
		: neighborhood
			? `${shown.resources.length.toLocaleString()} / ${resources.length.toLocaleString()} resources`
			: matched.length
				? `${pageStart + 1}–${pageStart + pageResources.length} of ${matched.length.toLocaleString()} resources`
				: '0 resources';

	const metrics = record
		? ([
				['Resources', resources.length],
				['Relations', relationships.length],
				['Facets', list(record.snapshot.facets).length],
				['Telemetry', list(record.snapshot.telemetry).length]
			] as const)
		: [];

	return (
		<section className="page-view graph-page" aria-label="Environment graph" hidden={!active}>
			<header className="page-header graph-heading">
				<div>
					<span className="eyebrow">Knowledge layer</span>
					<h1>Environment graph</h1>
					<p>Inspect current resources, relationships, provenance, and evidence.</p>
				</div>
				<div className="leg-controls">
					<label htmlFor="leg-select">Revision</label>
					<select id="leg-select" aria-label="Graph revision" defaultValue="current">
						<option value="current">Current graph</option>
					</select>
					<label className="check">
						<input type="checkbox" disabled /> Previous
					</label>
				</div>
			</header>
			<section className="summary panel" aria-label="Snapshot summary">
				<div className="snapshot-id">
					<strong>
						{record ? 'Current graph' : loaded.error ? 'Graph unavailable' : 'No snapshot'}
					</strong>
					<span>
						{record
							? record.generatedAt
							: loaded.error
								? loaded.error.message
								: 'Waiting for graph state'}
					</span>
				</div>
				<dl className="metrics">
					{metrics.map(([name, value]) => (
						<div key={name}>
							<dt>{name}</dt>
							<dd>{value.toLocaleString()}</dd>
						</div>
					))}
				</dl>
				<div className="delta" aria-live="polite">
					{record ? <span>Comparison off</span> : null}
				</div>
			</section>
			<section className="toolrow panel" aria-label="Graph controls">
				<label className="search">
					<span aria-hidden="true">⌕</span>
					<input
						type="search"
						placeholder="Search resources"
						autoComplete="off"
						aria-label="Search resources"
						value={filters.search}
						onChange={event => setFilter({ search: event.target.value })}
					/>
				</label>
				<label>
					Kind
					<select
						value={effective.kind}
						onChange={event => {
							setFilter({ kind: event.target.value });
							setReframe(count => count + 1);
						}}
					>
						<option value="">All kinds</option>
						{kinds.map(kind => (
							<option value={kind} key={kind}>
								{kind}
							</option>
						))}
					</select>
				</label>
				<label>
					Namespace
					<select
						value={effective.scope}
						onChange={event => {
							setFilter({ scope: event.target.value });
							setReframe(count => count + 1);
						}}
					>
						<option value="">All namespaces</option>
						{scopes.map(scope => (
							<option value={scope} key={scope}>
								{scope}
							</option>
						))}
					</select>
				</label>
				<label>
					Predicate
					<select
						value={effective.predicate}
						onChange={event => {
							setFilter({ predicate: event.target.value });
							setReframe(count => count + 1);
						}}
					>
						<option value="">All predicates</option>
						{predicates.map(predicate => (
							<option value={predicate} key={predicate}>
								{predicate}
							</option>
						))}
					</select>
				</label>
				{neighborhood ? (
					<>
						<label className="check">
							<input
								type="checkbox"
								checked={showLabels}
								onChange={event => setShowLabels(event.target.checked)}
							/>{' '}
							Labels
						</label>
						<button
							className="page-button"
							type="button"
							aria-label="Back to all resources"
							onClick={() => {
								clear();
								setReframe(count => count + 1);
							}}
						>
							←
						</button>
					</>
				) : null}
				<span className="graph-mode">{neighborhood ? 'Neighborhood' : 'Resource overview'}</span>
				<span className="visible-count">{visibleCount}</span>
				{neighborhood ? (
					<div className="zoom-controls" role="toolbar" aria-label="View controls">
						<button
							className="page-button"
							type="button"
							aria-label="Zoom out"
							onClick={() => zoom(0.8)}
						>
							−
						</button>
						<button
							className="page-button"
							type="button"
							aria-label="Fit graph"
							onClick={fitToView}
						>
							⊙
						</button>
						<button
							className="page-button"
							type="button"
							aria-label="Zoom in"
							onClick={() => zoom(1.25)}
						>
							+
						</button>
						<output aria-live="polite">{Math.round(transform.scale * 100)}%</output>
					</div>
				) : null}
			</section>
			<section className="explorer panel">
				<div className="graph-shell">
					{neighborhood ? (
						<GraphCanvas
							svg={svg}
							resources={shown.resources}
							relationships={shown.relationships}
							layout={layout}
							selected={selected}
							showLabels={showLabels}
							transform={transform}
							onPan={setTransform}
							onZoom={zoom}
							onSelect={select}
						/>
					) : (
						<div className="resource-overview-shell">
							<section className="resource-overview" aria-label="Resources">
								{pageResources.map(resource => (
									<button
										className="resource-item"
										type="button"
										key={resource.id}
										onClick={() => select({ type: 'resource', item: resource })}
									>
										<strong>{label(resource)}</strong>
										<span>{namespace(resource)}</span>
										<small>{resource.kind || 'unknown'}</small>
									</button>
								))}
								{record && !matched.length ? (
									<p className="overview-empty">No resources match the current filters.</p>
								) : null}
							</section>
							<nav className="overview-pagination" aria-label="Resource pages">
								<button
									className="page-button"
									type="button"
									aria-label="Previous resource page"
									disabled={page === 0}
									onClick={() => setOverviewPage(Math.max(0, page - 1))}
								>
									←
								</button>
								<output aria-live="polite">
									Page {page + 1} of {pageCount}
								</output>
								<button
									className="page-button"
									type="button"
									aria-label="Next resource page"
									disabled={page >= pageCount - 1}
									onClick={() => setOverviewPage(page + 1)}
								>
									→
								</button>
							</nav>
						</div>
					)}
					{message ? <div className="graph-state">{message}</div> : null}
					{neighborhood ? (
						<div className="legend">
							<span>
								<i className="dot resource-dot" />
								resource
							</span>
							<span>
								<i className="line" />
								relationship
							</span>
							<span>
								<i className="dot changed-dot" />
								added
							</span>
						</div>
					) : null}
				</div>
				<Inspector
					selection={selected}
					open={inspectorOpen}
					onClose={() => setInspectorOpen(false)}
				/>
			</section>
		</section>
	);
}
