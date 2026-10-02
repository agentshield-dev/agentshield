import { type FormEvent, type ReactNode, useMemo, useState } from 'react';
import { useApi } from '@/api/client';
import type {
	RelationshipDetailResponse,
	RelationshipsResponse,
	ResourceDetailResponse,
	ResourcesResponse
} from '@/api/types';
import { RelationshipRecord, ResourceRecord } from '@/components/CatalogRecords';
import { EmptyState } from '@/components/EmptyState';
import { Pagination } from '@/components/Pagination';
import { useGraph } from '@/lib/graph-context';
import { initials, label, list, namespace, unique } from '@/lib/model';
import { useCursorPager } from '@/lib/pager';
import { navigate } from '@/lib/route';

type CatalogType = 'resources' | 'relationships';

// The list endpoint matching the selected type returns one of these; the other field is absent.
type CatalogPage = Partial<ResourcesResponse & RelationshipsResponse>;

interface Filters {
	search: string;
	filter: string;
}

interface Row {
	id: string;
	title: string;
	meta: string;
	glyph: string;
}

const catalogTypes: readonly { id: CatalogType; title: string }[] = [
	{ id: 'resources', title: 'Resources' },
	{ id: 'relationships', title: 'Relationships' }
];

const noFilters: Filters = { search: '', filter: '' };

function isCatalogType(value: string | undefined): value is CatalogType {
	return value === 'resources' || value === 'relationships';
}

function catalogURL(type: CatalogType, filters: Filters, cursor: string): string {
	const query = new URLSearchParams({ limit: '25' });
	if (filters.search.trim()) query.set('q', filters.search.trim());
	if (filters.filter) query.set(type === 'resources' ? 'kind' : 'predicate', filters.filter);
	if (cursor) query.set('cursor', cursor);
	return `/api/v1/${type}?${query}`;
}

interface CatalogProps {
	active: boolean;
	refresh: number;
	parts: readonly string[];
	onViewGraph(id: string): void;
}

export function Catalog({ active, refresh, parts, onViewGraph }: CatalogProps) {
	const graph = useGraph();
	const [type, setType] = useState<CatalogType>('resources');
	const [draft, setDraft] = useState(noFilters);
	const [applied, setApplied] = useState(noFilters);
	const pager = useCursorPager();

	// The route owns the record type; switching it restarts paging and drops the kind/predicate filter.
	const requested = active ? parts[1] || type : type;
	const routeType = isCatalogType(requested) ? requested : 'resources';
	if (routeType !== type) {
		setType(routeType);
		setDraft(current => ({ ...current, filter: '' }));
		setApplied(current => ({ ...current, filter: '' }));
		pager.reset();
	}

	const selectedID = active ? parts[2] : undefined;
	const page = useApi<CatalogPage>(
		active ? catalogURL(type, applied, pager.cursor) : null,
		refresh
	);
	const { data, error } = page;

	const snapshot = graph.record?.snapshot;
	const filterOptions = useMemo(
		() =>
			type === 'resources'
				? unique(list(snapshot?.resources).map(item => item.kind))
				: unique(list(snapshot?.relationships).map(item => item.predicate)),
		[type, snapshot]
	);

	const rows: Row[] =
		type === 'resources'
			? list(data?.resources).map(item => ({
					id: item.id,
					title: label(item),
					meta: `${item.kind} · ${namespace(item)}`,
					glyph: initials(item.kind, '')
				}))
			: list(data?.relationships).map(item => ({
					id: item.id,
					title: `${graph.name(item.subjectId)} → ${graph.name(item.objectId)}`,
					meta: `${item.predicate} · ${item.qualifier || 'unqualified'}`,
					glyph: initials(item.predicate, 'RE')
				}));

	// The detail pane stays on the previous page's first record until the next page arrives.
	const shownPage = data ?? page.latest;
	const firstID =
		type === 'resources'
			? list(shownPage?.resources)[0]?.id
			: list(shownPage?.relationships)[0]?.id;
	const detailID = selectedID ?? firstID;
	const detailPath = detailID ? `/api/v1/${type}/${encodeURIComponent(detailID)}` : null;
	const resourceDetail = useApi<ResourceDetailResponse>(
		active && type === 'resources' ? detailPath : null,
		refresh
	);
	const relationshipDetail = useApi<RelationshipDetailResponse>(
		active && type === 'relationships' ? detailPath : null,
		refresh
	);
	const detail = type === 'resources' ? resourceDetail : relationshipDetail;

	function search(event: FormEvent) {
		event.preventDefault();
		setApplied(draft);
		pager.reset();
	}

	let detailPane: ReactNode;
	if (data && !rows.length) {
		detailPane = <EmptyState title="No catalog record selected" />;
	} else if (detail.error) {
		detailPane = (
			<EmptyState title="Record unavailable" error>
				{detail.error.message}
			</EmptyState>
		);
	} else if (resourceDetail.data && type === 'resources') {
		detailPane = <ResourceRecord response={resourceDetail.data} onViewGraph={onViewGraph} />;
	} else if (relationshipDetail.data && type === 'relationships') {
		detailPane = <RelationshipRecord response={relationshipDetail.data} />;
	} else if (detailID) {
		detailPane = <EmptyState title="Loading record…" />;
	} else {
		detailPane = (
			<EmptyState title="Select a catalog record">
				Identity, provenance, evidence, and graph relationships will appear here.
			</EmptyState>
		);
	}

	return (
		<section className="page-view catalog-page" aria-label="Environment catalog" hidden={!active}>
			<header className="page-header">
				<div>
					<span className="eyebrow">Queryable graph</span>
					<h1>Catalog</h1>
					<p>
						Browse current resources and relationships with their stable identities, provenance,
						evidence, and linked findings.
					</p>
				</div>
			</header>
			<form
				className="toolrow panel catalog-controls"
				aria-label="Filter catalog"
				onSubmit={search}
			>
				<div className="collection-tabs" role="tablist" aria-label="Catalog records">
					{catalogTypes.map(item => (
						<button
							className={type === item.id ? 'active' : undefined}
							type="button"
							role="tab"
							aria-selected={type === item.id}
							key={item.id}
							onClick={() => navigate(`catalog/${item.id}`)}
						>
							{item.title}
						</button>
					))}
				</div>
				<label className="search">
					<span aria-hidden="true">⌕</span>
					<input
						type="search"
						placeholder="Search catalog"
						autoComplete="off"
						aria-label="Search catalog"
						value={draft.search}
						onChange={event => setDraft({ ...draft, search: event.target.value })}
					/>
				</label>
				<label>
					Filter
					<select
						value={filterOptions.includes(draft.filter) ? draft.filter : ''}
						onChange={event => setDraft({ ...draft, filter: event.target.value })}
					>
						<option value="">{type === 'resources' ? 'All kinds' : 'All predicates'}</option>
						{filterOptions.map(option => (
							<option value={option} key={option}>
								{option}
							</option>
						))}
					</select>
				</label>
				<button className="button primary" type="submit">
					Search
				</button>
			</form>
			<div className="catalog-layout panel">
				<section className="catalog-list-shell">
					<div className="panel-head">
						<div>
							<h2>{type === 'resources' ? 'Resources' : 'Relationships'}</h2>
							<p>
								{error
									? 'Query failed'
									: data
										? `${rows.length.toLocaleString()} record${rows.length === 1 ? '' : 's'} on this page`
										: 'Loading catalog'}
							</p>
						</div>
					</div>
					<div className="catalog-list">
						{error ? (
							<EmptyState title="Catalog unavailable" error>
								{error.message}
							</EmptyState>
						) : !data ? (
							<EmptyState title="Loading catalog…" />
						) : rows.length ? (
							rows.map(row => (
								<a
									className={`catalog-row${selectedID === row.id ? ' active' : ''}`}
									href={`#catalog/${type}/${encodeURIComponent(row.id)}`}
									key={row.id}
								>
									<span className="asset-glyph">{row.glyph}</span>
									<span>
										<strong>{row.title}</strong>
										<small>{row.meta}</small>
									</span>
									<span aria-hidden="true">→</span>
								</a>
							))
						) : (
							<EmptyState title="No matching records">
								Adjust the catalog search or filter.
							</EmptyState>
						)}
					</div>
					<Pagination label="Catalog pages" subject="catalog" pager={pager} state={page} />
				</section>
				<article className="catalog-detail">{detailPane}</article>
			</div>
		</section>
	);
}
