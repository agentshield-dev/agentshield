import {
	BookOpen,
	House,
	Menu,
	Network,
	RefreshCw,
	ShieldCheck,
	TriangleAlert
} from 'lucide-react';
import { type ReactNode, useCallback, useEffect, useRef, useState } from 'react';
import { flushSync } from 'react-dom';
import { type ApiState, useApi } from '@/api/client';
import type { GraphRecord } from '@/api/types';
import agentShieldLogo from '@/assets/agentshield-logo-light.svg';
import { ThemeToggle } from '@/components/ThemeToggle';
import { GraphProvider } from '@/lib/graph-context';
import { navigate, useRoute, type View } from '@/lib/route';
import { Catalog } from '@/views/Catalog';
import { Explorer } from '@/views/Explorer';
import { Findings } from '@/views/Findings';
import { Overview } from '@/views/Overview';
import { Rules } from '@/views/Rules';

const titles: Record<View, string> = {
	overview: 'Overview',
	findings: 'Findings',
	rules: 'Rules',
	catalog: 'Catalog',
	graph: 'Environment graph'
};

// Reports whether the live stream is reconnecting, and refreshes when it announces a new graph.
// The browser does not poll: the server pushes a 'graph' event with the new digest over SSE (it
// polls PostgreSQL for a cheap revision per open stream), and only a digest that differs from the
// loaded graph triggers a refetch. EventSource ignores the server's keepalive comments and
// reconnects on its own.
function useLiveUpdates(loaded: ApiState<GraphRecord>, onChange: () => void): boolean {
	const [reconnecting, setReconnecting] = useState(false);
	const latest = useRef(loaded);
	useEffect(() => {
		latest.current = loaded;
	});

	useEffect(() => {
		const events = new EventSource('/api/v1/events');
		events.addEventListener('open', () => setReconnecting(false));
		events.addEventListener('error', () => setReconnecting(true));
		events.addEventListener('graph', event => {
			const current = latest.current;
			// An initial load in flight already fetches the newest graph.
			if (current.status === 'loading' && !current.data) return;
			const update = JSON.parse((event as MessageEvent<string>).data) as { sha256?: string };
			if (update.sha256 !== current.data?.sha256) onChange();
		});
		return () => events.close();
	}, [onChange]);

	return reconnecting;
}

function NavLink({
	view,
	current,
	icon,
	children
}: {
	view: View;
	current: View;
	icon: ReactNode;
	children: ReactNode;
}) {
	const active = view === current;
	return (
		<a
			href={`#${view}`}
			className={active ? 'active' : undefined}
			aria-current={active ? 'page' : undefined}
		>
			<span className="nav-icon" aria-hidden="true">
				{icon}
			</span>
			{children}
		</a>
	);
}

// Routes plain left clicks on same-page hash links through navigate() so the view updates in the
// same frame. Modified clicks, new-tab targets, downloads, and other pages keep browser behavior.
function followRoute(event: MouseEvent) {
	if (
		event.defaultPrevented ||
		event.button !== 0 ||
		event.metaKey ||
		event.ctrlKey ||
		event.shiftKey ||
		event.altKey
	) {
		return;
	}
	const anchor = event.target instanceof Element ? event.target.closest('a') : null;
	if (!anchor || anchor.target || anchor.hasAttribute('download')) return;
	const destination = new URL(anchor.href, window.location.href);
	if (
		destination.origin !== window.location.origin ||
		destination.pathname !== window.location.pathname ||
		destination.search !== window.location.search ||
		!destination.hash
	) {
		return;
	}
	event.preventDefault();
	flushSync(() => navigate(destination.hash));
}

export function App() {
	useEffect(() => {
		document.addEventListener('click', followRoute);
		return () => document.removeEventListener('click', followRoute);
	}, []);

	const route = useRoute();
	const { view, parts } = route;
	const [navOpen, setNavOpen] = useState(false);
	const [shownRoute, setShownRoute] = useState(route);
	// Bumping a key refetches: viewKey for the per-view APIs, graphKey for the shared graph.
	const [viewKey, setViewKey] = useState(0);
	const [graphKey, setGraphKey] = useState(0);
	const [pendingEntity, setPendingEntity] = useState<string | null>(null);
	const [findingTotal, setFindingTotal] = useState(0);
	const loaded = useApi<GraphRecord>('/api/v1/graph', graphKey);
	const [draftsToReview, setDraftsToReview] = useState(0);

	const refreshAll = useCallback(() => {
		setViewKey(key => key + 1);
		setGraphKey(key => key + 1);
	}, []);
	const reconnecting = useLiveUpdates(loaded, refreshAll);

	// Navigating closes the mobile menu.
	if (route !== shownRoute) {
		setShownRoute(route);
		setNavOpen(false);
	}

	// Manual reload refetches the full graph only on the graph view, where it is the main content.
	function reload() {
		setViewKey(key => key + 1);
		if (view === 'graph') setGraphKey(key => key + 1);
	}

	function viewGraph(id: string) {
		setPendingEntity(id);
		navigate('graph');
	}

	const syncStatus = loaded.error
		? 'Graph unavailable'
		: loaded.data
			? 'Graph synchronized'
			: 'Connecting';
	const liveLabel = reconnecting ? 'Reconnecting' : loaded.error ? 'API error' : 'Live';

	return (
		<div className={navOpen ? 'app-shell nav-open' : 'app-shell'}>
			<aside className="sidebar" aria-label="Primary navigation">
				<div className="sidebar-content">
					<a className="brand" href="#overview" aria-label="AgentShield overview">
						<img src={agentShieldLogo} alt="" />
					</a>
					<div className="workspace-switcher">
						<span className="workspace-icon">AS</span>
						<span>
							<strong>Current environment</strong>
							<small>Live graph</small>
						</span>
					</div>
					<nav>
						<span className="nav-label">Understand</span>
						<NavLink view="overview" current={view} icon={<House size={16} />}>
							<span>Overview</span>
						</NavLink>
						<NavLink view="graph" current={view} icon={<Network size={16} />}>
							<span>Environment graph</span>
						</NavLink>
						<NavLink view="catalog" current={view} icon={<BookOpen size={16} />}>
							<span>Catalog</span>
						</NavLink>
						<span className="nav-label nav-label-spaced">Investigate</span>
						<NavLink view="findings" current={view} icon={<TriangleAlert size={16} />}>
							<span>Findings</span>
							{findingTotal ? <b>{findingTotal.toLocaleString()}</b> : null}
						</NavLink>
						<NavLink view="rules" current={view} icon={<ShieldCheck size={16} />}>
							<span>Rules</span>
							{draftsToReview ? <b>{draftsToReview.toLocaleString()}</b> : null}
						</NavLink>
					</nav>
					<div className="system-status">
						<span className="status-dot" />
						<div>
							<strong>Graph service</strong>
							<small>{syncStatus}</small>
						</div>
					</div>
					<div className="environment">
						<span /> agentshield <b>v0</b>
					</div>
				</div>
			</aside>

			<main className="main-shell">
				<header className="topbar">
					<div className="topbar-left">
						<button
							className="bare-button mobile-menu"
							type="button"
							aria-label="Toggle navigation"
							onClick={() => setNavOpen(open => !open)}
						>
							<Menu size={18} aria-hidden="true" />
						</button>
						<div className="breadcrumb">
							<span>agentshield</span>
							<i>/</i>
							<strong>{titles[view]}</strong>
						</div>
					</div>
					<div className="top-actions">
						<span className="live-status">
							<i />
							<span>{liveLabel}</span>
						</span>
						<ThemeToggle />
						<button
							className="bare-button"
							type="button"
							aria-label="Refresh current view"
							title="Refresh current view"
							onClick={reload}
						>
							<RefreshCw size={16} aria-hidden="true" />
						</button>
						<span className="avatar" aria-hidden="true">
							AS
						</span>
					</div>
				</header>

				<div className="content">
					<GraphProvider record={loaded.data}>
						<Overview active={view === 'overview'} refresh={viewKey} />
						<Findings
							active={view === 'findings'}
							refresh={viewKey}
							selectedID={parts[0] === 'findings' ? parts[1] : undefined}
							onTotal={setFindingTotal}
							onViewGraph={viewGraph}
						/>
						<Rules
							active={view === 'rules'}
							refresh={viewKey}
							parts={parts}
							onAwaitingReview={setDraftsToReview}
							onViewGraph={viewGraph}
						/>
						<Catalog
							active={view === 'catalog'}
							refresh={viewKey}
							parts={parts}
							onViewGraph={viewGraph}
						/>
						<Explorer
							active={view === 'graph'}
							loaded={loaded}
							reconnecting={reconnecting}
							pendingEntity={pendingEntity}
							onPendingHandled={() => setPendingEntity(null)}
						/>
					</GraphProvider>
				</div>
			</main>
		</div>
	);
}
