import {
	BookOpen,
	House,
	Menu,
	Network,
	RefreshCw,
	ShieldCheck,
	TriangleAlert,
	X
} from 'lucide-react';
import { type ReactNode, useCallback, useEffect, useRef, useState } from 'react';
import { flushSync } from 'react-dom';
import { type ApiState, useApi } from '@/api/client';
import type { GraphRecord, PluginsResponse } from '@/api/types';
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

type LiveState = 'connecting' | 'live' | 'reconnecting';

// Reports the live stream state, and refreshes when it announces a new graph.
function useLiveUpdates(loaded: ApiState<GraphRecord>, onChange: () => void): LiveState {
	const [state, setState] = useState<LiveState>('connecting');
	const latest = useRef(loaded);
	useEffect(() => {
		latest.current = loaded;
	});

	useEffect(() => {
		const events = new EventSource('/api/v1/events');
		events.addEventListener('open', () => setState('live'));
		events.addEventListener('error', () => setState('reconnecting'));
		events.addEventListener('graph', event => {
			const current = latest.current;
			// An initial load in flight already fetches the newest graph.
			if (current.status === 'loading' && !current.data) return;
			const update = JSON.parse((event as MessageEvent<string>).data) as { revision?: number };
			if (update.revision !== current.data?.revision) onChange();
		});
		return () => events.close();
	}, [onChange]);

	return state;
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

export function App({ demo = false }: { demo?: boolean }) {
	useEffect(() => {
		document.addEventListener('click', followRoute);
		return () => document.removeEventListener('click', followRoute);
	}, []);

	const route = useRoute();
	const { view, parts } = route;
	const [navOpen, setNavOpen] = useState(false);
	const menuButton = useRef<HTMLButtonElement>(null);
	const closeButton = useRef<HTMLButtonElement>(null);
	const restoreMenuFocus = useRef(false);
	const closeNavigation = useCallback(() => {
		restoreMenuFocus.current = true;
		setNavOpen(false);
	}, []);
	const [shownRoute, setShownRoute] = useState(route);
	// Bumping a key refetches: viewKey for the per-view APIs, graphKey for the shared graph.
	const [viewKey, setViewKey] = useState(0);
	const [graphKey, setGraphKey] = useState(0);
	const [pendingEntity, setPendingEntity] = useState<string | null>(null);
	const [findingTotal, setFindingTotal] = useState(0);
	const loaded = useApi<GraphRecord>('/api/v1/graph', graphKey);
	const plugins = useApi<PluginsResponse>('/api/v1/plugins');
	const [draftsToReview, setDraftsToReview] = useState(0);

	const refreshAll = useCallback(() => {
		setViewKey(key => key + 1);
		setGraphKey(key => key + 1);
	}, []);
	const liveState = useLiveUpdates(loaded, refreshAll);
	const reconnecting = liveState === 'reconnecting';
	useEffect(() => {
		const viewport = window.matchMedia('(max-width: 1040px)');
		const closeDesktopDrawer = (event: MediaQueryListEvent) => {
			if (!event.matches) setNavOpen(false);
		};
		viewport.addEventListener('change', closeDesktopDrawer);
		return () => viewport.removeEventListener('change', closeDesktopDrawer);
	}, []);
	useEffect(() => {
		if (navOpen || !restoreMenuFocus.current) return;
		restoreMenuFocus.current = false;
		menuButton.current?.focus();
	}, [navOpen]);
	useEffect(() => {
		if (!navOpen) return;
		const demoToolbar = document.querySelector<HTMLElement>('.demo-toolbar');
		document.documentElement.classList.add('nav-modal-open');
		demoToolbar?.setAttribute('inert', '');
		const focusFrame = requestAnimationFrame(() => closeButton.current?.focus());
		const close = (event: KeyboardEvent) => {
			if (event.key !== 'Escape') return;
			closeNavigation();
		};
		window.addEventListener('keydown', close);
		return () => {
			cancelAnimationFrame(focusFrame);
			document.documentElement.classList.remove('nav-modal-open');
			demoToolbar?.removeAttribute('inert');
			window.removeEventListener('keydown', close);
		};
	}, [navOpen, closeNavigation]);

	useEffect(() => {
		if (route === shownRoute) return;
		setShownRoute(route);
		if (!navOpen) return;
		closeNavigation();
	}, [route, shownRoute, navOpen, closeNavigation]);

	// Manual reload refetches the full graph only on the graph view, where it is the main content.
	function reload() {
		setViewKey(key => key + 1);
		if (view === 'graph') setGraphKey(key => key + 1);
	}

	function viewGraph(id: string) {
		setPendingEntity(id);
		navigate('graph');
	}

	const syncStatus = demo
		? loaded.error
			? 'Sample graph unavailable'
			: reconnecting
				? loaded.data
					? 'Sample graph ready; updates reconnecting'
					: 'Loading sample graph; updates reconnecting'
				: liveState === 'connecting'
					? loaded.data
						? 'Sample graph loaded; updates connecting'
						: 'Loading sample graph'
					: loaded.data
						? 'Sample graph ready'
						: 'Loading sample graph'
		: loaded.error
			? 'Graph unavailable'
			: reconnecting
				? loaded.data
					? 'Graph loaded; updates reconnecting'
					: 'Connecting to graph updates'
				: liveState === 'connecting'
					? loaded.data
						? 'Graph loaded; updates connecting'
						: 'Connecting to graph updates'
					: loaded.data
						? 'Graph synchronized'
						: 'Connecting';
	const graphStatus = loaded.error
		? 'error'
		: liveState !== 'live'
			? 'loading'
			: loaded.data
				? 'healthy'
				: 'loading';
	const liveStatus = loaded.error
		? 'error'
		: reconnecting
			? 'reconnecting'
			: liveState === 'live'
				? 'healthy'
				: 'loading';
	const liveLabel = demo
		? loaded.error
			? 'Demo error'
			: reconnecting
				? 'Demo reconnecting'
				: liveState === 'live'
					? 'Demo ready'
					: 'Connecting demo'
		: loaded.error
			? 'Connection issue'
			: reconnecting
				? 'Reconnecting'
				: liveState === 'live'
					? 'Live'
					: 'Connecting';

	return (
		<div className={navOpen ? 'app-shell nav-open' : 'app-shell'}>
			<aside id="primary-navigation" className="sidebar" aria-label="Primary navigation">
				<div className="sidebar-content">
					<button
						ref={closeButton}
						className="bare-button sidebar-close"
						type="button"
						aria-label="Close navigation"
						onClick={closeNavigation}
					>
						<X size={18} aria-hidden="true" />
					</button>
					<a className="brand" href="#overview" aria-label="AgentShield overview">
						<img src={agentShieldLogo} alt="" />
					</a>
					<div className="workspace-switcher">
						<span className="workspace-icon">AS</span>
						<span>
							<strong>{demo ? 'Sample environment' : 'Current environment'}</strong>
							<small>{demo ? 'Simulated graph' : 'Live graph'}</small>
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
						<span className={`status-dot ${graphStatus}`} aria-hidden="true" />
						<div>
							<strong>{demo ? 'Demo data' : 'Graph service'}</strong>
							<small>{syncStatus}</small>
						</div>
					</div>
				</div>
			</aside>
			<button
				className="nav-backdrop"
				type="button"
				tabIndex={-1}
				aria-label="Dismiss navigation"
				onClick={closeNavigation}
			/>

			<main className="main-shell" inert={navOpen}>
				<header className="topbar">
					<div className="topbar-left">
						<button
							ref={menuButton}
							className="bare-button mobile-menu"
							type="button"
							aria-label="Toggle navigation"
							aria-controls="primary-navigation"
							aria-expanded={navOpen}
							onClick={() => setNavOpen(open => !open)}
						>
							<Menu size={18} aria-hidden="true" />
						</button>
						<div className="breadcrumb">
							<strong>{titles[view]}</strong>
						</div>
					</div>
					<div className="top-actions">
						<span className={`live-status ${liveStatus}`} role="status" aria-live="polite">
							<i aria-hidden="true" />
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
					</div>
				</header>

				<div className="content">
					<GraphProvider
						record={loaded.data}
						plugins={plugins.data?.plugins ?? plugins.latest?.plugins}
					>
						<Overview active={view === 'overview'} refresh={viewKey} demo={demo} />
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
