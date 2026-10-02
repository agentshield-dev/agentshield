// Hash routing (#view/part/...): navigation stays in the browser, so the server serves the UI as
// static files with no per-route fallback.
import { useMemo, useSyncExternalStore } from 'react';

const routeChange = 'agentshield:route-change';

export const views = ['overview', 'findings', 'rules', 'catalog', 'graph'] as const;
export type View = (typeof views)[number];

export interface Route {
	view: View;
	parts: string[];
}

function decode(part: string): string {
	try {
		return decodeURIComponent(part);
	} catch {
		return part;
	}
}

function isView(value: string | undefined): value is View {
	return views.some(view => view === value);
}

export function parseRoute(hash: string): Route {
	const parts = hash.slice(1).split('/').filter(Boolean).map(decode);
	return { view: isView(parts[0]) ? parts[0] : 'overview', parts };
}

function subscribe(onChange: () => void): () => void {
	window.addEventListener('hashchange', onChange);
	window.addEventListener('popstate', onChange);
	window.addEventListener(routeChange, onChange);
	return () => {
		window.removeEventListener('hashchange', onChange);
		window.removeEventListener('popstate', onChange);
		window.removeEventListener(routeChange, onChange);
	};
}

export function useRoute(): Route {
	const hash = useSyncExternalStore(subscribe, () => window.location.hash);
	return useMemo(() => parseRoute(hash), [hash]);
}

// pushState does not fire hashchange, so subscribers are notified through a custom event.
export function navigate(hash: string): void {
	const next = hash.startsWith('#') ? hash : `#${hash}`;
	if (window.location.hash === next) return;
	window.history.pushState(null, '', next);
	window.dispatchEvent(new Event(routeChange));
}
