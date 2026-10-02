// Fetch helpers for the AgentShield HTTP API. URLs are relative because the UI is served by the same
// process and its Content-Security-Policy only allows same-origin requests. Errors carry the
// server's {"error": "..."} message so views can show it as is.
import { useEffect, useState } from 'react';

export type ApiStatus = 'idle' | 'loading' | 'success' | 'error';

export interface ApiState<T> {
	url: string | null;
	status: ApiStatus;
	data?: T;
	// Last successful response for any url, so surrounding panels can stay put while the next loads.
	latest?: T;
	error?: Error;
}

export function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

class HTTPError extends Error {
	constructor(
		message: string,
		readonly status: number
	) {
		super(message);
	}
}

async function parse<T>(response: Response): Promise<T> {
	const data: unknown = await response.json().catch(() => ({}));
	if (!response.ok) {
		const message =
			typeof data === 'object' && data !== null && 'error' in data && typeof data.error === 'string'
				? data.error
				: '';
		throw new HTTPError(message || `${response.status} ${response.statusText}`, response.status);
	}
	return data as T;
}

export async function fetchJSON<T>(url: string, signal?: AbortSignal): Promise<T> {
	return parse<T>(await fetch(url, { cache: 'no-store', signal }));
}

export async function postJSON<T>(url: string, body: unknown): Promise<T> {
	return parse<T>(
		await fetch(url, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body)
		})
	);
}

// Fetches url (skipped while null) and refetches when url or refresh changes. Data is kept across
// a refresh of the same url and dropped when the url changes.
export function useApi<T>(url: string | null, refresh = 0): ApiState<T> {
	const [state, setState] = useState<ApiState<T>>({ url: null, status: 'idle' });

	// biome-ignore lint/correctness/useExhaustiveDependencies: refresh only re-triggers the fetch
	useEffect(() => {
		if (url === null) return;
		const controller = new AbortController();
		let retry: number | undefined;
		let retryDelay = 1000;
		setState(current => ({
			url,
			status: 'loading',
			data: current.url === url ? current.data : undefined,
			latest: current.latest
		}));
		const load = () => {
			fetchJSON<T>(url, controller.signal).then(
				data => setState({ url, status: 'success', data, latest: data }),
				(error: unknown) => {
					if (controller.signal.aborted) return;
					setState(current => ({
						url,
						status: 'error',
						error: error instanceof Error ? error : new Error(String(error)),
						latest: current.latest
					}));
					// Network failures and 5xx may be transient (restart, 503 while a feature is
					// unavailable), so retry with capped backoff. A 4xx will not change on retry.
					if (!(error instanceof HTTPError) || error.status >= 500) {
						retry = window.setTimeout(load, retryDelay);
						retryDelay = Math.min(retryDelay * 2, 30_000);
					}
				}
			);
		};
		load();
		return () => {
			controller.abort();
			window.clearTimeout(retry);
		};
	}, [url, refresh]);

	if (state.url === url) return state;
	return { url, status: url === null ? 'idle' : 'loading', latest: state.latest };
}
