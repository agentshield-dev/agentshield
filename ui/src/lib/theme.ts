export type Theme = 'light' | 'dark';

export const themeStorageKey = 'agentshield-theme';

export function preferredTheme(): Theme {
	try {
		const stored = localStorage.getItem(themeStorageKey);
		if (stored === 'light' || stored === 'dark') return stored;
	} catch {}
	return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export function applyTheme(theme: Theme) {
	document.documentElement.dataset.theme = theme;
}

export function saveTheme(theme: Theme) {
	try {
		localStorage.setItem(themeStorageKey, theme);
	} catch {}
}
