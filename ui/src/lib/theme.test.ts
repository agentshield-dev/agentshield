import { afterEach, describe, expect, it, vi } from 'vitest';
import { preferredTheme, saveTheme, themeStorageKey } from './theme';

afterEach(() => vi.unstubAllGlobals());

function environment(stored: string | null, dark: boolean) {
	const storage = { getItem: vi.fn(() => stored), setItem: vi.fn() };
	vi.stubGlobal('localStorage', storage);
	vi.stubGlobal('window', { matchMedia: () => ({ matches: dark }) });
	return storage;
}

describe('theme preference', () => {
	it('uses the system preference without a saved choice', () => {
		environment(null, true);
		expect(preferredTheme()).toBe('dark');
		environment(null, false);
		expect(preferredTheme()).toBe('light');
	});

	it('respects an explicit choice over the system preference', () => {
		environment('light', true);
		expect(preferredTheme()).toBe('light');
		environment('dark', false);
		expect(preferredTheme()).toBe('dark');
	});

	it('ignores invalid stored preferences', () => {
		environment('invalid', true);
		expect(preferredTheme()).toBe('dark');
	});

	it('saves an explicit choice', () => {
		const storage = environment(null, false);
		saveTheme('dark');
		expect(storage.setItem).toHaveBeenCalledWith(themeStorageKey, 'dark');
	});

	it('keeps working when storage is unavailable', () => {
		const storage = environment(null, true);
		storage.getItem.mockImplementation(() => {
			throw new Error('Storage blocked');
		});
		storage.setItem.mockImplementation(() => {
			throw new Error('Storage blocked');
		});
		expect(preferredTheme()).toBe('dark');
		expect(() => saveTheme('light')).not.toThrow();
	});
});
