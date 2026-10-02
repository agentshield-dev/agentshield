import { Moon, Sun } from 'lucide-react';
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { applyTheme, preferredTheme, saveTheme, themeStorageKey } from '@/lib/theme';

export function ThemeToggle() {
	const [theme, setTheme] = useState(preferredTheme);
	const explicitChoice = useRef(false);
	const dark = theme === 'dark';
	const label = dark ? 'Switch to light mode' : 'Switch to dark mode';

	useLayoutEffect(() => applyTheme(theme), [theme]);

	useEffect(() => {
		const system = window.matchMedia('(prefers-color-scheme: dark)');
		const onSystemChange = () => {
			if (!explicitChoice.current) setTheme(preferredTheme());
		};
		const onStorage = (event: StorageEvent) => {
			if (event.key !== null && event.key !== themeStorageKey) return;
			explicitChoice.current = false;
			setTheme(preferredTheme());
		};
		system.addEventListener('change', onSystemChange);
		window.addEventListener('storage', onStorage);
		return () => {
			system.removeEventListener('change', onSystemChange);
			window.removeEventListener('storage', onStorage);
		};
	}, []);

	function toggle() {
		const next = dark ? 'light' : 'dark';
		explicitChoice.current = true;
		saveTheme(next);
		setTheme(next);
	}

	return (
		<button
			className="bare-button theme-toggle"
			type="button"
			aria-label={label}
			title={label}
			onClick={toggle}
		>
			{dark ? <Sun size={20} aria-hidden="true" /> : <Moon size={20} aria-hidden="true" />}
		</button>
	);
}
