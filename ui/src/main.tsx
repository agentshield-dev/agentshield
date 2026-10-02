import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from '@/App';
import { applyTheme, preferredTheme } from '@/lib/theme';
import '@/styles.css';

applyTheme(preferredTheme());

if (!window.location.hash) window.history.replaceState(null, '', '#overview');

const container = document.getElementById('root');
if (container) {
	if (import.meta.env.VITE_AGENTSHIELD_DEMO === '1') {
		void import('@/Demo').then(async ({ Demo, startDemo }) => {
			await startDemo();
			createRoot(container).render(
				<StrictMode>
					<Demo />
				</StrictMode>
			);
		});
	} else {
		createRoot(container).render(
			<StrictMode>
				<App />
			</StrictMode>
		);
	}
}
