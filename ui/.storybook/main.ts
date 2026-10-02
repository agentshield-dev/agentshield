import type { StorybookConfig } from '@storybook/react-vite';

const config: StorybookConfig = {
	stories: ['../stories/**/*.stories.@(ts|tsx)'],
	addons: ['msw-storybook-addon', '@storybook/addon-vitest'],
	framework: { name: '@storybook/react-vite', options: { strictMode: true } },
	staticDirs: ['./public'],
	core: { disableTelemetry: true, disableWhatsNewNotifications: true },
	features: { sidebarOnboardingChecklist: false },
	// Requests must reach the fake backend, never the dev server's /api proxy to a real service.
	viteFinal: config => ({ ...config, server: { ...config.server, proxy: {} } })
};

export default config;
