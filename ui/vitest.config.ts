import { fileURLToPath, URL } from 'node:url';
import { storybookTest } from '@storybook/addon-vitest/vitest-plugin';
import react from '@vitejs/plugin-react';
import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

// The storybook project runs every story, including its play function, in headless Chromium
// against the fake backend. The unit project runs plain *.test.ts files under src in Node.
export default defineConfig({
	plugins: [react()],
	resolve: {
		alias: {
			'@': fileURLToPath(new URL('./src', import.meta.url))
		}
	},
	test: {
		projects: [
			{
				extends: true,
				test: { name: 'unit', environment: 'node', include: ['src/**/*.test.ts'] }
			},
			{
				extends: true,
				plugins: [
					storybookTest({ configDir: fileURLToPath(new URL('./.storybook', import.meta.url)) })
				],
				test: {
					name: 'storybook',
					browser: {
						enabled: true,
						headless: true,
						viewport: { width: 1280, height: 800 },
						provider: playwright({ contextOptions: { locale: 'en-US', timezoneId: 'UTC' } }),
						instances: [{ browser: 'chromium' }]
					}
				}
			}
		]
	}
});
