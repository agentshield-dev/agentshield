import { fileURLToPath, URL } from 'node:url';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
	publicDir: process.env.VITE_AGENTSHIELD_DEMO === '1' ? '.storybook/public' : 'public',
	plugins: [
		react(),
		{
			name: 'keep-dist-placeholder',
			generateBundle() {
				// emptyOutDir wipes the tracked placeholder that keeps Go's //go:embed all:dist valid.
				this.emitFile({ type: 'asset', fileName: '.gitkeep', source: '' });
			}
		}
	],
	resolve: {
		alias: {
			'@': fileURLToPath(new URL('./src', import.meta.url))
		}
	},
	build: {
		emptyOutDir: true,
		reportCompressedSize: false,
		sourcemap: false
	},
	server: {
		port: 5173,
		proxy: {
			'/api': process.env.AGENTSHIELD_API ?? 'http://127.0.0.1:8088'
		}
	}
});
