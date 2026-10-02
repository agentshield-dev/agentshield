import type { Preview } from '@storybook/react-vite';
import { mswLoader } from 'msw-storybook-addon/csf3';
import { backend, handlers } from '../mocks/handlers';
import '../src/styles.css';

const preview: Preview = {
	loaders: [mswLoader()],
	beforeEach: () => {
		backend.reset();
		// The app picks its view from the URL hash; replaceState avoids a hashchange on a mounted app.
		window.history.replaceState(null, '', '#overview');
	},
	parameters: { layout: 'fullscreen', msw: handlers }
};

export default preview;
