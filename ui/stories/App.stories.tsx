import type { Meta, StoryObj } from '@storybook/react-vite';
import { HttpResponse, http } from 'msw/http';
import { sse } from 'msw/sse';
import { expect, userEvent, waitFor, within } from 'storybook/test';
import { App } from '@/App';
import { list } from '@/lib/model';
import { themeStorageKey } from '@/lib/theme';
import { dataset, finding, minutesAfter } from '../mocks/dataset';
import { backend, withOverrides } from '../mocks/handlers';
import { demoScenario } from '../mocks/scenarios';

const meta = {
	title: 'App',
	component: App,
	parameters: { layout: 'fullscreen' }
} satisfies Meta<typeof App>;

export default meta;
type Story = StoryObj<typeof meta>;

const wait = { timeout: 5000 };

// The app picks its view from the URL hash, so a story starts a route before it renders.
const at = (hash: string): Pick<Story, 'beforeEach'> => ({
	beforeEach: () => {
		window.history.replaceState(null, '', hash);
	}
});

const deepLink = (route: string, id: string) => `#${route}/${encodeURIComponent(id)}`;
const resources = list(dataset.snapshot.resources);
const count = (kind: string) => resources.filter(resource => resource.kind === kind).length;
const rows = (root: HTMLElement, selector: string) => root.querySelectorAll(selector);

export const Overview: Story = {
	...at('#overview'),
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		const summary = within(await canvas.findByRole('region', { name: 'Environment summary' }));
		const unhealthy = dataset.contributions.filter(
			item => !item.ready || item.sourceHealth !== 'healthy'
		);
		const expected: [string, number][] = [
			['Graph resources', resources.length],
			['Relationships', list(dataset.snapshot.relationships).length],
			['Sources needing attention', unhealthy.length]
		];
		for (const [name, value] of expected) {
			await waitFor(
				() => expect(summary.getByText(name).closest('article')).toHaveTextContent(String(value)),
				wait
			);
		}
		await waitFor(() => expect(rows(canvasElement, '.overview-row')).toHaveLength(5), wait);
		await expect(rows(canvasElement, '.source-row')).toHaveLength(dataset.contributions.length);
		for (const health of ['healthy', 'degraded', 'stale']) {
			await expect(canvas.getAllByText(health, { selector: '.badge' }).length).toBeGreaterThan(0);
		}
	}
};

let overviewFailures = 0;

export const OverviewRecoversFromTransientFailure: Story = {
	...at('#overview'),
	beforeEach: () => {
		window.history.replaceState(null, '', '#overview');
		overviewFailures = 0;
	},
	parameters: {
		msw: withOverrides(
			http.get('/api/v1/overview', () => {
				if (overviewFailures++ === 0) {
					return HttpResponse.json(
						{ error: 'create graph manifest: internal server error; see the server log' },
						{ status: 500 }
					);
				}
				return HttpResponse.json(backend.overview());
			})
		)
	},
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await canvas.findAllByText('Overview unavailable', {}, wait);
		const summary = within(canvas.getByRole('region', { name: 'Environment summary' }));
		await waitFor(
			() =>
				expect(summary.getByText('Graph resources').closest('article')).toHaveTextContent(
					String(resources.length)
				),
			{ timeout: 5000 }
		);
	}
};

export const Navigation: Story = {
	...at('#overview'),
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await canvas.findByRole('heading', { name: 'Security overview' }, wait);
		const navigation = within(canvas.getByRole('navigation'));
		navigation.getByRole('link', { name: /Catalog/ }).click();
		expect(canvas.queryByRole('heading', { name: 'Catalog' })).not.toBeNull();
	}
};

export const ThemeToggle: Story = {
	...at('#overview'),
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		const root = document.documentElement;
		const initial = root.dataset.theme;
		const next = initial === 'dark' ? 'light' : 'dark';
		try {
			await userEvent.click(canvas.getByRole('button', { name: `Switch to ${next} mode` }));
			await expect(root).toHaveAttribute('data-theme', next);
			await expect(localStorage.getItem(themeStorageKey)).toBe(next);
			await expect(getComputedStyle(root).getPropertyValue('--bg').trim()).toBe(
				next === 'dark' ? '#030712' : '#f8f9fb'
			);
			await expect(
				getComputedStyle(canvas.getByLabelText('Primary navigation')).backgroundColor
			).toBe(next === 'dark' ? 'rgb(16, 20, 31)' : 'rgb(255, 255, 255)');
			await expect(canvas.getByRole('button', { name: `Switch to ${initial} mode` })).toBeVisible();
			await userEvent.click(canvas.getByRole('button', { name: `Switch to ${initial} mode` }));
			await expect(root).toHaveAttribute('data-theme', initial);
		} finally {
			localStorage.removeItem(themeStorageKey);
		}
	}
};

export const DarkMode: Story = {
	beforeEach: () => {
		window.history.replaceState(null, '', '#overview');
		localStorage.setItem(themeStorageKey, 'dark');
		return () => localStorage.removeItem(themeStorageKey);
	},
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await expect(document.documentElement).toHaveAttribute('data-theme', 'dark');
		await expect(canvas.getByRole('button', { name: 'Switch to light mode' })).toBeVisible();
		await canvas.findByRole('region', { name: 'Environment summary' });
	}
};

export const Findings: Story = {
	...at('#findings'),
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		const active = dataset.findings.filter(item => item.status === 'active');
		await waitFor(() => expect(rows(canvasElement, '.finding-row')).toHaveLength(20), wait);
		await userEvent.click(canvas.getByRole('button', { name: 'Next findings page' }));
		await waitFor(
			() => expect(rows(canvasElement, '.finding-row')).toHaveLength(active.length - 20),
			wait
		);

		await userEvent.click(canvas.getByRole('button', { name: 'Previous findings page' }));
		await userEvent.selectOptions(canvas.getByLabelText('Severity'), 'high');
		await userEvent.click(canvas.getByRole('button', { name: 'Apply filters' }));
		const high = active.filter(item => item.severity === 'high').length;
		await waitFor(() => expect(rows(canvasElement, '.finding-row')).toHaveLength(high), wait);

		await userEvent.click(canvas.getByRole('button', { name: 'Clear' }));
		await waitFor(() => expect(rows(canvasElement, '.finding-row')).toHaveLength(20), wait);
	}
};

const withProposals = finding('cart-no-netpol');

export const FindingWithRemediations: Story = {
	...at(deepLink('findings', withProposals.id)),
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await canvas.findByRole('heading', { name: withProposals.summary, level: 2 }, wait);
		await waitFor(() => expect(rows(canvasElement, '.remediation-item')).toHaveLength(2), wait);
		const [select] = await canvas.findAllByLabelText(
			'Action for network.declare-ingress-isolation',
			{},
			wait
		);
		await expect(select).toHaveTextContent('kubernetes · network-policy/v1 · demo-cluster');
		await expect(select).toHaveTextContent('cilium · cilium-network-policy/v1 · demo-cluster');
	}
};

const approvable = demoScenario('catalog-ingress').finding;

export const ApproveRemediation: Story = {
	beforeEach: () => {
		window.history.replaceState(null, '', deepLink('findings', approvable.id));
		backend.configure({ settleMs: 300 });
	},
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		const dialog = within(document.body);
		// Approval ends in a graph change, which the app ignores until its first graph load lands.
		await canvas.findByText('Graph synchronized', {}, wait);
		await userEvent.click(await canvas.findByRole('button', { name: 'Prepare' }, wait));

		const sheet = within(await dialog.findByRole('dialog', {}, wait));
		await expect(sheet.getByText('Explicit approval')).toBeVisible();
		await expect(sheet.getByText('network.declare-ingress-isolation')).toBeVisible();
		await userEvent.click(sheet.getByRole('button', { name: 'Approve and apply' }));
		const item = within(canvasElement.querySelector('.remediation-item') as HTMLElement);
		await waitFor(
			() => expect(item.getByRole('status')).toHaveTextContent('Applied and verified.'),
			wait
		);
		await expect(item.queryByRole('button', { name: 'Prepare' })).toBeNull();
		await expect(item.getByText('Applied', { exact: true })).toBeVisible();

		// Discovery then observes the new policy and the finding is invalidated by the graph change.
		await canvas.findByText('Historical finding.', { exact: false }, wait);
		await expect(
			canvas.getByText('Actions are unavailable for an invalidated finding.')
		).toBeVisible();
	}
};

const historical = finding('route-plain-http');

export const InvalidatedFinding: Story = {
	...at(deepLink('findings', historical.id)),
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await canvas.findByRole('heading', { name: historical.summary, level: 2 }, wait);
		await expect(canvas.getByText('Historical finding.', { exact: false })).toBeVisible();
		await expect(
			canvas.getByText('Actions are unavailable for an invalidated finding.')
		).toBeVisible();
	}
};

const ruleMatch = finding('orders-rule-match');

export const DetectionRuleFinding: Story = {
	...at(deepLink('findings', ruleMatch.id)),
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await canvas.findByRole('heading', { name: ruleMatch.summary, level: 2 }, wait);
		await expect(canvas.getByText('Detection rule', { selector: 'dd' })).toBeVisible();
		await expect(canvas.getByText(`${ruleMatch.detectionRuleId} r1`)).toBeVisible();
		await expect(canvas.queryByText('Uncertainty')).toBeNull();
	}
};

export const Catalog: Story = {
	...at('#catalog'),
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await waitFor(() => expect(rows(canvasElement, '.catalog-row')).toHaveLength(25), wait);
		await canvas.findByRole('heading', { name: /Related findings/ }, wait);

		await userEvent.type(canvas.getByLabelText('Search catalog'), 'orders');
		await userEvent.click(canvas.getByRole('button', { name: 'Search' }));
		await waitFor(() => {
			const shown = [...rows(canvasElement, '.catalog-row')];
			expect(shown.length).toBeGreaterThan(0);
			expect(shown.length).toBeLessThan(25);
			for (const row of shown) expect(row.textContent).toContain('orders');
		}, wait);

		await userEvent.clear(canvas.getByLabelText('Search catalog'));
		await canvas.findByRole('option', { name: 'kubernetes/pod' }, wait);
		await userEvent.selectOptions(canvas.getByLabelText('Filter'), 'kubernetes/pod');
		await userEvent.click(canvas.getByRole('button', { name: 'Search' }));
		await waitFor(
			() => expect(rows(canvasElement, '.catalog-row')).toHaveLength(count('kubernetes/pod')),
			wait
		);
	}
};

export const CatalogRelationships: Story = {
	...at('#catalog/relationships'),
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await waitFor(() => expect(rows(canvasElement, '.catalog-row')).toHaveLength(25), wait);
		await expect(canvas.getByRole('tab', { name: 'Relationships' })).toHaveAttribute(
			'aria-selected',
			'true'
		);
		await userEvent.click(canvas.getByRole('button', { name: 'Next catalog page' }));
		await waitFor(() => expect(canvas.getByText('Page 2')).toBeVisible(), wait);
		await canvas.findByRole('heading', { name: 'Provenance' }, wait);
	}
};

const frontend = dataset.world.services.get('shop/frontend');

export const CatalogResource: Story = {
	...at(deepLink('catalog/resources', frontend?.id ?? '')),
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await canvas.findByRole('heading', { name: 'shop/frontend', level: 2 }, wait);
		await expect(await canvas.findByText('istio · demo-cluster')).toBeVisible();
		await expect(canvas.getByText('kubernetes · demo-cluster')).toBeVisible();
		await userEvent.click(canvas.getByRole('button', { name: 'View graph' }));
		await canvas.findByRole('img', { name: 'Selected resource neighborhood' }, wait);
	}
};

export const Graph: Story = {
	...at('#graph'),
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await userEvent.click(
			await canvas.findByRole(
				'button',
				{ name: /^shop\/orders\s*shop\s*kubernetes\/deployment/ },
				wait
			)
		);
		const graph = await canvas.findByRole('img', { name: 'Selected resource neighborhood' }, wait);
		await expect(graph.querySelectorAll('[role="button"]').length).toBeGreaterThan(2);
		const details = within(await canvas.findByRole('complementary', { name: 'Selection details' }));
		await expect(details.getByRole('heading', { name: 'shop/orders', level: 2 })).toBeVisible();
		backend.publish();
		await canvas.findByText(minutesAfter(2), {}, wait);
		await expect(canvas.getByRole('img', { name: 'Selected resource neighborhood' })).toBeVisible();

		await userEvent.click(canvas.getByRole('button', { name: 'Back to all resources' }));
		await canvas.findByRole('region', { name: 'Resources' }, wait);
	}
};

export const LiveUpdate: Story = {
	...at('#findings'),
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		const active = dataset.findings.filter(item => item.status === 'active').length;
		const navigation = within(
			await canvas.findByRole('complementary', { name: 'Primary navigation' })
		);
		await waitFor(
			() =>
				expect(navigation.getByRole('link', { name: /Findings/ })).toHaveTextContent(
					String(active)
				),
			wait
		);
		// The app ignores stream events until its first graph load lands, so raise the finding after.
		await navigation.findByText('Graph synchronized', {}, wait);

		const summary = 'shop/cart opened a first connection to export.partner-example.net.';
		backend.raiseFinding(summary);
		await canvas.findAllByText(summary, {}, wait);
		await waitFor(
			() =>
				expect(navigation.getByRole('link', { name: /Findings/ })).toHaveTextContent(
					String(active + 1)
				),
			wait
		);
	}
};

export const SlowNetwork: Story = {
	beforeEach: () => {
		window.history.replaceState(null, '', '#findings');
		backend.configure({ latencyMs: 1200 });
	},
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		const findings = within(await canvas.findByRole('region', { name: 'Security findings' }));
		await findings.findByText('Loading findings…');
		await waitFor(() => expect(rows(canvasElement, '.finding-row')).toHaveLength(20), {
			timeout: 8000
		});
	}
};

export const FreshInstall: Story = {
	...at('#overview'),
	beforeEach: () => {
		window.history.replaceState(null, '', '#overview');
		backend.configure({ materialized: false });
	},
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await canvas.findAllByText('Overview unavailable', {}, wait);
		await expect(
			canvas.getAllByText('load graph overview: graph is not materialized')
		).not.toHaveLength(0);
		const navigation = within(canvas.getByRole('complementary', { name: 'Primary navigation' }));
		await expect(await navigation.findByText('Graph unavailable', {}, wait)).toBeVisible();
		await expect(await canvas.findByText('API error', {}, wait)).toBeVisible();
	}
};

export const ApiFailure: Story = {
	...at('#findings'),
	parameters: {
		msw: withOverrides(
			...['graph', 'overview', 'findings'].map(path =>
				http.get(`/api/v1/${path}`, () =>
					HttpResponse.json(
						{ error: `query ${path}: internal server error; see the server log` },
						{ status: 500 }
					)
				)
			)
		)
	},
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await canvas.findByText('Findings unavailable', {}, wait);
		await expect(
			canvas.getByText('query findings: internal server error; see the server log')
		).toBeVisible();
		await expect(await canvas.findByText('API error', {}, wait)).toBeVisible();
	}
};

export const Reconnecting: Story = {
	...at('#overview'),
	parameters: {
		msw: withOverrides(
			sse<{ graph: string }>('/api/v1/events', ({ client }) => {
				client.error();
			})
		)
	},
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await canvas.findByText('Reconnecting', {}, wait);
		const navigation = within(canvas.getByRole('complementary', { name: 'Primary navigation' }));
		await expect(await navigation.findByText('Graph synchronized', {}, wait)).toBeVisible();
	}
};
