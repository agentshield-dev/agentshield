import type { Meta, StoryObj } from '@storybook/react-vite';
import { expect, userEvent, waitFor, within } from 'storybook/test';
import { App } from '@/App';
import { label, list } from '@/lib/model';
import { dataset } from '../mocks/dataset';
import { backend } from '../mocks/handlers';
import { deploymentIds } from '../mocks/rules';

const meta = {
	title: 'Rules',
	component: App,
	parameters: { layout: 'fullscreen' }
} satisfies Meta<typeof App>;

export default meta;
type Story = StoryObj<typeof meta>;

// Drafts poll every few seconds while they are being authored.
const wait = { timeout: 10_000 };

const at = (hash: string): Pick<Story, 'beforeEach'> => ({
	beforeEach: () => {
		backend.configure({ authorMs: 200 });
		window.history.replaceState(null, '', hash);
	}
});

// The seed gives the first Deployment approved rules, the next two drafts awaiting review, the
// fourth a retrying draft, the sixth a failed draft, and the rest queued drafts. Draft IDs follow
// that order.
const workloads = deploymentIds();
const name = (id: string) =>
	label(list(dataset.snapshot.resources).find(resource => resource.id === id) ?? { id });

export const LoadedRules: Story = {
	...at('#rules'),
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		const rules = within(await canvas.findByRole('region', { name: 'Loaded rule list' }, wait));
		// Two approved rules for the first Deployment, and shadow rules for the two pending drafts.
		await waitFor(() => expect(rules.getAllByRole('button')).toHaveLength(7), wait);
		await expect(rules.getAllByText('active')).toHaveLength(2);
		await expect(rules.getAllByText('shadow')).toHaveLength(5);
		const summary = within(canvas.getByRole('region', { name: 'Rule summary' }));
		await expect(summary.getByText('Drafts awaiting review').closest('article')).toHaveTextContent(
			'2'
		);
		await expect(canvas.getByText("process_class == 'shell'", { selector: 'pre' })).toBeVisible();
		const navigation = within(canvas.getByRole('navigation'));
		await waitFor(
			() => expect(navigation.getByRole('link', { name: /Rules/ })).toHaveTextContent('2'),
			wait
		);
	}
};

export const ApproveDraft: Story = {
	...at('#rules/drafts/2'),
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await canvas.findByRole('heading', { name: name(workloads[1]), level: 2 }, wait);
		await userEvent.click(await canvas.findByRole('button', { name: 'Approve' }, wait));
		const dialog = within(
			await within(document.body).findByRole('dialog', { name: 'Approve rules' })
		);
		await expect(dialog.getByRole('heading', { name: 'Activate 3 rules' })).toBeVisible();
		await userEvent.click(dialog.getByRole('button', { name: 'Approve and activate' }));
		await canvas.findByText('Approved; the rules now run in active mode.', {}, wait);
		await canvas.findByText('approved', { selector: '.finding-title .badge' }, wait);

		await userEvent.click(canvas.getByRole('tab', { name: 'Loaded rules' }));
		const rules = within(await canvas.findByRole('region', { name: 'Loaded rule list' }, wait));
		await waitFor(() => expect(rules.getAllByText('active')).toHaveLength(5), wait);
	}
};

export const RejectDraft: Story = {
	...at('#rules/drafts/3'),
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await canvas.findByRole('heading', { name: name(workloads[2]), level: 2 }, wait);
		await userEvent.click(await canvas.findByRole('button', { name: 'Reject' }, wait));
		await canvas.findByText('Rejected; the rules are no longer loaded.', {}, wait);
		await canvas.findByText('rejected', { selector: '.finding-title .badge' }, wait);
		await expect(canvas.getByRole('button', { name: 'Approve' })).toBeEnabled();
	}
};

export const RegenerateDraft: Story = {
	...at('#rules/drafts/1'),
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await canvas.findByRole('heading', { name: name(workloads[0]), level: 2 }, wait);
		await userEvent.click(await canvas.findByRole('button', { name: 'Regenerate' }, wait));
		await canvas.findByText('Regeneration requested.', {}, wait);
		await canvas.findByText('awaiting review', { selector: '.finding-title .badge' }, wait);
		await expect(canvas.getByText(/^Requested by api\/web-ui$/)).toBeVisible();
		await expect(canvas.getAllByText(/^add_rule · /)).toHaveLength(3);
	}
};

export const RuleReviewDisabled: Story = {
	...at('#rules/drafts/2'),
	beforeEach: () => {
		backend.configure({ ruleReview: false });
		window.history.replaceState(null, '', '#rules/drafts/2');
	},
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await userEvent.click(await canvas.findByRole('button', { name: 'Approve' }, wait));
		const dialog = within(
			await within(document.body).findByRole('dialog', { name: 'Approve rules' })
		);
		await userEvent.click(dialog.getByRole('button', { name: 'Approve and activate' }));
		await dialog.findByText(/rule review is disabled on a non-loopback listener/, {}, wait);
	}
};

export const WorkloadInspector: Story = {
	...at('#graph'),
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		const target = name(workloads[0]);
		const [namespace] = target.split('/');
		await userEvent.click(
			await canvas.findByRole(
				'button',
				{ name: new RegExp(`^${target}\\s*${namespace}\\s*kubernetes/deployment`) },
				wait
			)
		);
		const details = within(await canvas.findByRole('complementary', { name: 'Selection details' }));
		const rules = within(await details.findByRole('region', { name: 'Detection rules' }, wait));
		await rules.findByRole('heading', { name: 'Detection rules · 2' }, wait);
		await userEvent.click(rules.getByRole('button', { name: 'Regenerate rules' }));
		await rules.findByText('Regenerating draft #1.', {}, wait);
		await rules.findByText(/· awaiting review$/, {}, wait);
		await userEvent.click(rules.getByRole('button', { name: 'Open draft' }));
		await canvas.findByRole('heading', { name: target, level: 2 }, wait);
	}
};

export const AuthorQueuedDraftNow: Story = {
	...at('#rules/drafts/5'),
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await canvas.findByRole('heading', { name: name(workloads[4]), level: 2 }, wait);
		await canvas.findByText(/Waiting for the baseline window/, {}, wait);
		await userEvent.click(canvas.getByRole('button', { name: 'Author now' }));
		await canvas.findByText('Authoring requested.', {}, wait);
		await canvas.findByText('awaiting review', { selector: '.finding-title .badge' }, wait);
		await expect(canvas.getByRole('button', { name: 'Regenerate' })).toBeEnabled();
	}
};

export const RetryFailedDraft: Story = {
	...at('#rules/drafts/6'),
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await canvas.findByRole('heading', { name: name(workloads[5]), level: 2 }, wait);
		await canvas.findByText('failed', { selector: '.finding-title .badge' }, wait);
		await canvas.findByText('Authoring gave up.', {}, wait);
		await canvas.findByText(/The worker stopped after 8 attempts/, {}, wait);
		await userEvent.click(canvas.getByRole('button', { name: 'Author now' }));
		await canvas.findByText('Authoring requested.', {}, wait);
		await canvas.findByText('awaiting review', { selector: '.finding-title .badge' }, wait);
	}
};
