import type { Meta, StoryObj } from '@storybook/react-vite';
import { HttpResponse, http } from 'msw/http';
import { expect, userEvent, waitFor, within } from 'storybook/test';
import { RemediationItem } from '@/components/Remediation';
import { list } from '@/lib/model';
import { finding } from '../mocks/dataset';
import { backend, withOverrides } from '../mocks/handlers';

const isolation = finding('catalog-no-netpol');
const mutualTLS = finding('shop-permissive-mtls');
const routeDelivery = finding('gateway-mixed-listeners');

const meta = {
	title: 'Components/RemediationItem',
	component: RemediationItem,
	args: { finding: isolation, proposal: list(isolation.remediations)[0], active: true, refresh: 0 },
	decorators: [
		Story => (
			<section className="remediation-list">
				<Story />
			</section>
		)
	]
} satisfies Meta<typeof RemediationItem>;

export default meta;
type Story = StoryObj<typeof meta>;

const wait = { timeout: 5000 };

export const Executable: Story = {
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		const select = await canvas.findByLabelText(
			'Action for network.declare-ingress-isolation',
			{},
			wait
		);
		await expect(select).toHaveTextContent('kubernetes · network-policy/v1 · demo-cluster');
		await userEvent.click(canvas.getByRole('button', { name: 'Prepare' }));

		const dialog = within(await within(document.body).findByRole('dialog', {}, wait));
		await expect(dialog.queryByText('Action')).toBeNull();
		await expect(dialog.queryByText('Plan')).toBeNull();
		await expect(dialog.getByRole('region', { name: 'Change to apply' })).toBeVisible();
		await expect(dialog.getByText(/"kind": "NetworkPolicy"/)).toBeVisible();
		await userEvent.click(dialog.getByRole('button', { name: 'Cancel' }));
		await waitFor(() => expect(within(document.body).queryByRole('dialog')).toBeNull(), wait);
		await expect(canvas.getByRole('status')).toHaveTextContent('Prepared; approval pending.');
	}
};

export const MutualTLS: Story = {
	args: { finding: mutualTLS, proposal: list(mutualTLS.remediations)[0] },
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		const select = await canvas.findByLabelText(
			'Action for transport.require-mutual-tls',
			{},
			wait
		);
		await expect(select).toHaveTextContent('istio · peer-authentication/v1 · demo-cluster');
		await userEvent.click(canvas.getByRole('button', { name: 'Prepare' }));
		const dialog = within(await within(document.body).findByRole('dialog', {}, wait));
		await expect(dialog.getByRole('region', { name: 'Change to apply' })).toBeVisible();
		await expect(dialog.getByText(/"mode": "STRICT"/)).toBeVisible();
		await userEvent.click(dialog.getByRole('button', { name: 'Cancel' }));
	}
};

export const AdvisoryOnly: Story = {
	args: { finding: routeDelivery, proposal: list(routeDelivery.remediations)[0] },
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await canvas.findByLabelText('Action for gateway.prevent-route-delivery', {}, wait);
		await userEvent.click(canvas.getByRole('button', { name: 'Prepare' }));
		await waitFor(
			() =>
				expect(canvas.getByRole('status')).toHaveTextContent(
					'Review the route attachment and detach it through the owning gateway configuration.'
				),
			wait
		);
		await expect(within(document.body).queryByRole('dialog')).toBeNull();
	}
};

export const RemediationUnavailable: Story = {
	beforeEach: () => {
		backend.configure({ remediations: false });
	},
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await expect(
			await canvas.findByText(
				'enumerate remediation actions: live remediation is unavailable',
				{},
				wait
			)
		).toBeVisible();
	}
};

export const NoLiveAction: Story = {
	parameters: {
		msw: withOverrides(
			http.get('/api/v1/findings/:findingID/remediations/:proposalID/candidates', () =>
				HttpResponse.json({ candidates: null })
			)
		)
	},
	play: async ({ canvasElement }) => {
		await expect(
			await within(canvasElement).findByText('No live action available', {}, wait)
		).toBeVisible();
	}
};

export const PrepareFails: Story = {
	parameters: {
		msw: withOverrides(
			http.post('/api/v1/findings/:findingID/remediations/:proposalID/prepare', () =>
				HttpResponse.json(
					{ error: 'prepare remediation: target pod no longer exists' },
					{ status: 409 }
				)
			)
		)
	},
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await userEvent.click(await canvas.findByRole('button', { name: 'Prepare' }, wait));
		await waitFor(
			() =>
				expect(canvas.getByRole('status')).toHaveTextContent(
					'prepare remediation: target pod no longer exists'
				),
			wait
		);
	}
};
