import type { Meta, StoryObj } from '@storybook/react-vite';
import { expect, within } from 'storybook/test';
import { MetricCards } from '@/components/MetricCards';

const meta = {
	title: 'Components/MetricCards',
	component: MetricCards,
	args: {
		label: 'Environment summary',
		metrics: [
			['Graph resources', 45],
			['Relationships', 101],
			['Sources needing attention', 2]
		]
	}
} satisfies Meta<typeof MetricCards>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
	play: async ({ canvasElement }) => {
		const canvas = within(canvasElement);
		await expect(canvas.getByRole('region', { name: 'Environment summary' })).toBeVisible();
		await expect(canvas.getByText('Relationships').closest('article')).toHaveTextContent('101');
	}
};

export const LargeNumbers: Story = {
	args: {
		metrics: [
			['Graph resources', 1284903],
			['Relationships', 9120441],
			['Sources needing attention', 0]
		]
	}
};
