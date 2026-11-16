import type { Meta, StoryObj } from '@storybook/react-vite';
import { expect, within } from 'storybook/test';
import { EmptyState } from '@/components/EmptyState';

const meta = {
	title: 'Components/EmptyState',
	component: EmptyState,
	args: {
		title: 'No active findings',
		children: 'No active findings were reported for the current graph.'
	}
} satisfies Meta<typeof EmptyState>;

export default meta;
type Story = StoryObj<typeof meta>;

export const Default: Story = {
	play: async ({ canvasElement }) => {
		await expect(within(canvasElement).getByText('No active findings')).toBeVisible();
	}
};

export const Failure: Story = {
	args: {
		title: 'Findings unavailable',
		error: true,
		children: 'query findings: database is unavailable'
	}
};

export const TitleOnly: Story = {
	args: { title: 'Loading findings…', children: undefined }
};
