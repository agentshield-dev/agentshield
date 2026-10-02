import type { Finding } from '@/api/types';
import { finding } from './dataset';

export interface DemoScenario {
	id: string;
	name: string;
	description: string;
	finding: Finding;
}

export const demoScenarios: readonly DemoScenario[] = [
	{
		id: 'catalog-ingress',
		name: 'Unprotected catalog service',
		description: 'Detect an exposed catalog workload and apply ingress isolation.',
		finding: finding('catalog-no-netpol')
	},
	{
		id: 'cart-ingress',
		name: 'Unprotected cart service',
		description: 'Detect two exposed cart replicas and review their proposed isolation.',
		finding: finding('cart-no-netpol')
	}
];

export function demoScenario(id: string): DemoScenario {
	const scenario = demoScenarios.find(item => item.id === id);
	if (!scenario) throw new Error(`unknown demo scenario ${id}`);
	return scenario;
}
