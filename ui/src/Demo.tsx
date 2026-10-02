import { setupWorker } from 'msw/browser';
import { useState } from 'react';
import { App } from '@/App';
import { navigate } from '@/lib/route';
import { backend, handlers } from '../mocks/handlers';
import { demoScenario, demoScenarios } from '../mocks/scenarios';

const worker = setupWorker(...handlers);

export async function startDemo(): Promise<void> {
	backend.reset();
	backend.configure({ settleMs: 1200 });
	backend.replaceFindings([]);
	window.history.replaceState(null, '', '#findings');
	await worker.start({ onUnhandledFrame: 'bypass' });
}

export function Demo() {
	const [scenarioId, setScenarioId] = useState(demoScenarios[0]?.id ?? '');
	const scenario = demoScenario(scenarioId);

	const trigger = () => {
		backend.replaceFindings([scenario.finding]);
		navigate(`#findings/${encodeURIComponent(scenario.finding.id)}`);
		requestAnimationFrame(() => window.scrollTo(0, 0));
	};

	const reset = () => {
		backend.replaceFindings([]);
		navigate('#findings');
		requestAnimationFrame(() => window.scrollTo(0, 0));
	};

	return (
		<div className="demo-shell">
			<header className="demo-toolbar">
				<div className="demo-copy">
					<strong>Simulated playground</strong>
					<span>No cluster, database, or model calls</span>
				</div>
				<div className="demo-controls">
					<label>
						<span>Scenario</span>
						<select value={scenarioId} onChange={event => setScenarioId(event.target.value)}>
							{demoScenarios.map(item => (
								<option key={item.id} value={item.id}>
									{item.name}
								</option>
							))}
						</select>
					</label>
					<button className="button primary" type="button" onClick={trigger}>
						Trigger observation
					</button>
					<button className="button secondary" type="button" onClick={reset}>
						Reset
					</button>
				</div>
			</header>
			<p className="demo-description" aria-live="polite">
				{scenario.description}
			</p>
			<App />
		</div>
	);
}
