export function MetricCards({
	label,
	metrics
}: {
	label: string;
	metrics: readonly (readonly [name: string, value: number])[];
}) {
	return (
		<section className="metric-grid" aria-label={label}>
			{metrics.map(([name, value]) => (
				<article className="metric-card" key={name}>
					<span>{name}</span>
					<strong>{value.toLocaleString()}</strong>
				</article>
			))}
		</section>
	);
}
