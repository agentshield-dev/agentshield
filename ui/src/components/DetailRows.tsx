import { Fragment } from 'react';
import { formatValue, isRecord } from '@/lib/model';

// Renders dt/dd pairs for an object, optionally restricted to the given keys.
export function DetailRows({ value, keys }: { value: unknown; keys?: readonly string[] }) {
	const record = isRecord(value) ? value : {};
	const entries = keys
		? keys.filter(key => record[key] !== undefined).map(key => [key, record[key]] as const)
		: Object.entries(record);
	return entries.map(([key, raw]) => (
		<Fragment key={key}>
			<dt>{key}</dt>
			<dd className={typeof raw === 'string' && raw.length > 20 ? 'mono' : undefined}>
				{formatValue(raw)}
			</dd>
		</Fragment>
	));
}
