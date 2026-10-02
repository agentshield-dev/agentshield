import type { ReactNode } from 'react';

export function EmptyState({
	title,
	error,
	children
}: {
	title: string;
	error?: boolean;
	children?: ReactNode;
}) {
	return (
		<div className={error ? 'empty-state error-state' : 'empty-state'}>
			<strong>{title}</strong>
			{children ? <p>{children}</p> : null}
		</div>
	);
}
