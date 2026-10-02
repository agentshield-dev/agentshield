import type { ApiState } from '@/api/client';
import type { CursorPager } from '@/lib/pager';

interface PaginationProps {
	label: string;
	subject: string;
	pager: CursorPager;
	state: ApiState<{ nextCursor?: string }>;
}

// Buttons keep their enabled state while the next page loads: a button that becomes disabled loses
// focus, which makes the browser drop its scroll anchor and jump the page.
export function Pagination({ label, subject, pager, state }: PaginationProps) {
	const loading = !state.data && !state.error;
	const nextCursor = state.data?.nextCursor;
	const hasNext = loading ? Boolean(state.latest?.nextCursor) : Boolean(nextCursor);
	return (
		<nav className="pagination" aria-label={label}>
			<span>Page {pager.page}</span>
			<div>
				<button
					className="page-button"
					type="button"
					aria-label={`Previous ${subject} page`}
					disabled={!pager.hasPrevious && !loading}
					onClick={() => pager.hasPrevious && pager.previous()}
				>
					←
				</button>
				<button
					className="page-button"
					type="button"
					aria-label={`Next ${subject} page`}
					disabled={!hasNext}
					onClick={() => nextCursor && pager.next(nextCursor)}
				>
					→
				</button>
			</div>
		</nav>
	);
}
