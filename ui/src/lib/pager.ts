import { useState } from 'react';

interface PagerState {
	cursor: string;
	history: readonly string[];
	page: number;
}

const first: PagerState = { cursor: '', history: [], page: 1 };

// Cursor pagination with a back stack, since the API only returns the next cursor.
export function useCursorPager() {
	const [state, setState] = useState(first);
	return {
		cursor: state.cursor,
		page: state.page,
		hasPrevious: state.history.length > 0,
		next: (nextCursor: string) =>
			setState(current => ({
				cursor: nextCursor,
				history: [...current.history, current.cursor],
				page: current.page + 1
			})),
		previous: () =>
			setState(current => ({
				cursor: current.history.at(-1) ?? '',
				history: current.history.slice(0, -1),
				page: current.page - 1
			})),
		reset: () => setState(first)
	};
}

export type CursorPager = ReturnType<typeof useCursorPager>;
