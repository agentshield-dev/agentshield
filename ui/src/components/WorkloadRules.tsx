import { useEffect, useState } from 'react';
import { errorMessage, useApi } from '@/api/client';
import type { RuleDraftsResponse, RulesResponse } from '@/api/types';
import { requestRegeneration } from '@/components/RuleDraftDetail';
import { list } from '@/lib/model';
import { navigate } from '@/lib/route';
import {
	authoringPollMs,
	draftState,
	draftStateLabels,
	isAuthoring,
	ruleSelector
} from '@/lib/rules';

// Inspector section for a Deployment: its loaded rules, current draft, and a regenerate action.
export function WorkloadRules({ workloadId }: { workloadId: string }) {
	const [changes, setChanges] = useState(0);
	const [status, setStatus] = useState('');
	const [busy, setBusy] = useState(false);
	const loaded = useApi<RulesResponse>('/api/v1/rules', changes);
	const drafts = useApi<RuleDraftsResponse>('/api/v1/rule-drafts', changes);
	const rules = list(loaded.data?.workloadRules).filter(
		item => item.rule.workloadResourceId === workloadId
	);
	const workloadDrafts = list(drafts.data?.drafts).filter(draft => draft.resourceId === workloadId);
	const draft = workloadDrafts.find(item => item.currentRevision) ?? workloadDrafts[0];
	const authoring = draft ? isAuthoring(draft) : false;
	// A failed draft offers Author now too: the worker will not retry it on its own.
	const offerAuthor = authoring || draft?.status === 'failed';
	const running = draft ? draftState(draft) === 'authoring' : false;

	useEffect(() => {
		if (!authoring) return;
		const timer = window.setInterval(() => setChanges(value => value + 1), authoringPollMs);
		return () => window.clearInterval(timer);
	}, [authoring]);

	async function regenerate() {
		setBusy(true);
		setStatus('');
		try {
			const response = await requestRegeneration(workloadId);
			setStatus(`${offerAuthor ? 'Authoring' : 'Regenerating'} draft #${response.draft.id}.`);
		} catch (failure) {
			setStatus(errorMessage(failure));
		} finally {
			setBusy(false);
			setChanges(value => value + 1);
		}
	}

	const error = loaded.error ?? drafts.error;
	return (
		<section className="detail-section" aria-label="Detection rules">
			<h3>Detection rules · {rules.length}</h3>
			{error ? (
				<p className="approval-error">{error.message}</p>
			) : rules.length ? (
				<ul className="evidence-list">
					{rules.map(item => (
						<li key={`${item.mode}/${item.rule.id}`}>
							<a
								className="text-link"
								href={`#rules/active/${encodeURIComponent(`${item.mode}/${item.rule.id}`)}`}
							>
								{ruleSelector(item.rule)}
							</a>{' '}
							{item.rule.expression} ({item.mode})
						</li>
					))}
				</ul>
			) : (
				<p className="muted">No loaded rules for this workload.</p>
			)}
			<dl className="detail-grid">
				<dt>Current draft</dt>
				<dd>
					{draft ? (
						<a className="text-link" href={`#rules/drafts/${draft.id}`}>
							#{draft.id} · {draftStateLabels[draftState(draft)]}
						</a>
					) : (
						'none'
					)}
				</dd>
			</dl>
			<div className="remediation-actions">
				<button
					className="button secondary"
					type="button"
					disabled={busy || running || !draft?.currentRevision}
					onClick={regenerate}
				>
					{running ? 'Authoring…' : offerAuthor ? 'Author now' : 'Regenerate rules'}
				</button>
				{draft ? (
					<button
						className="button secondary"
						type="button"
						onClick={() => navigate(`rules/drafts/${draft.id}`)}
					>
						Open draft
					</button>
				) : null}
			</div>
			<p className="remediation-status" role="status">
				{status}
			</p>
		</section>
	);
}
