import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { errorMessage, postJSON, useApi } from '@/api/client';
import type { RuleDraft, RuleDraftResponse, RuleDraftToolCall, RuleProposal } from '@/api/types';
import { EmptyState } from '@/components/EmptyState';
import { useGraph } from '@/lib/graph-context';
import { formatTime, isRecord, list } from '@/lib/model';
import {
	authoringPollMs,
	draftBadge,
	draftState,
	draftStateLabels,
	isAuthoring,
	ruleSelector
} from '@/lib/rules';

export function requestRegeneration(resourceId: string): Promise<RuleDraftResponse> {
	return postJSON<RuleDraftResponse>(
		`/api/v1/resources/${encodeURIComponent(resourceId)}/rule-drafts`,
		{}
	);
}

interface ApprovalDialogProps {
	draft: RuleDraft;
	proposal: RuleProposal;
	onApproved(count: number): void;
	onClose(): void;
}

function ApprovalDialog({ draft, proposal, onApproved, onClose }: ApprovalDialogProps) {
	const graph = useGraph();
	const dialog = useRef<HTMLDialogElement>(null);
	const [error, setError] = useState('');
	const [busy, setBusy] = useState(false);
	const rules = list(proposal.rules);
	const [selected, setSelected] = useState(() => new Set(rules.map(item => item.rule.id)));

	useEffect(() => {
		const element = dialog.current;
		if (element && !element.open) element.showModal();
	}, []);

	async function approve() {
		setBusy(true);
		setError('');
		try {
			await postJSON(`/api/v1/rule-drafts/${draft.id}/review`, {
				decision: 'approved',
				ruleIds: [...selected]
			});
			onApproved(selected.size);
			dialog.current?.close();
		} catch (failure) {
			setError(errorMessage(failure));
		} finally {
			setBusy(false);
		}
	}

	return createPortal(
		<dialog ref={dialog} className="approval-dialog" onClose={onClose} aria-label="Approve rules">
			<form method="dialog" className="approval-sheet">
				<header>
					<span className="eyebrow">Explicit approval</span>
					<h2>Activate {selected.size === 1 ? 'one rule' : `${selected.size} rules`}</h2>
				</header>
				<dl className="detail-grid">
					<dt>Resource</dt>
					<dd>{graph.name(draft.resourceId)}</dd>
					<dt>Draft</dt>
					<dd>#{draft.id}</dd>
					<dt>Effect</dt>
					<dd>
						The rules leave shadow mode, and their matches become findings. They replace this
						resource's previously approved rules.
					</dd>
				</dl>
				<section className="approval-preview" aria-label="Select rules to activate">
					<h3>Select rules to activate</h3>
					<div className="rule-selection">
						{rules.map(item => (
							<label key={item.rule.id}>
								<input
									type="checkbox"
									checked={selected.has(item.rule.id)}
									onChange={event => {
										const next = new Set(selected);
										if (event.target.checked) next.add(item.rule.id);
										else next.delete(item.rule.id);
										setSelected(next);
									}}
								/>
								<span>
									<strong>{ruleSelector(item.rule)}</strong>
									<code>{item.rule.expression}</code>
								</span>
							</label>
						))}
					</div>
				</section>
				<p className="approval-error" role="alert">
					{error}
				</p>
				<footer>
					<button className="button secondary" type="submit" value="cancel">
						Cancel
					</button>
					<button
						className="button primary"
						type="button"
						disabled={busy || selected.size === 0}
						onClick={approve}
					>
						Approve selected
					</button>
				</footer>
			</form>
		</dialog>,
		document.body
	);
}

function traceLine(call: RuleDraftToolCall): string {
	const args = isRecord(call.arguments) ? call.arguments : {};
	const detail =
		call.name === 'add_rule'
			? `${String(args.selector ?? '')} · ${String(args.expression ?? '')}`
			: String(args.rationale ?? '');
	const result = isRecord(call.result) ? call.result : {};
	if (call.error) return `${call.name} · error: ${call.error}`;
	if (call.name === 'add_rule' && result.added === false) {
		return `${call.name} · rejected: ${String(result.error ?? '')} · ${detail}`;
	}
	return `${call.name} · ${detail}`;
}

interface RuleDraftDetailProps {
	draftId: number;
	active: boolean;
	refresh: number;
	onChanged(): void;
	onViewGraph(id: string): void;
}

export function RuleDraftDetail({
	draftId,
	active,
	refresh,
	onChanged,
	onViewGraph
}: RuleDraftDetailProps) {
	const graph = useGraph();
	const [poll, setPoll] = useState(0);
	const [status, setStatus] = useState('');
	const [busy, setBusy] = useState(false);
	const [approving, setApproving] = useState(false);
	const [shownId, setShownId] = useState(draftId);
	const detail = useApi<RuleDraftResponse>(
		active ? `/api/v1/rule-drafts/${draftId}` : null,
		refresh + poll
	);
	const response = detail.data;
	const authoring = response ? isAuthoring(response.draft) : false;

	if (shownId !== draftId) {
		setShownId(draftId);
		setStatus('');
	}

	// While the model authors the draft, poll until it completes.
	useEffect(() => {
		if (!active || !authoring) return;
		const timer = window.setInterval(() => setPoll(value => value + 1), authoringPollMs);
		return () => window.clearInterval(timer);
	}, [active, authoring]);

	if (detail.error && !response) {
		return (
			<EmptyState title="Draft unavailable" error>
				{detail.error.message}
			</EmptyState>
		);
	}
	if (!response) return <EmptyState title="Loading draft…" />;

	const { draft, proposal } = response;
	const state = draftState(draft);
	const rules = list(proposal?.rules);
	const trace = list(proposal?.toolCalls);
	const approvedRuleIDs = new Set(list(proposal?.approvedRuleIds));

	async function act(action: () => Promise<unknown>, done: string) {
		setBusy(true);
		setStatus('');
		try {
			await action();
			setStatus(done);
			onChanged();
			setPoll(value => value + 1);
		} catch (failure) {
			setStatus(errorMessage(failure));
		} finally {
			setBusy(false);
		}
	}

	return (
		<>
			<header className="finding-title">
				<div>
					<span className="eyebrow">Draft #{draft.id}</span>
					<h2>{graph.name(draft.resourceId)}</h2>
				</div>
				<span className={draftBadge(state)}>{draftStateLabels[state]}</span>
			</header>
			<p className="finding-summary">
				{proposal?.rationale ||
					(authoring
						? 'The AI author has not finished this draft yet.'
						: 'The author returned no rationale.')}
			</p>
			{(state === 'retrying' || state === 'failed') && draft.lastError ? (
				<div className="stale-note">
					<strong>{state === 'failed' ? 'Authoring gave up.' : 'Authoring failed.'}</strong>{' '}
					{draft.lastError}
				</div>
			) : null}
			{!draft.currentRevision ? (
				<div className="stale-note">
					<strong>Previous revision.</strong> This draft cannot be newly approved. An earlier
					approval may remain active while the resource still publishes that authoring context.
				</div>
			) : null}
			<dl className="finding-meta">
				<div>
					<dt>Trigger</dt>
					<dd>{draft.requestedBy ? `Requested by ${draft.requestedBy}` : 'New context'}</dd>
				</div>
				<div>
					<dt>Requested</dt>
					<dd>{formatTime(draft.requestedAt ?? draft.createdAt)}</dd>
				</div>
				<div>
					<dt>{draft.reviewedAt ? 'Reviewed' : 'Completed'}</dt>
					<dd>
						{draft.reviewedAt
							? `${formatTime(draft.reviewedAt)} by ${draft.reviewedBy}`
							: draft.completedAt
								? formatTime(draft.completedAt)
								: '—'}
					</dd>
				</div>
				<div>
					<dt>Rules</dt>
					<dd>{draft.ruleCount}</dd>
				</div>
			</dl>
			{proposal?.context ? (
				<section className="record-section">
					<h3>Resource context</h3>
					<pre>
						{JSON.stringify(
							{ context: proposal.context, attributes: proposal.attributes },
							null,
							2
						)}
					</pre>
				</section>
			) : null}
			<section className="remediation-list" aria-label="Draft rules">
				<h3>Proposed rules</h3>
				{authoring ? (
					<p className="muted">
						{state === 'queued'
							? draft.requestedAt
								? 'Requested; waiting for the authoring worker.'
								: 'Waiting for the stabilization window. Author now skips the wait.'
							: state === 'authoring'
								? 'The AI author is adding rules…'
								: 'The worker will retry this draft automatically. Author now retries it without waiting.'}
					</p>
				) : state === 'failed' ? (
					<p className="muted">
						The worker stopped after {draft.attemptCount} attempt
						{draft.attemptCount === 1 ? '' : 's'}. Author now retries it.
					</p>
				) : rules.length ? (
					rules.map(item => (
						<article className="remediation-item" key={item.rule.id}>
							<div className="finding-row-top">
								<strong>{ruleSelector(item.rule)}</strong>
								<div className="badge-row">
									<span className="badge">{item.rule.risk}</span>
									{state === 'approved' && proposal?.approvedRuleIds ? (
										<span className={approvedRuleIDs.has(item.rule.id) ? 'badge good' : 'badge'}>
											{approvedRuleIDs.has(item.rule.id) ? 'active' : 'not approved'}
										</span>
									) : null}
								</div>
							</div>
							<section className="approval-preview">
								<pre>{item.rule.expression}</pre>
							</section>
							<span>{item.rationale}</span>
						</article>
					))
				) : (
					<p className="muted">The author abstained: no rule fits this resource.</p>
				)}
			</section>
			<div className="remediation-actions">
				{state === 'review' || state === 'rejected' ? (
					<button
						className="button primary"
						type="button"
						disabled={busy || !rules.length || !draft.currentRevision}
						onClick={() => setApproving(true)}
					>
						Approve
					</button>
				) : null}
				{state === 'review' || state === 'approved' ? (
					<button
						className="button secondary"
						type="button"
						disabled={busy}
						onClick={() =>
							act(
								() => postJSON(`/api/v1/rule-drafts/${draft.id}/review`, { decision: 'rejected' }),
								'Rejected; the rules are no longer loaded.'
							)
						}
					>
						Reject
					</button>
				) : null}
				<button
					className="button secondary"
					type="button"
					disabled={busy || state === 'authoring' || !draft.currentRevision}
					onClick={() =>
						act(
							() => requestRegeneration(draft.resourceId),
							authoring || state === 'failed' ? 'Authoring requested.' : 'Regeneration requested.'
						)
					}
				>
					{authoring || state === 'failed' ? 'Author now' : 'Regenerate'}
				</button>
				<button
					className="button secondary"
					type="button"
					onClick={() => onViewGraph(draft.resourceId)}
				>
					View resource
				</button>
			</div>
			<p className="remediation-status" role="status">
				{status}
			</p>
			{trace.length ? (
				<section className="record-section">
					<h3>Authoring trace</h3>
					<ul className="signal-list">
						{trace.map((call, index) => (
							// biome-ignore lint/suspicious/noArrayIndexKey: the trace is append-only and ordered.
							<li key={index}>{traceLine(call)}</li>
						))}
					</ul>
				</section>
			) : null}
			{approving && proposal ? (
				<ApprovalDialog
					draft={draft}
					proposal={proposal}
					onApproved={count => {
						setStatus(
							`Approved ${count} ${count === 1 ? 'rule' : 'rules'}; the selection now runs in active mode.`
						);
						onChanged();
						setPoll(value => value + 1);
					}}
					onClose={() => setApproving(false)}
				/>
			) : null}
		</>
	);
}
