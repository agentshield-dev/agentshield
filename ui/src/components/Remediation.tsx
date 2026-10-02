import { type ReactNode, useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { errorMessage, postJSON, useApi } from '@/api/client';
import type {
	ApproveResponse,
	Candidate,
	CandidatesResponse,
	Finding,
	Plan,
	Preparation,
	PrepareResponse,
	Proposal
} from '@/api/types';
import { list } from '@/lib/model';

// Live remediation for one proposal on a finding. Nothing is written to a provider until the user
// approves in the dialog, and every step goes through the server:
//
//   1. GET  .../candidates  lists the provider actions that can implement the proposal.
//   2. POST .../prepare     plans the chosen action and dry-runs its writes; nothing is written.
//   3. POST .../approve     executes the prepared plan and re-reads the provider to verify it.
//
// The browser only sends IDs and the user's selection. The server loads the proposal from the
// stored finding and executes only the plan it prepared, so a client cannot inject a payload.
// Errors come back as {"error": "..."} and are shown verbatim: 503 means live remediation is
// disabled on this server (no discovery, or a non-loopback --listen), and 409 means the finding,
// target, or provider state changed since the step before, or that a server restart discarded the
// in-memory prepared plan. See docs/architecture/remediation.md.

// A successful prepare: the action the user picked, the server's plan, and the dry-run result.
interface Prepared {
	candidate: Candidate;
	plan: Plan;
	preparation?: Preparation;
}

interface ApprovalDialogProps {
	proposal: Proposal;
	prepared: Prepared;
	approveURL: string;
	onApproved(status: string, applied: boolean): void;
	onClose(): void;
}

function ApprovalDialog({
	proposal,
	prepared,
	approveURL,
	onApproved,
	onClose
}: ApprovalDialogProps) {
	const dialog = useRef<HTMLDialogElement>(null);
	const [error, setError] = useState('');
	const [busy, setBusy] = useState(false);

	useEffect(() => {
		const element = dialog.current;
		if (element && !element.open) element.showModal();
	}, []);

	// The approval carries only the plan ID. The server re-checks that provider state still matches
	// the dry-run before writing, and answers 409 instead of applying a stale plan. Approving a plan
	// that already succeeded returns the recorded result without writing again.
	async function approve() {
		setBusy(true);
		setError('');
		try {
			const response = await postJSON<ApproveResponse>(approveURL, { planId: prepared.plan.id });
			const applied = response.verification?.satisfied === true;
			// A failed or unsatisfied verification after a successful write is still a 200, because
			// the cluster changed; it must not read as success. Approving again re-runs only Verify.
			const incomplete = response.verificationError
				? `Applied; verification incomplete: ${response.verificationError}`
				: 'Applied; verification incomplete.';
			onApproved(applied ? 'Applied and verified.' : incomplete, applied);
			dialog.current?.close();
		} catch (failure) {
			setError(errorMessage(failure));
		} finally {
			setBusy(false);
		}
	}

	return createPortal(
		<dialog ref={dialog} className="approval-dialog" onClose={onClose}>
			<form method="dialog" className="approval-sheet">
				<header>
					<span className="eyebrow">Explicit approval</span>
					<h2>{proposal.intent}</h2>
				</header>
				<dl className="detail-grid">
					<dt>Provider</dt>
					<dd>{prepared.candidate.providerId}</dd>
					<dt>Target</dt>
					<dd>
						{proposal.target.kind} · {proposal.target.entityId}
					</dd>
				</dl>
				{/* Dry-run output per controlled field: current state and what the provider admitted. */}
				<section className="approval-preview" aria-label="Change to apply">
					<h3>Change to apply</h3>
					<pre>{JSON.stringify(list(prepared.preparation?.providerState), null, 2)}</pre>
				</section>
				<p className="approval-error" role="alert">
					{error}
				</p>
				<footer>
					<button className="button secondary" type="submit" value="cancel">
						Cancel
					</button>
					{/* Disabled while in flight so a double click cannot send a second approval. */}
					<button className="button primary" type="button" disabled={busy} onClick={approve}>
						Approve and apply
					</button>
				</footer>
			</form>
		</dialog>,
		document.body
	);
}

interface RemediationItemProps {
	finding: Finding;
	proposal: Proposal;
	active: boolean;
	refresh: number;
}

export function RemediationItem({ finding, proposal, active, refresh }: RemediationItemProps) {
	// Candidates load only while the finding is open. useApi retries 5xx with backoff, so a 503
	// (remediation disabled) stays visible as the error message below rather than failing silently.
	const base = `/api/v1/findings/${encodeURIComponent(finding.id)}/remediations/${encodeURIComponent(proposal.id)}`;
	const candidates = useApi<CandidatesResponse>(active ? `${base}/candidates` : null, refresh);
	const [selected, setSelected] = useState(0);
	const [status, setStatus] = useState('');
	const [preparing, setPreparing] = useState(false);
	const [prepared, setPrepared] = useState<Prepared | null>(null);
	const [applied, setApplied] = useState(false);

	const options = list(candidates.data?.candidates);
	// Clamp the selection: a refresh can return fewer candidates than before.
	const candidate = options[Math.min(selected, options.length - 1)];

	async function prepare() {
		if (!candidate) return;
		setPreparing(true);
		setStatus('Preparing…');
		try {
			const response = await postJSON<PrepareResponse>(`${base}/prepare`, {
				providerId: candidate.providerId,
				sourceId: candidate.sourceId,
				actionId: candidate.actionId
			});
			// Advisory-only actions have no executable plan; show the guidance and never offer approval.
			if (response.plan.mode === 'advisory-only') {
				setStatus(response.plan.advisory ?? '');
				return;
			}
			setPrepared({ candidate, plan: response.plan, preparation: response.preparation });
			setStatus('Prepared; approval pending.');
		} catch (failure) {
			setStatus(errorMessage(failure));
		} finally {
			setPreparing(false);
		}
	}

	let actions: ReactNode;
	if (applied) {
		actions = <span className="badge active">Applied</span>;
	} else if (candidates.error) {
		actions = <span className="approval-error">{candidates.error.message}</span>;
	} else if (!candidates.data) {
		actions = <span className="muted">Loading actions…</span>;
	} else if (!candidate) {
		actions = <span className="muted">No live action available</span>;
	} else {
		actions = (
			<>
				<select
					aria-label={`Action for ${proposal.intent}`}
					value={selected}
					onChange={event => setSelected(Number(event.target.value))}
				>
					{options.map((option, index) => (
						<option
							value={index}
							key={`${option.providerId}/${option.sourceId}/${option.actionId}`}
						>
							{option.providerId} · {option.actionId} · {option.sourceId}
						</option>
					))}
				</select>
				<button type="button" disabled={preparing} onClick={prepare}>
					Prepare
				</button>
			</>
		);
	}

	return (
		<article className="remediation-item">
			<div>
				<strong>{proposal.intent}</strong>
				<span>
					{proposal.target.kind} · {proposal.target.entityId}
				</span>
			</div>
			<div className="remediation-actions">{actions}</div>
			<p className="remediation-status" role="status">
				{status}
			</p>
			{prepared ? (
				<ApprovalDialog
					proposal={proposal}
					prepared={prepared}
					approveURL={`${base}/approve`}
					onApproved={(message, succeeded) => {
						setStatus(message);
						setApplied(succeeded);
					}}
					onClose={() => setPrepared(null)}
				/>
			) : null}
		</article>
	);
}
