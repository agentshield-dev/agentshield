import type { JsonBodyType } from 'msw';
import { type HttpHandler, HttpResponse, http } from 'msw/http';
import { sse } from 'msw/sse';
import { ApiError, FakeBackend, type GraphEvent } from './backend';

// The backend instance every story talks to; stories reset it and may reconfigure it.
export const backend = new FakeBackend();

const query = (request: Request) => new URL(request.url).searchParams;

async function respond(produce: () => JsonBodyType, status = 200): Promise<Response> {
	if (backend.config.latencyMs) {
		await new Promise(resolve => setTimeout(resolve, backend.config.latencyMs));
	}
	try {
		return HttpResponse.json(produce(), { status });
	} catch (error) {
		if (error instanceof ApiError) {
			return HttpResponse.json({ error: error.message }, { status: error.status });
		}
		throw error;
	}
}

const text = (value: string | readonly string[] | undefined) => String(value ?? '');

export const handlers: HttpHandler[] = [
	http.get('/api/v1/graph', () => respond(() => backend.graph())),
	http.get('/api/v1/overview', () => respond(() => backend.overview())),
	http.get('/api/v1/resources', ({ request }) => respond(() => backend.resources(query(request)))),
	http.get('/api/v1/resources/:resourceID', ({ params }) =>
		respond(() => backend.resource(text(params.resourceID)))
	),
	http.get('/api/v1/relationships', ({ request }) =>
		respond(() => backend.relationships(query(request)))
	),
	http.get('/api/v1/relationships/:relationshipID', ({ params }) =>
		respond(() => backend.relationship(text(params.relationshipID)))
	),
	http.get('/api/v1/exposures', ({ request }) => respond(() => backend.exposures(query(request)))),
	http.get('/api/v1/findings', ({ request }) =>
		respond(() => backend.queryFindings(query(request)))
	),
	http.get('/api/v1/findings/:findingID', ({ params }) =>
		respond(() => backend.finding(text(params.findingID)))
	),
	http.get('/api/v1/findings/:findingID/remediations/:proposalID/candidates', ({ params }) =>
		respond(() => backend.candidates(text(params.findingID), text(params.proposalID)))
	),
	http.post(
		'/api/v1/findings/:findingID/remediations/:proposalID/prepare',
		async ({ request, params }) => {
			const body: unknown = await request.json().catch(() => undefined);
			return respond(() => backend.prepare(text(params.findingID), text(params.proposalID), body));
		}
	),
	http.post(
		'/api/v1/findings/:findingID/remediations/:proposalID/approve',
		async ({ request, params }) => {
			const body: unknown = await request.json().catch(() => undefined);
			return respond(() => backend.approve(text(params.findingID), text(params.proposalID), body));
		}
	),
	http.get('/api/v1/rules', () => respond(() => backend.rules())),
	http.get('/api/v1/rule-drafts', () => respond(() => backend.ruleDrafts())),
	http.get('/api/v1/rule-drafts/:jobID', ({ params }) =>
		respond(() => backend.ruleDraft(text(params.jobID)))
	),
	http.post('/api/v1/rule-drafts/:jobID/review', async ({ request, params }) => {
		const body: unknown = await request.json().catch(() => undefined);
		return respond(() => backend.reviewRuleDraft(text(params.jobID), body));
	}),
	http.post('/api/v1/workloads/:resourceID/rule-drafts', ({ params }) =>
		respond(() => backend.requestRuleDraft(text(params.resourceID)), 202)
	),
	// Like the service, the stream announces the current graph on connect and every change after.
	sse<{ graph: string }>('/api/v1/events', ({ client }) => {
		const announce = (event: GraphEvent) =>
			client.send({ event: 'graph', data: JSON.stringify(event) });
		const unsubscribe = backend.subscribe(announce);
		// MSW closes the client once the EventSource goes away; stop announcing to it from then on.
		const close = client.close.bind(client);
		client.close = () => {
			unsubscribe();
			close();
		};
		const current = backend.currentEvent();
		if (current) announce(current);
	})
];

// Story-specific handlers win over the defaults because the first matching handler answers.
export const withOverrides = (...overrides: HttpHandler[]): HttpHandler[] => [
	...overrides,
	...handlers
];
