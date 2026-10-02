import type {
	AssertionBase,
	IdentityClaim,
	List,
	Resource,
	ResourceAssertion,
	SecuritySemantics
} from '@/api/types';

const SECURITY_SEMANTICS_KEY = 'agentshield.io/security-semantics';
const NAMESPACE_KEYS = ['namespace', 'kubernetes/namespace', 'istio/namespace'];

export function list<T>(value: List<T>): readonly T[] {
	return value ?? [];
}

export function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function unique(values: readonly (string | undefined)[]): string[] {
	const present = values.filter((value): value is string => Boolean(value));
	return [...new Set(present)].sort((a, b) => a.localeCompare(b));
}

export function formatValue(raw: unknown): string {
	return typeof raw === 'object' ? JSON.stringify(raw) : String(raw ?? '');
}

export function formatTime(value: string): string {
	return new Date(value).toLocaleString();
}

export function initials(kind: string | undefined, fallback: string): string {
	return ((kind || fallback).split('/').at(-1) ?? '').slice(0, 2).toUpperCase();
}

export interface Labelled {
	id: string;
	identity?: IdentityClaim;
	assertions?: List<ResourceAssertion>;
}

export function label(resource: Labelled): string {
	return (
		list(resource.assertions)[0]?.displayName ||
		resource.identity?.immutableKey ||
		resource.id ||
		'unknown'
	);
}

export function namespace(resource: Resource): string {
	for (const assertion of list(resource.assertions)) {
		const values = assertion.attributes ?? assertion.properties ?? {};
		for (const key of NAMESPACE_KEYS) {
			if (values[key]) return values[key];
		}
	}
	return 'cluster-scoped';
}

export function securitySemantics(assertion: AssertionBase): SecuritySemantics | null {
	const value =
		assertion.properties?.[SECURITY_SEMANTICS_KEY] ||
		assertion.attributes?.[SECURITY_SEMANTICS_KEY];
	if (!value) return null;
	try {
		return JSON.parse(value) as SecuritySemantics;
	} catch {
		return null;
	}
}

export function allEvidence(assertions: List<AssertionBase>): string[] {
	return unique(list(assertions).flatMap(assertion => list(assertion.evidenceIds)));
}
