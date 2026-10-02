// Pure geometry for the Explorer graph, kept free of React and the DOM so it is deterministic and
// testable. The graph is drawn left to right: each relationship's subject sits in an earlier column
// than its object where the graph allows, nodes stack vertically within a column, and edges are
// horizontal cubic Beziers between node sides. Pixel constants here must match the SVG text offsets
// and the .node and .edge-label fonts that GraphCanvas and styles.css use.
import type { Relationship, Resource } from '@/api/types';
import { label, namespace } from '@/lib/model';

export type Selection =
	| { type: 'resource'; item: Resource }
	| { type: 'relationship'; item: Relationship };

export interface NodeBox {
	x: number;
	y: number;
	width: number;
	height: number;
	nameLines: string[];
	metaLines: string[];
}

export interface Size {
	width: number;
	height: number;
}

export interface GraphLayout extends Size {
	positions: ReadonlyMap<string, NodeBox>;
}

export interface Transform {
	x: number;
	y: number;
	scale: number;
}

export type VisualState = 'normal' | 'selected' | 'dim';

export interface Port {
	sourceY?: number;
	targetY?: number;
}

export interface CurvePoint {
	x: number;
	y: number;
	normalX: number;
	normalY: number;
}

export interface EdgeLabelInput {
	relationID: string;
	text: string;
	visualState: VisualState;
	pinned: boolean;
	// Candidate anchors along the curve, in order of preference.
	points: CurvePoint[];
	// Dense samples of the curve, used to keep other labels off a selected path.
	pathPoints: CurvePoint[];
	x: number;
	y: number;
}

export interface PlacedLabel {
	relationID: string;
	text: string;
	visualState: VisualState;
	x: number;
	y: number;
	connector?: { x1: number; y1: number; x2: number; y2: number };
}

interface Bounds {
	left: number;
	right: number;
	top: number;
	bottom: number;
}

// Column pitch and node width; the 160px between columns leaves room for edge curves and labels.
const GROUP_WIDTH = 580;
const NODE_WIDTH = 420;

export const emptyLayout: GraphLayout = { positions: new Map(), width: 0, height: 0 };

// Wraps at the last separator in the final 40% of a line, so long IDs and paths break at a
// segment boundary; text with no such separator is cut at lineLength.
export function wrapText(value: string, lineLength: number): string[] {
	let remaining = value;
	const lines: string[] = [];
	while (remaining.length > lineLength) {
		const chunk = remaining.slice(0, lineLength + 1);
		const candidates = [' ', '/', '·', ':', '-', '_']
			.map(separator => chunk.lastIndexOf(separator))
			.filter(index => index >= Math.floor(lineLength * 0.6));
		const breakAt = candidates.length ? Math.max(...candidates) + 1 : lineLength;
		lines.push(remaining.slice(0, breakAt).trimEnd());
		remaining = remaining.slice(breakAt).trimStart();
	}
	if (remaining || !lines.length) lines.push(remaining);
	return lines;
}

// Columns follow dependency depth (Kahn's algorithm); nodes in cycles take the first column free
// of their already-placed neighbors.
export function layoutGraph(
	resources: readonly Resource[],
	relationships: readonly Relationship[]
): GraphLayout {
	const byID = new Map(resources.map(resource => [resource.id, resource]));
	const rank = new Map<string, number>(resources.map(resource => [resource.id, 0]));
	const indegree = new Map<string, number>(resources.map(resource => [resource.id, 0]));
	const outgoing = new Map<string, string[]>(resources.map(resource => [resource.id, []]));
	for (const relation of relationships) {
		const source = relation.subjectId;
		const target = relation.objectId;
		if (!byID.has(source) || !byID.has(target) || source === target) continue;
		outgoing.get(source)?.push(target);
		indegree.set(target, (indegree.get(target) ?? 0) + 1);
	}

	// Longest-path ranking: a node's column is one past its furthest-right predecessor. Sorting the
	// queue by label keeps the result independent of API response order.
	const byLabel = (a: Resource, b: Resource) => label(a).localeCompare(label(b));
	const queue = resources.filter(resource => indegree.get(resource.id) === 0).sort(byLabel);
	const visited = new Set<string>();
	for (let resource = queue.shift(); resource; resource = queue.shift()) {
		visited.add(resource.id);
		for (const target of outgoing.get(resource.id) ?? []) {
			rank.set(target, Math.max(rank.get(target) ?? 0, (rank.get(resource.id) ?? 0) + 1));
			const remaining = (indegree.get(target) ?? 0) - 1;
			indegree.set(target, remaining);
			const next = byID.get(target);
			if (remaining === 0 && next) queue.push(next);
		}
		queue.sort(byLabel);
	}

	// Kahn's algorithm never reaches nodes in or downstream of a cycle; place those afterwards.
	const assignedCycles = new Set<string>();
	for (const resource of resources.filter(item => !visited.has(item.id)).sort(byLabel)) {
		const neighboringRanks = new Set<number>();
		for (const relation of relationships) {
			const source = relation.subjectId;
			const target = relation.objectId;
			const neighbor = source === resource.id ? target : target === resource.id ? source : null;
			if (neighbor && (visited.has(neighbor) || assignedCycles.has(neighbor))) {
				neighboringRanks.add(rank.get(neighbor) ?? 0);
			}
		}
		let column = 0;
		while (neighboringRanks.has(column)) column++;
		rank.set(resource.id, column);
		assignedCycles.add(resource.id);
	}

	// Cycle placement can skip ranks; renumber so there are no empty columns.
	const rankValues = [...new Set(rank.values())].sort((a, b) => a - b);
	const compactRank = new Map(rankValues.map((value, index) => [value, index]));
	const groups = new Map<number, Resource[]>(rankValues.map((_, index) => [index, []]));
	for (const resource of resources) {
		groups.get(compactRank.get(rank.get(resource.id) ?? 0) ?? 0)?.push(resource);
	}

	const positions = new Map<string, NodeBox>();
	let maxBottom = 0;
	for (const [column, items] of [...groups.entries()].sort(([a], [b]) => a - b)) {
		// Within a column, namespace then kind then name keeps related resources adjacent.
		const key = (resource: Resource) =>
			`${namespace(resource)}\u0000${resource.kind}\u0000${label(resource)}`;
		items.sort((a, b) => key(a).localeCompare(key(b)));
		let y = 40;
		for (const resource of items) {
			const nameLines = wrapText(label(resource), 40);
			const metaLines = wrapText(`${namespace(resource)} · ${resource.kind || 'unknown'}`, 44);
			// 21px name and 17px meta line heights match the tspan offsets in GraphCanvas; 46px is the
			// top and bottom padding plus the first meta line. Nodes are separated by a 52px gap.
			const height = 46 + nameLines.length * 21 + (metaLines.length - 1) * 17;
			positions.set(resource.id, {
				x: column * GROUP_WIDTH + 44,
				y,
				width: NODE_WIDTH,
				height,
				nameLines,
				metaLines
			});
			y += height + 52;
		}
		maxBottom = Math.max(maxBottom, y - 52);
	}
	return { positions, width: groups.size * GROUP_WIDTH + 30, height: maxBottom + 40 };
}

// Spreads the attachment points of edges that share a node side, ordered by where each edge goes.
export function relationshipPorts(
	relationships: readonly Relationship[],
	positions: ReadonlyMap<string, NodeBox>
): Map<string, Port> {
	interface SideEntry {
		resourceID: string;
		counterpartY: number;
		endpoint: 'sourceY' | 'targetY';
		relationID: string;
	}
	const sides = new Map<string, SideEntry[]>();
	for (const relation of relationships) {
		const source = positions.get(relation.subjectId);
		const target = positions.get(relation.objectId);
		if (!source || !target) continue;
		// Forward edges leave the subject's right side and enter the object's left side; backward
		// edges (cycles) use the opposite sides. edgeGeometry must make the same choice.
		const forward = target.x + target.width / 2 >= source.x + source.width / 2;
		const entries: [string, SideEntry][] = [
			[
				`${relation.subjectId}:${forward ? 'right' : 'left'}`,
				{
					resourceID: relation.subjectId,
					counterpartY: target.y + target.height / 2,
					endpoint: 'sourceY',
					relationID: relation.id
				}
			],
			[
				`${relation.objectId}:${forward ? 'left' : 'right'}`,
				{
					resourceID: relation.objectId,
					counterpartY: source.y + source.height / 2,
					endpoint: 'targetY',
					relationID: relation.id
				}
			]
		];
		for (const [key, entry] of entries) {
			const side = sides.get(key);
			if (side) side.push(entry);
			else sides.set(key, [entry]);
		}
	}

	const ports = new Map<string, Port>();
	// Ordering ports by the far end's height keeps edges sharing a side from crossing each other.
	for (const entries of sides.values()) {
		entries.sort(
			(left, right) =>
				left.counterpartY - right.counterpartY || left.relationID.localeCompare(right.relationID)
		);
		const position = positions.get(entries[0].resourceID);
		if (!position) continue;
		const padding = Math.min(12, position.height / 4);
		const usable = position.height - padding * 2;
		entries.forEach((entry, index) => {
			const port = ports.get(entry.relationID) ?? {};
			port[entry.endpoint] =
				entries.length === 1
					? position.y + position.height / 2
					: position.y + padding + (usable * index) / (entries.length - 1);
			ports.set(entry.relationID, port);
		});
	}
	return ports;
}

function edgeGeometry(source: NodeBox, target: NodeBox, port: Port) {
	const forward = target.x + target.width / 2 >= source.x + source.width / 2;
	const sourceX = forward ? source.x + source.width : source.x;
	const targetX = forward ? target.x : target.x + target.width;
	const sourceY = port.sourceY ?? source.y + source.height / 2;
	const targetY = port.targetY ?? target.y + target.height / 2;
	// Horizontal control points give each edge a smooth S; the 36px floor keeps edges between
	// adjacent or same-column nodes from folding into a sharp kink.
	const bend = Math.max(36, Math.abs(targetX - sourceX) * 0.42);
	const sourceControlX = sourceX + (forward ? bend : -bend);
	const targetControlX = targetX + (forward ? -bend : bend);
	return { sourceX, sourceY, targetX, targetY, sourceControlX, targetControlX };
}

export function edgePath(source: NodeBox, target: NodeBox, port: Port): string {
	const { sourceX, sourceY, targetX, targetY, sourceControlX, targetControlX } = edgeGeometry(
		source,
		target,
		port
	);
	return `M ${sourceX} ${sourceY} C ${sourceControlX} ${sourceY}, ${targetControlX} ${targetY}, ${targetX} ${targetY}`;
}

// Samples the edge's cubic Bezier at the given parameters, with the unit normal at each point.
export function edgeCurvePoints(
	source: NodeBox,
	target: NodeBox,
	port: Port,
	times: readonly number[]
): CurvePoint[] {
	const { sourceX, sourceY, targetX, targetY, sourceControlX, targetControlX } = edgeGeometry(
		source,
		target,
		port
	);
	return times.map(time => {
		const inverse = 1 - time;
		const tangentX =
			3 * inverse ** 2 * (sourceControlX - sourceX) +
			6 * inverse * time * (targetControlX - sourceControlX) +
			3 * time ** 2 * (targetX - targetControlX);
		// Both y control points equal their endpoint's y, which collapses the y-derivative to this.
		const tangentY = 6 * inverse * time * (targetY - sourceY);
		const magnitude = Math.hypot(tangentX, tangentY) || 1;
		return {
			x:
				inverse ** 3 * sourceX +
				3 * inverse ** 2 * time * sourceControlX +
				3 * inverse * time ** 2 * targetControlX +
				time ** 3 * targetX,
			y:
				inverse ** 3 * sourceY +
				3 * inverse ** 2 * time * sourceY +
				3 * inverse * time ** 2 * targetY +
				time ** 3 * targetY,
			normalX: -tangentY / magnitude,
			normalY: tangentX / magnitude
		};
	});
}

function overlaps(left: Bounds, right: Bounds, padding = 0): boolean {
	return (
		left.right + padding > right.left &&
		left.left - padding < right.right &&
		left.bottom + padding > right.top &&
		left.top - padding < right.bottom
	);
}

// Places each label at the first offset along its curve that clears nodes, other labels, and the
// selected path; labels that cannot be cleared stay on the curve.
export function placeEdgeLabels(
	labels: readonly EdgeLabelInput[],
	positions: ReadonlyMap<string, NodeBox>,
	size: Size
): PlacedLabel[] {
	const nodeBounds: Bounds[] = [...positions.values()].map(position => ({
		left: position.x,
		right: position.x + position.width,
		top: position.y,
		bottom: position.y + position.height
	}));
	const selectedPathPoints = labels
		.filter(item => item.visualState === 'selected')
		.flatMap(item => item.pathPoints);
	const placed: Bounds[] = [];

	// Greedy placement: pinned (selected) labels claim space first, then top to bottom.
	// Each label tries its anchors in preference order, stepping out along the normal on both sides.
	return [...labels]
		.sort(
			(left, right) =>
				Number(right.pinned) - Number(left.pinned) ||
				left.y - right.y ||
				left.x - right.x ||
				left.text.localeCompare(right.text)
		)
		.map(item => {
			// 8.6px approximates one character of the 14px monospace edge-label font.
			const width = Math.max(58, item.text.length * 8.6);
			let placement: { x: number; baseline: number; bounds: Bounds; anchor: CurvePoint } | null =
				null;
			for (const point of item.points) {
				// Steps of 19px, roughly one label height, so successive tries do not overlap.
				for (const offset of [0, -19, 19, -38, 38, -57, 57, -76, 76]) {
					const x = point.x + point.normalX * offset;
					const baseline = point.y + point.normalY * offset;
					// Text sits on its baseline: ascenders reach about 15px above it, descenders 5px below.
					const candidate = {
						left: x - width / 2,
						right: x + width / 2,
						top: baseline - 15,
						bottom: baseline + 5
					};
					if (
						candidate.left < 4 ||
						candidate.right > size.width - 4 ||
						candidate.top < 4 ||
						candidate.bottom > size.height - 4
					) {
						continue;
					}
					if (
						nodeBounds.some(bounds => overlaps(candidate, bounds, 6)) ||
						placed.some(bounds => overlaps(candidate, bounds, 4))
					) {
						continue;
					}
					if (
						item.visualState !== 'selected' &&
						selectedPathPoints.some(
							selectedPoint =>
								selectedPoint.x >= candidate.left - 5 &&
								selectedPoint.x <= candidate.right + 5 &&
								selectedPoint.y >= candidate.top - 5 &&
								selectedPoint.y <= candidate.bottom + 5
						)
					) {
						continue;
					}
					placement = { x, baseline, bounds: candidate, anchor: point };
					break;
				}
				if (placement) break;
			}

			const fallback = item.points[0];
			const x = placement?.x ?? fallback.x;
			const baseline = placement?.baseline ?? fallback.y;
			if (placement) placed.push(placement.bounds);
			// A label moved off its curve gets a leader line back to its anchor.
			const connector =
				placement && Math.hypot(x - placement.anchor.x, baseline - placement.anchor.y) > 1
					? { x1: placement.anchor.x, y1: placement.anchor.y, x2: x, y2: baseline - 5 }
					: undefined;
			return {
				relationID: item.relationID,
				text: item.text,
				visualState: item.visualState,
				x,
				y: baseline,
				connector
			};
		});
}

// Fits the whole graph in the viewport with a 20px margin, never enlarging past 1:1. The 0.12 floor
// keeps very large graphs from shrinking to an unreadable speck.
export function fitTransform(viewport: Size, content: Size): Transform {
	const scale = Math.min(
		1,
		Math.max(
			0.12,
			Math.min((viewport.width - 40) / content.width, (viewport.height - 40) / content.height)
		)
	);
	return { x: Math.max(20, (viewport.width - content.width * scale) / 2), y: 20, scale };
}

// Frames the graph at a readable scale, centered on the focused node when the graph overflows.
export function readableTransform(viewport: Size, content: Size, focus: NodeBox | null): Transform {
	const fit = Math.min(
		1,
		Math.min((viewport.width - 40) / content.width, (viewport.height - 40) / content.height)
	);
	// Unlike fitTransform, never drop below 0.85 so text stays legible; pan instead.
	const scale = Math.max(0.85, fit);
	const contentWidth = content.width * scale;
	const contentHeight = content.height * scale;
	const focusX = focus ? (focus.x + focus.width / 2) * scale : contentWidth / 2;
	const focusY = focus ? (focus.y + focus.height / 2) * scale : contentHeight / 2;
	const clampAxis = (desired: number, viewportSize: number, contentSize: number) =>
		contentSize <= viewportSize - 48
			? (viewportSize - contentSize) / 2
			: Math.max(viewportSize - contentSize - 24, Math.min(24, desired));
	return {
		x: clampAxis(viewport.width / 2 - focusX, viewport.width, contentWidth),
		y: clampAxis(viewport.height / 2 - focusY, viewport.height, contentHeight),
		scale
	};
}

// Zooms about (centerX, centerY), e.g. the cursor, so the point under it stays fixed.
export function zoomTransform(
	current: Transform,
	factor: number,
	centerX: number,
	centerY: number
): Transform {
	const scale = Math.min(2.5, Math.max(0.1, current.scale * factor));
	const ratio = scale / current.scale;
	return {
		x: centerX - (centerX - current.x) * ratio,
		y: centerY - (centerY - current.y) * ratio,
		scale
	};
}
