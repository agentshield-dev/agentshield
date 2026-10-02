// SVG rendering and pointer handling for the Explorer graph. Geometry comes from lib/layout; this
// component decides visual state (selected, related, dim) and wires pan, zoom, and selection.
import { Fragment, type RefObject, useEffect, useMemo, useRef, useState } from 'react';
import { flushSync } from 'react-dom';
import type { Relationship, Resource } from '@/api/types';
import { useGraph } from '@/lib/graph-context';
import {
	type EdgeLabelInput,
	edgeCurvePoints,
	edgePath,
	type GraphLayout,
	placeEdgeLabels,
	relationshipPorts,
	type Selection,
	type Transform,
	type VisualState
} from '@/lib/layout';
import { label, namespace } from '@/lib/model';

interface GraphCanvasProps {
	svg: RefObject<SVGSVGElement | null>;
	resources: readonly Resource[];
	relationships: readonly Relationship[];
	layout: GraphLayout;
	selected: Selection | null;
	showLabels: boolean;
	transform: Transform;
	onPan(update: (current: Transform) => Transform): void;
	onZoom(factor: number, centerX: number, centerY: number): void;
	onSelect(selection: Selection): void;
}

// Label anchors as Bezier parameters, middle first, so a label stays near its edge's midpoint
// unless that spot is taken. PATH_SAMPLES traces the whole curve for selected-path avoidance.
const CURVE_ANCHORS = [0.5, 0.4, 0.6, 0.3, 0.7, 0.2, 0.8, 0.15, 0.85];
const PATH_SAMPLES = Array.from({ length: 41 }, (_, index) => index / 40);

function edgeVisualState(
	relation: Relationship,
	selectedID: string | null,
	selectedRelationID: string | null
): VisualState {
	const connected =
		selectedID && (relation.subjectId === selectedID || relation.objectId === selectedID);
	if (connected || selectedRelationID === relation.id) return 'selected';
	if (selectedID || selectedRelationID) return 'dim';
	return 'normal';
}

function isActivation(event: { key: string }): boolean {
	return event.key === 'Enter' || event.key === ' ';
}

export function GraphCanvas({
	svg,
	resources,
	relationships,
	layout,
	selected,
	showLabels,
	transform,
	onPan,
	onZoom,
	onSelect
}: GraphCanvasProps) {
	const graph = useGraph();
	const drag = useRef<{ x: number; y: number; tx: number; ty: number } | null>(null);
	const [panning, setPanning] = useState(false);
	const { positions } = layout;

	const selectedID = selected?.type === 'resource' ? selected.item.id : null;
	const selectedRelationID = selected?.type === 'relationship' ? selected.item.id : null;
	const selectedEndpoints = new Set(
		selected?.type === 'relationship' ? [selected.item.subjectId, selected.item.objectId] : []
	);
	const neighborIDs = new Set<string>();
	if (selectedID) {
		for (const relation of relationships) {
			if (relation.subjectId === selectedID) neighborIDs.add(relation.objectId);
			if (relation.objectId === selectedID) neighborIDs.add(relation.subjectId);
		}
	}

	const edges = useMemo(() => {
		const ports = relationshipPorts(relationships, positions);
		return relationships.flatMap(relation => {
			const source = positions.get(relation.subjectId);
			const target = positions.get(relation.objectId);
			if (!source || !target) return [];
			const port = ports.get(relation.id) ?? {};
			const visualState = edgeVisualState(relation, selectedID, selectedRelationID);
			const labelInput: EdgeLabelInput = {
				relationID: relation.id,
				text: relation.predicate || 'relationship',
				visualState,
				pinned: visualState === 'selected',
				points: edgeCurvePoints(source, target, port, CURVE_ANCHORS),
				pathPoints: edgeCurvePoints(source, target, port, PATH_SAMPLES),
				x: (source.x + target.x) / 2,
				y: (source.y + target.y) / 2
			};
			return [{ relation, path: edgePath(source, target, port), visualState, labelInput }];
		});
	}, [relationships, positions, selectedID, selectedRelationID]);

	const labels = useMemo(
		() =>
			showLabels
				? placeEdgeLabels(
						edges.map(edge => edge.labelInput),
						positions,
						layout
					)
				: [],
		[showLabels, edges, positions, layout]
	);

	useEffect(() => {
		const element = svg.current;
		if (!element) return;
		// React registers wheel listeners as passive, so zooming without page scroll needs a native one.
		const onWheel = (event: WheelEvent) => {
			event.preventDefault();
			const rect = element.getBoundingClientRect();
			onZoom(event.deltaY < 0 ? 1.12 : 0.89, event.clientX - rect.left, event.clientY - rect.top);
		};
		element.addEventListener('wheel', onWheel, { passive: false });
		return () => element.removeEventListener('wheel', onWheel);
	}, [svg, onZoom]);

	// Below 0.45 scale text is unreadable, so the overview class hides it and leaves the shapes.
	const className = [transform.scale < 0.45 && 'overview', panning && 'panning']
		.filter(Boolean)
		.join(' ');

	return (
		<svg
			ref={svg}
			id="graph"
			className={className || undefined}
			role="img"
			aria-label="Selected resource neighborhood"
			// biome-ignore lint/a11y/noNoninteractiveTabindex: keeps the canvas focusable, as before the React port
			tabIndex={0}
			onPointerDown={event => {
				if (event.button !== 0 || (event.target as Element).closest('.node, .edge')) return;
				drag.current = { x: event.clientX, y: event.clientY, tx: transform.x, ty: transform.y };
				event.currentTarget.setPointerCapture(event.pointerId);
				setPanning(true);
			}}
			onPointerMove={event => {
				const start = drag.current;
				if (!start) return;
				// Commit the pan before the browser extends a text selection from this move.
				flushSync(() =>
					onPan(current => ({
						...current,
						x: start.tx + event.clientX - start.x,
						y: start.ty + event.clientY - start.y
					}))
				);
			}}
			onPointerUp={() => {
				drag.current = null;
				setPanning(false);
			}}
			onPointerCancel={() => {
				drag.current = null;
				setPanning(false);
			}}
		>
			<defs>
				<marker
					id="arrow"
					viewBox="0 0 10 10"
					refX="9"
					refY="5"
					markerWidth="5"
					markerHeight="5"
					orient="auto-start-reverse"
				>
					<path d="M 0 0 L 10 5 L 0 10 z" />
				</marker>
			</defs>
			<g
				id="viewport"
				transform={`translate(${transform.x} ${transform.y}) scale(${transform.scale})`}
			>
				<g id="edges">
					{edges.map(({ relation, path, visualState }) => (
						<Fragment key={relation.id}>
							<path d={path} className={`edge ${visualState}`} data-relation-id={relation.id} />
							{/* biome-ignore lint/a11y/useSemanticElements: SVG has no button element */}
							<path
								d={path}
								className="edge hit"
								tabIndex={0}
								role="button"
								aria-label={`${relation.predicate || 'relationship'}: ${graph.reference(relation.subjectId)} to ${graph.reference(relation.objectId)}`}
								onClick={event => {
									event.stopPropagation();
									// A mouse click must not leave a focus ring on the shape.
									event.currentTarget.blur();
									onSelect({ type: 'relationship', item: relation });
								}}
								onKeyDown={event => {
									if (isActivation(event)) onSelect({ type: 'relationship', item: relation });
								}}
							/>
						</Fragment>
					))}
					{labels.map(item => (
						<Fragment key={item.relationID}>
							{item.connector ? (
								<line
									x1={item.connector.x1}
									y1={item.connector.y1}
									x2={item.connector.x2}
									y2={item.connector.y2}
									className={`edge-label-connector ${item.visualState}`}
									data-relation-id={item.relationID}
								/>
							) : null}
							<text
								x={item.x}
								y={item.y}
								className={`edge-label ${item.visualState}`}
								data-relation-id={item.relationID}
							>
								{item.text}
							</text>
						</Fragment>
					))}
				</g>
				<g id="nodes">
					{resources.map(resource => {
						const position = positions.get(resource.id);
						if (!position) return null;
						const isSelected = selectedID === resource.id;
						const isEndpoint = selectedEndpoints.has(resource.id);
						const isDim =
							Boolean(selectedID && !isSelected && !neighborIDs.has(resource.id)) ||
							Boolean(selectedRelationID && !isEndpoint);
						const nodeClass = [
							'node',
							isSelected && 'selected',
							isEndpoint && 'related',
							isDim && 'dim'
						]
							.filter(Boolean)
							.join(' ');
						return (
							// biome-ignore lint/a11y/useSemanticElements: SVG has no button element
							<g
								key={resource.id}
								className={nodeClass}
								transform={`translate(${position.x} ${position.y})`}
								tabIndex={0}
								role="button"
								aria-label={`${resource.kind || 'resource'}: ${label(resource)}`}
								onClick={event => {
									event.stopPropagation();
									// A mouse click must not leave a focus ring on the shape.
									event.currentTarget.blur();
									onSelect({ type: 'resource', item: resource });
								}}
								onKeyDown={event => {
									if (isActivation(event)) onSelect({ type: 'resource', item: resource });
								}}
							>
								<rect width={position.width} height={position.height} rx={4} />
								<rect className="kind-band" width={6} height={position.height} rx={2} />
								<title>{`${label(resource)}\n${namespace(resource)} · ${resource.kind || 'unknown'}`}</title>
								<text>
									{position.nameLines.map((line, index) => (
										// biome-ignore lint/suspicious/noArrayIndexKey: wrapped lines have no identity
										<tspan key={index} x={15} y={27 + index * 21}>
											{line}
										</tspan>
									))}
								</text>
								<text className="node-kind">
									{position.metaLines.map((line, index) => (
										// biome-ignore lint/suspicious/noArrayIndexKey: wrapped lines have no identity
										<tspan key={index} x={15} y={30 + position.nameLines.length * 21 + index * 17}>
											{line}
										</tspan>
									))}
								</text>
							</g>
						);
					})}
				</g>
			</g>
		</svg>
	);
}
