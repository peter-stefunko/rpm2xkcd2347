from collections import defaultdict, deque
from dataclasses import dataclass

from ..graph.analysis import AnalysisResult
from ..graph.model import DependencyGraph
from ..metrics.model import PackageMetrics
from .base import Renderer
from .model import RenderOptions

# Note: This entire file currently serves the sole purpose of having at least
# some presentable demo output. All of this will get heavily refactored and is
# not curently worth analyzing at all.

_BLOCK_W = 120
_BLOCK_H = 22
_H_GAP = 3          # horizontal gap between adjacent blocks in one layer
_V_GAP = 2          # vertical gap between layers
_TOWER_GAP = 50     # horizontal gap between disconnected dependency towers
_PADDING = 24       # canvas padding

_FONT_SIZE = 10
_FONT_FAMILY = "monospace"
_BLOCK_FILL = "#ebebeb"
_BLOCK_STROKE = "#aaa"
_TEXT_COLOR = "#333"


@dataclass
class _Block:
    spdx_id: str
    layer: int
    x: float
    width: float


@dataclass
class _Tower:
    blocks: list[_Block]
    width: float
    height: float


class XkcdRenderer(Renderer):
    def render(
        self,
        graph: DependencyGraph,
        analysis: AnalysisResult,
        metrics: dict[str, PackageMetrics],
        options: RenderOptions,
    ) -> None:
        with open(options.output_path, "w", encoding="utf-8") as f:
            f.write(self._build_svg(graph, analysis, metrics))

    def _build_svg(
        self,
        graph: DependencyGraph,
        analysis: AnalysisResult,
        metrics: dict[str, PackageMetrics],
    ) -> str:
        wccs = self._find_wccs(graph)
        towers = [self._layout_tower(wcc, graph, analysis) for wcc in wccs]
        towers.sort(key=lambda t: len(t.blocks), reverse=True)

        svg_w = sum(t.width for t in towers) + (len(towers) - 1) * _TOWER_GAP + 2 * _PADDING
        svg_h = max(t.height for t in towers) + 2 * _PADDING

        parts: list[str] = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<svg xmlns="http://www.w3.org/2000/svg"'
            f' width="{svg_w:.1f}" height="{svg_h:.1f}"'
            f' viewBox="0 0 {svg_w:.1f} {svg_h:.1f}">',
        ]

        x_cursor = float(_PADDING)
        for i, tower in enumerate(towers):
            self._emit_tower(parts, tower, graph, metrics, x_cursor, svg_h, i)
            x_cursor += tower.width + _TOWER_GAP

        parts.append("</svg>")
        return "\n".join(parts)

    def _find_wccs(self, graph: DependencyGraph) -> list[set[str]]:
        adj: dict[str, set[str]] = defaultdict(set)
        for sid, deps in graph.dependencies.items():
            for d in deps:
                adj[sid].add(d)
                adj[d].add(sid)

        visited: set[str] = set()
        components: list[set[str]] = []
        for start in graph.packages:
            if start in visited:
                continue
            component: set[str] = set()
            queue: deque[str] = deque([start])
            while queue:
                node = queue.popleft()
                if node in visited:
                    continue
                visited.add(node)
                component.add(node)
                queue.extend(adj[node])
            components.append(component)
        return components

    def _layout_tower(
        self,
        component: set[str],
        graph: DependencyGraph,
        analysis: AnalysisResult,
    ) -> _Tower:
        layer_pkgs: dict[int, list[str]] = defaultdict(list)
        for sid in component:
            layer_pkgs[analysis.layers[sid]].append(sid)
        for pkgs in layer_pkgs.values():
            pkgs.sort(key=lambda s: graph.packages[s].name)

        max_layer = max(layer_pkgs)

        dependants: dict[str, list[str]] = defaultdict(list)
        for sid in component:
            for dep in analysis.dag.dependencies.get(sid, []):
                if dep in component:
                    dependants[dep].append(sid)

        positions: dict[str, tuple[float, float]] = {}

        top_pkgs = layer_pkgs[max_layer]
        x = 0.0
        for i, sid in enumerate(top_pkgs):
            positions[sid] = (x, x + _BLOCK_W)
            gap = _H_GAP if i < len(top_pkgs) - 1 else 0.0
            if i < len(top_pkgs) - 1:
                next_sid = top_pkgs[i + 1]
                deps_a = set(analysis.dag.dependencies.get(sid, [])) & component
                deps_b = set(analysis.dag.dependencies.get(next_sid, [])) & component
                gap = _H_GAP if deps_a & deps_b else _TOWER_GAP
            x += _BLOCK_W + gap

        tower_width = x

        for layer in range(max_layer - 1, -1, -1):
            pkgs = layer_pkgs.get(layer, [])
            if not pkgs:
                continue

            ideal: dict[str, tuple[float, float]] = {}
            for sid in pkgs:
                placed = [d for d in dependants.get(sid, []) if d in positions]
                if placed:
                    xl = min(positions[d][0] for d in placed)
                    xr = max(positions[d][1] for d in placed)
                else:
                    xl, xr = 0.0, float(_BLOCK_W)
                ideal[sid] = (xl, max(xr, xl + _BLOCK_W))

            sorted_pkgs = sorted(pkgs, key=lambda s: (ideal[s][0], graph.packages[s].name))
            resolved = _resolve_overlaps(sorted_pkgs, ideal)
            positions.update(resolved)

            for xl, xr in resolved.values():
                tower_width = max(tower_width, xr)

        height = (max_layer + 1) * _BLOCK_H + max_layer * _V_GAP
        blocks = [
            _Block(spdx_id=sid, layer=analysis.layers[sid], x=xl, width=xr - xl)
            for sid, (xl, xr) in positions.items()
        ]
        return _Tower(blocks=blocks, width=tower_width, height=height)

    def _emit_tower(
        self,
        parts: list[str],
        tower: _Tower,
        graph: DependencyGraph,
        metrics: dict[str, PackageMetrics],
        x_origin: float,
        svg_h: float,
        tower_idx: int,
    ) -> None:
        tower_bottom = svg_h - _PADDING

        def block_y(layer: int) -> float:
            return tower_bottom - (layer + 1) * _BLOCK_H - layer * _V_GAP

        layers: dict[int, list[_Block]] = defaultdict(list)
        for b in tower.blocks:
            layers[b.layer].append(b)

        parts.append(f'  <g id="tower-{tower_idx}">')
        for layer in sorted(layers):
            parts.append(f'    <g id="tower-{tower_idx}-layer-{layer}">')
            for block in layers[layer]:
                self._emit_block(
                    parts,
                    block,
                    graph,
                    metrics.get(block.spdx_id),
                    x_origin,
                    block_y(layer),
                )
            parts.append("    </g>")
        parts.append("  </g>")

    def _emit_block(
        self,
        parts: list[str],
        block: _Block,
        graph: DependencyGraph,
        pkg_metrics: PackageMetrics | None,
        x_origin: float,
        y: float,
    ) -> None:
        x = x_origin + block.x
        w = block.width
        name = _xml_escape(graph.packages[block.spdx_id].name)
        fill = self._block_fill(pkg_metrics)
        parts.append(
            f'      <rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{_BLOCK_H}"'
            f' fill="{fill}" stroke="{_BLOCK_STROKE}" stroke-width="1" rx="2"/>'
        )
        parts.append(
            f'      <text x="{x + w / 2:.1f}" y="{y + _BLOCK_H / 2:.1f}"'
            f' text-anchor="middle" dominant-baseline="middle"'
            f' font-size="{_FONT_SIZE}" font-family="{_FONT_FAMILY}"'
            f' fill="{_TEXT_COLOR}">{name}</text>'
        )

    def _block_fill(self, pkg_metrics: PackageMetrics | None) -> str:
        return _BLOCK_FILL


def _resolve_overlaps(
    pkgs: list[str],
    ideal: dict[str, tuple[float, float]],
) -> dict[str, tuple[float, float]]:
    result: dict[str, tuple[float, float]] = {}
    i = 0
    while i < len(pkgs):
        combined_left = ideal[pkgs[i]][0]
        combined_right = ideal[pkgs[i]][1]
        group = [pkgs[i]]
        j = i + 1

        grew = True
        while grew:
            grew = False
            while j < len(pkgs) and ideal[pkgs[j]][0] < combined_right:
                combined_right = max(combined_right, ideal[pkgs[j]][1])
                group.append(pkgs[j])
                j += 1
                grew = True

            if j < len(pkgs):
                n = len(group)
                per_w = max(
                    (combined_right - combined_left - (n - 1) * _H_GAP) / n,
                    float(_BLOCK_W),
                )
                resolved_end = combined_left + n * per_w + (n - 1) * _H_GAP
                if ideal[pkgs[j]][0] < resolved_end:
                    combined_right = max(combined_right, ideal[pkgs[j]][1])
                    group.append(pkgs[j])
                    j += 1
                    grew = True

        n = len(group)
        per_w = max(
            (combined_right - combined_left - (n - 1) * _H_GAP) / n,
            float(_BLOCK_W),
        )
        x = combined_left
        for pkg in group:
            result[pkg] = (x, x + per_w)
            x += per_w + _H_GAP

        i = j

    return result


def _xml_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
