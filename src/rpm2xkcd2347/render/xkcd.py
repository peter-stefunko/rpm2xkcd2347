import random
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass

from ..graph.analysis import AnalysisResult
from ..graph.model import DependencyGraph
from ..metrics.model import PackageMetrics
from .base import Renderer
from .model import RenderOptions

# Note: This entire file currently serves the sole purpose of having at least
# some presentable demo output. All of this will get heavily refactored and is
# not curently worth analyzing at all.

_BLOCK_W = 70
_BLOCK_H = _BLOCK_W * 1.4
_H_GAP = 3          # horizontal gap between adjacent blocks in one layer
_V_GAP = 1          # vertical gap between layers
_TOWER_GAP = 50     # horizontal gap between disconnected dependency towers
_PADDING = 24       # canvas padding

_FONT_SIZE = 10
_FONT_FAMILY = "monospace"
_BLOCK_FILL = "#e1e1e1"
_BLOCK_STROKE = "#000"
_BLOCK_STROKE_W = 2
_TEXT_COLOR = "#333"

_WOBBLE_SCALE = 2


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

        x_cursor = _PADDING
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

        excl_parent: dict[str, str | None] = {}
        for sid in component:
            deps_of = [d for d in dependants.get(sid, []) if d in component]
            excl_parent[sid] = deps_of[0] if len(deps_of) == 1 else None

        natural_w: dict[str, float] = {}
        for layer in range(max_layer + 1):
            for sid in layer_pkgs.get(layer, []):
                excl_deps = sorted(
                    (d for d in analysis.dag.dependencies.get(sid, [])
                     if d in component and excl_parent.get(d) == sid),
                    key=lambda d: graph.packages[d].name,
                )
                if not excl_deps:
                    natural_w[sid] = float(_BLOCK_W)
                else:
                    w = sum(natural_w[d] for d in excl_deps)
                    w += sum(
                        _sibling_gap(excl_deps[i], excl_deps[i + 1], analysis, component)
                        for i in range(len(excl_deps) - 1)
                    )
                    natural_w[sid] = max(w, float(_BLOCK_W))

        positions: dict[str, tuple[float, float]] = {}

        def gap_fn(a: str, b: str) -> float:
            return _sibling_gap(a, b, analysis, component)

        top_pkgs = layer_pkgs[max_layer]
        x = 0.0
        for i, sid in enumerate(top_pkgs):
            positions[sid] = (x, x + natural_w[sid])
            if i < len(top_pkgs) - 1:
                x += natural_w[sid] + gap_fn(sid, top_pkgs[i + 1])
            else:
                x += natural_w[sid]
        tower_width = x

        for layer in range(max_layer - 1, -1, -1):
            pkgs = layer_pkgs.get(layer, [])
            if not pkgs:
                continue

            ideal: dict[str, tuple[float, float]] = {}
            orphans: list[str] = []
            for sid in pkgs:
                placed = [d for d in dependants.get(sid, []) if d in positions]
                if placed:
                    xl = min(positions[d][0] for d in placed)
                    xr = max(positions[d][1] for d in placed)
                else:
                    xl, xr = 0.0, float(_BLOCK_W)
                    orphans.append(sid)
                ideal[sid] = (xl, max(xr, xl + natural_w.get(sid, float(_BLOCK_W))))

            non_orphan_set = set(pkgs) - set(orphans)
            for orphan in orphans:
                orphan_deps = set(analysis.dag.dependencies.get(orphan, [])) & component
                for candidate in sorted(non_orphan_set, key=lambda s: graph.packages[s].name):
                    if orphan_deps & (set(analysis.dag.dependencies.get(candidate, [])) & component):
                        ideal[orphan] = ideal[candidate]
                        break

            sorted_pkgs = sorted(pkgs, key=lambda s: (ideal[s][0], graph.packages[s].name))
            resolved = _resolve_overlaps_nw(sorted_pkgs, ideal, natural_w, gap_fn)
            positions.update(resolved)
            for xl, xr in resolved.values():
                tower_width = max(tower_width, xr)

        top_ideal: dict[str, tuple[float, float]] = {}
        for sid in top_pkgs:
            dep_placed = [
                d for d in analysis.dag.dependencies.get(sid, [])
                if d in positions and d in component
            ]
            if dep_placed:
                xl = min(positions[d][0] for d in dep_placed)
                xr = max(positions[d][1] for d in dep_placed)
                top_ideal[sid] = (xl, max(xr, xl + natural_w.get(sid, float(_BLOCK_W))))
            else:
                top_ideal[sid] = positions[sid]
        sorted_top = sorted(top_pkgs, key=lambda s: (top_ideal[s][0], graph.packages[s].name))
        positions.update(_resolve_overlaps_nw(sorted_top, top_ideal, natural_w, gap_fn))
        tower_width = max(xr for _, xr in positions.values())

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
        path = _wobbly_rect(x, y, w, _BLOCK_H, block.spdx_id)
        parts.append(
            f'      <path d="{path}"'
            f' fill="{fill}" stroke="{_BLOCK_STROKE}" stroke-width="{_BLOCK_STROKE_W}"/>'
        )
        parts.append(
            f'      <text x="{x + w / 2:.1f}" y="{y + _BLOCK_H / 2:.1f}"'
            f' text-anchor="middle" dominant-baseline="middle"'
            f' font-size="{_FONT_SIZE}" font-family="{_FONT_FAMILY}"'
            f' fill="{_TEXT_COLOR}">{name}</text>'
        )

    def _block_fill(self, pkg_metrics: PackageMetrics | None) -> str:
        return _BLOCK_FILL


def _sibling_gap(
    a: str,
    b: str,
    analysis: AnalysisResult,
    component: set[str],
) -> float:
    deps_a = set(analysis.dag.dependencies.get(a, [])) & component
    deps_b = set(analysis.dag.dependencies.get(b, [])) & component
    return float(_H_GAP) if deps_a & deps_b else float(_TOWER_GAP)


def _resolve_overlaps_nw(
    pkgs: list[str],
    ideal: dict[str, tuple[float, float]],
    natural_w: dict[str, float],
    gap_fn: "Callable[[str, str], float]",
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
                total_w = sum(natural_w.get(p, _BLOCK_W) for p in group)
                total_gaps = sum(gap_fn(group[k], group[k + 1]) for k in range(len(group) - 1))
                resolved_end = combined_left + total_w + total_gaps
                if ideal[pkgs[j]][0] < resolved_end:
                    combined_right = max(combined_right, ideal[pkgs[j]][1])
                    group.append(pkgs[j])
                    j += 1
                    grew = True

        if len(group) == 1:
            result[group[0]] = (combined_left, combined_right)
        else:
            x = combined_left
            for k, pkg in enumerate(group):
                w = natural_w.get(pkg, _BLOCK_W)
                result[pkg] = (x, x + w)
                if k < len(group) - 1:
                    x += w + gap_fn(pkg, group[k + 1])
                else:
                    x += w

        i = j
    return result


def _wobbly_rect(x: float, y: float, w: float, h: float, spdx_id: str) -> str:
    rng = random.Random(spdx_id)

    def jitter(scale: float) -> float:
        return (rng.random() * 2.0 - 1.0) * scale

    c = _WOBBLE_SCALE
    s = _WOBBLE_SCALE * 1.2

    tl = (x + jitter(c),     y + jitter(c))
    tr = (x + w + jitter(c), y + jitter(c))
    br = (x + w + jitter(c), y + h + jitter(c))
    bl = (x + jitter(c),     y + h + jitter(c))

    def ctrl(p1: tuple[float, float], p2: tuple[float, float]) -> tuple[float, float]:
        mx, my = (p1[0] + p2[0]) / 2.0, (p1[1] + p2[1]) / 2.0
        dx, dy = p2[0] - p1[0], p2[1] - p1[1]
        length = (dx * dx + dy * dy) ** 0.5
        px, py = (-dy / length, dx / length) if length else (0.0, 0.0)
        bow = jitter(s)
        return (mx + px * bow, my + py * bow)

    ct, cr, cb, cl = ctrl(tl, tr), ctrl(tr, br), ctrl(br, bl), ctrl(bl, tl)
    return (
        f'M {tl[0]:.1f},{tl[1]:.1f} '
        f'Q {ct[0]:.1f},{ct[1]:.1f} {tr[0]:.1f},{tr[1]:.1f} '
        f'Q {cr[0]:.1f},{cr[1]:.1f} {br[0]:.1f},{br[1]:.1f} '
        f'Q {cb[0]:.1f},{cb[1]:.1f} {bl[0]:.1f},{bl[1]:.1f} '
        f'Q {cl[0]:.1f},{cl[1]:.1f} {tl[0]:.1f},{tl[1]:.1f} Z'
    )


def _xml_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
