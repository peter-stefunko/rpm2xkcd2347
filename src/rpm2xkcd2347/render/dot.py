from pathlib import Path

from ..graph.analysis import AnalysisResult
from ..graph.model import DependencyGraph
from ..metrics.model import PackageMetrics
from .base import Renderer
from .model import RenderOptions


class DotRenderer(Renderer):
    def render(
        self,
        graph: DependencyGraph,
        analysis: AnalysisResult,
        metrics: dict[str, PackageMetrics],
        options: RenderOptions,
    ) -> None:
        colors = self._node_colors(analysis.cycles) if options.highlight_cycles else {}
        base = Path(options.output_path)
        self._write_graph(graph, colors, options.output_path)
        self._write_cycle_graphs(graph, analysis.cycles, colors, base.parent)
        if analysis.fas:
            fas_set = set(analysis.fas)
            self._write_graph(graph, colors, str(base.parent / (base.stem + '.fas.dot')), fas=fas_set)
            self._write_graph(analysis.dag, colors, str(base.parent / (base.stem + '.dag.dot')))

    def _node_colors(self, cycles: list[list[str]]) -> dict[str, str]:
        palette = [
            "cyan", "coral", "lightgreen", "gold", "orchid",
            "salmon", "turquoise", "tomato", "deepskyblue", "khaki",
        ]
        colors: dict[str, str] = {}
        for i, component in enumerate(cycles):
            for spdx_id in component:
                colors[spdx_id] = palette[i % len(palette)]
        return colors

    def _write_graph(
        self,
        graph: DependencyGraph,
        node_colors: dict[str, str],
        path: str,
        fas: set[tuple[str, str]] | None = None,
        node_filter: set[str] | None = None,
    ) -> None:
        nodes = node_filter if node_filter is not None else set(graph.packages)
        with open(path, "w", encoding="utf-8") as f:
            f.write("digraph Dependencies {\n")
            for spdx_id in nodes:
                pkg = graph.packages[spdx_id]
                color = node_colors.get(spdx_id, "white")
                f.write(f'"{spdx_id}" [label="{pkg.name}" style=filled fillcolor="{color}"]\n')
            for spdx_id in nodes:
                for dep_id in graph.dependencies[spdx_id]:
                    if dep_id not in nodes:
                        continue
                    if fas and (spdx_id, dep_id) in fas:
                        f.write(f'"{spdx_id}" -> "{dep_id}" [style=dashed color=red]\n')
                    else:
                        f.write(f'"{spdx_id}" -> "{dep_id}"\n')
            f.write("}\n")

    def _reachable(self, graph: DependencyGraph, root: str) -> set[str]:
        visited: set[str] = set()
        stack = [root]
        while stack:
            node = stack.pop()
            if node in visited:
                continue
            visited.add(node)
            stack.extend(graph.dependencies[node])
        return visited

    def _write_cycle_graphs(
        self,
        graph: DependencyGraph,
        cycles: list[list[str]],
        node_colors: dict[str, str],
        out_dir: Path,
    ) -> None:
        for i, component in enumerate(cycles, start=1):
            root = component[0]
            name = graph.packages[root].name
            path = str(out_dir / f"cycle{i}-{name}.dot")
            self._write_graph(graph, node_colors, path, node_filter=self._reachable(graph, root))
