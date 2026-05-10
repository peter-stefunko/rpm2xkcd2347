from pathlib import Path
from typing import TextIO

from ..graph.analysis import AnalysisResult
from ..graph.model import DependencyGraph
from ..metrics.model import PackageMetrics
from .base import Renderer
from .model import RenderOptions

class DotRenderer(Renderer):
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

    def render(
        self,
        graph: DependencyGraph,
        analysis: AnalysisResult,
        metrics: dict[str, PackageMetrics],
        options: RenderOptions,
    ) -> None:
        colors = self._node_colors(analysis.cycles) if options.highlight_cycles else {}
        self._write_full_graph(graph, colors, options.output_path)
        self._write_cycle_graphs(graph, analysis.cycles, colors, Path(options.output_path).parent)
        if analysis.fas:
            base = Path(options.output_path)
            self._write_dag(graph, set(analysis.fas), colors, str(base.parent / (base.stem + '.fas.dot')))
            self._write_full_graph(analysis.dag, colors, str(base.parent / (base.stem + '.dag.dot')))

    def _write_node(
        self,
        f: TextIO,
        spdx_id: str,
        graph: DependencyGraph,
        node_colors: dict[str, str],
        visited: set[str],
    ) -> None:
        visited.add(spdx_id)
        name = graph.packages[spdx_id].name
        color = node_colors.get(spdx_id, "white")
        f.write(f'"{spdx_id}" [label="{name}" style=filled fillcolor="{color}"]\n')
        for dep_id in graph.dependencies[spdx_id]:
            f.write(f'"{spdx_id}" -> "{dep_id}"\n')
            if dep_id not in visited:
                self._write_node(f, dep_id, graph, node_colors, visited)

    def _write_full_graph(
        self,
        graph: DependencyGraph,
        node_colors: dict[str, str],
        path: str,
    ) -> None:
        visited: set[str] = set()
        with open(path, "w", encoding="utf-8") as f:
            f.write("digraph Dependencies {\n")
            for spdx_id in graph.packages:
                if spdx_id not in visited:
                    self._write_node(f, spdx_id, graph, node_colors, visited)
            f.write("}\n")

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
            cycle_ids = set(component)
            visited: set[str] = set()
            with open(path, "w", encoding="utf-8") as f:
                f.write("digraph Dependencies {\n")
                self._write_node(f, root, graph, node_colors, visited)
                f.write("}\n")

    def _write_dag(
        self,
        graph: DependencyGraph,
        fas: set[tuple[str, str]],
        node_colors: dict[str, str],
        path: str,
    ) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write("digraph Dependencies {\n")
            for spdx_id, pkg in graph.packages.items():
                color = node_colors.get(spdx_id, "white")
                f.write(f'"{spdx_id}" [label="{pkg.name}" style=filled fillcolor="{color}"]\n')
            for spdx_id in graph.packages:
                for dep_id in graph.dependencies[spdx_id]:
                    if (spdx_id, dep_id) in fas:
                        f.write(f'"{spdx_id}" -> "{dep_id}" [style=dashed color=red]\n')
                    else:
                        f.write(f'"{spdx_id}" -> "{dep_id}"\n')
            f.write("}\n")
