from typing import TextIO

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
        cycle_ids: set[str] = set()
        if options.highlight_cycles:
            for component in analysis.cycles:
                cycle_ids.update(component)

        self._write_full_graph(graph, cycle_ids, options.output_path)
        self._write_cycle_graphs(graph, analysis.cycles)

    def _write_node(
        self,
        f: TextIO,
        spdx_id: str,
        graph: DependencyGraph,
        cycle_ids: set[str],
        visited: set[str],
    ) -> None:
        visited.add(spdx_id)
        name = graph.packages[spdx_id].name
        color = "cyan" if spdx_id in cycle_ids else "white"
        f.write(f'"{spdx_id}" [label="{name}" style=filled fillcolor="{color}"]\n')
        for dep_id in graph.dependencies[spdx_id]:
            f.write(f'"{spdx_id}" -> "{dep_id}"\n')
            if dep_id not in visited:
                self._write_node(f, dep_id, graph, cycle_ids, visited)

    def _write_full_graph(
        self,
        graph: DependencyGraph,
        cycle_ids: set[str],
        path: str,
    ) -> None:
        visited: set[str] = set()
        with open(path, "w", encoding="utf-8") as f:
            f.write("digraph Dependencies {\n")
            for spdx_id in graph.packages:
                if spdx_id not in visited:
                    self._write_node(f, spdx_id, graph, cycle_ids, visited)
            f.write("}\n")

    def _write_cycle_graphs(
        self,
        graph: DependencyGraph,
        cycles: list[list[str]],
    ) -> None:
        for i, component in enumerate(cycles, start=1):
            root = component[0]
            name = graph.packages[root].name
            path = f"cycle{i}-{name}.dot"
            cycle_ids = set(component)  # highlight only this cycle's packages
            visited: set[str] = set()
            with open(path, "w", encoding="utf-8") as f:
                f.write("digraph Dependencies {\n")
                self._write_node(f, root, graph, cycle_ids, visited)
                f.write("}\n")
