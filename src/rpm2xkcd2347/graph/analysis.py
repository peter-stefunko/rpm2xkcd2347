from collections import defaultdict
from dataclasses import dataclass

from .model import DependencyGraph


@dataclass
class AnalysisResult:
    cycles: list[list[str]]                  # list of cyclic SCCs (spdx_ids)
    frequencies: dict[str, tuple[int, int]]  # spdx_id → (dependants, dependencies)


def _reverse(dependencies: dict[str, list[str]]) -> dict[str, list[str]]:
    rev: dict[str, list[str]] = defaultdict(list)
    for pkg, deps in dependencies.items():
        if pkg not in rev:
            rev[pkg] = []
        for dep in deps:
            rev[dep].append(pkg)
    return dict(rev)


def _push_dfs(
    graph: dict[str, list[str]],
    color: dict[str, str],
    stack: list[str],
    pkg: str,
) -> None:
    color[pkg] = "gray"
    for dep in graph[pkg]:
        if color.get(dep) == "white":
            _push_dfs(graph, color, stack, dep)
    color[pkg] = "black"
    stack.append(pkg)


def _label_dfs(
    rev_graph: dict[str, list[str]],
    color: dict[str, str],
    component: list[str],
    pkg: str,
) -> None:
    color[pkg] = "gray"
    component.append(pkg)
    for dep in rev_graph.get(pkg, []):
        if color.get(dep) == "white":
            _label_dfs(rev_graph, color, component, dep)
    color[pkg] = "black"


def _kosaraju(dependencies: dict[str, list[str]]) -> list[list[str]]:
    rev = _reverse(dependencies)
    packages = list(dependencies.keys())
    color = {pkg: "white" for pkg in packages}
    stack: list[str] = []

    for pkg in packages:
        if color[pkg] == "white":
            _push_dfs(dependencies, color, stack, pkg)

    color = {pkg: "white" for pkg in packages}
    sccs: list[list[str]] = []
    while stack:
        pkg = stack.pop()
        if color[pkg] == "white":
            component: list[str] = []
            _label_dfs(rev, color, component, pkg)
            sccs.append(component)

    return sccs


def _cyclic_sccs(
    dependencies: dict[str, list[str]],
    sccs: list[list[str]],
) -> list[list[str]]:
    cycles = []
    for component in sccs:
        if len(component) >= 2:
            cycles.append(component)
        elif len(component) == 1:
            pkg = component[0]
            if pkg in dependencies.get(pkg, []):
                cycles.append(component)
    return cycles


def _frequencies(dependencies: dict[str, list[str]]) -> dict[str, tuple[int, int]]:
    dependant_count: dict[str, int] = defaultdict(int)
    for deps in dependencies.values():
        for dep in deps:
            dependant_count[dep] += 1
    return {
        pkg: (dependant_count.get(pkg, 0), len(deps))
        for pkg, deps in dependencies.items()
    }


def analyze(graph: DependencyGraph) -> AnalysisResult:
    sccs = _kosaraju(graph.dependencies)
    cycles = _cyclic_sccs(graph.dependencies, sccs)
    frequencies = _frequencies(graph.dependencies)
    return AnalysisResult(cycles=cycles, frequencies=frequencies)
