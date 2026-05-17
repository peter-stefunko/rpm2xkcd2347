from collections import defaultdict, deque
from dataclasses import dataclass

from .model import DependencyGraph


@dataclass
class AnalysisResult:
    cycles: list[list[str]]                  # list of cyclic SCCs (spdx_ids)
    frequencies: dict[str, tuple[int, int]]  # spdx_id -> (dependants, dependencies)
    fas: list[tuple[str, str]]               # feedback arc set: edges to remove to break all cycles
    dag: DependencyGraph                     # graph with FAS edges removed (directed acyclic graph)
    layers: dict[str, int]                   # spdx_id -> topological layer (0 = no dependencies)


def analyze(graph: DependencyGraph) -> AnalysisResult:
    """Analyze a dependency graph and return cycles and dependency frequencies."""
    sccs = _kosaraju(graph.dependencies)
    cycles = _cyclic_sccs(graph.dependencies, sccs)
    frequencies = _frequencies(graph.dependencies)
    fas = _greedy_fas(graph.dependencies)
    fas_set = set(fas)
    dag_deps = {
        spdx_id: [d for d in deps if (spdx_id, d) not in fas_set]
        for spdx_id, deps in graph.dependencies.items()
    }
    dag = DependencyGraph(packages=graph.packages, dependencies=dag_deps)
    layers = _topological_layers(dag)
    return AnalysisResult(cycles=cycles, frequencies=frequencies, fas=fas, dag=dag, layers=layers)


def _topological_layers(dag: DependencyGraph) -> dict[str, int]:
    rev = _reverse(dag.dependencies)
    remaining_deps = {spdx_id: len(deps) for spdx_id, deps in dag.dependencies.items()}
    layers: dict[str, int] = {spdx_id: 0 for spdx_id in dag.packages}
    queue: deque[str] = deque(spdx_id for spdx_id, count in remaining_deps.items() if count == 0)

    while queue:
        node = queue.popleft()
        for dependant in rev.get(node, []):
            layers[dependant] = max(layers[dependant], layers[node] + 1)
            remaining_deps[dependant] -= 1
            if remaining_deps[dependant] == 0:
                queue.append(dependant)

    return layers


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
    visited: set[str],
    stack: list[str],
    pkg: str,
) -> None:
    visited.add(pkg)
    for dep in graph[pkg]:
        if dep not in visited:
            _push_dfs(graph, visited, stack, dep)
    stack.append(pkg)


def _label_dfs(
    rev_graph: dict[str, list[str]],
    visited: set[str],
    component: list[str],
    pkg: str,
) -> None:
    visited.add(pkg)
    component.append(pkg)
    for dep in rev_graph.get(pkg, []):
        if dep not in visited:
            _label_dfs(rev_graph, visited, component, dep)


def _kosaraju(dependencies: dict[str, list[str]]) -> list[list[str]]:
    rev = _reverse(dependencies)
    packages = list(dependencies.keys())
    visited: set[str] = set()
    stack: list[str] = []

    for pkg in packages:
        if pkg not in visited:
            _push_dfs(dependencies, visited, stack, pkg)

    visited = set()
    sccs: list[list[str]] = []
    while stack:
        pkg = stack.pop()
        if pkg not in visited:
            component: list[str] = []
            _label_dfs(rev, visited, component, pkg)
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


def _greedy_fas(dependencies: dict[str, list[str]]) -> list[tuple[str, str]]:
    rev = _reverse(dependencies)
    nodes = list(dependencies.keys())
    outdeg = {u: len(dependencies.get(u, [])) for u in nodes}
    indeg = {u: len(rev.get(u, [])) for u in nodes}

    s1: list[str] = []
    s2: list[str] = []
    remaining = set(nodes)

    def remove(u: str) -> None:
        remaining.discard(u)
        for v in dependencies.get(u, []):
            if v in remaining:
                indeg[v] -= 1
        for w in rev.get(u, []):
            if w in remaining:
                outdeg[w] -= 1

    while remaining:
        while True:
            sink = next((u for u in remaining if outdeg[u] == 0), None)
            if sink is None:
                break
            s2.insert(0, sink)
            remove(sink)
        while True:
            source = next((u for u in remaining if indeg[u] == 0), None)
            if source is None:
                break
            s1.append(source)
            remove(source)
        if not remaining:
            break
        u = max(remaining, key=lambda u: outdeg[u] - indeg[u])
        s1.append(u)
        remove(u)

    rank = {node: i for i, node in enumerate(s1 + s2)}
    return [
        (u, v)
        for u, deps in dependencies.items()
        for v in deps
        if rank[u] > rank[v]
    ]
