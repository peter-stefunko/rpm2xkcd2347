#!/usr/bin/env python3

import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, TextIO


def reverse_graph(graph: dict[str, list[str]]) -> dict[str, list[str]]:
    rev: dict[str, list[str]] = defaultdict(list)

    for pkg, dependencies in graph.items():
        for dep in dependencies:
            if dep not in rev:
                rev[dep] = []
            rev[dep].append(pkg)

    return rev


def push_dfs(graph: dict[str, list[str]],
             color: dict[str, str],
             stack: list[str],
             pkg: str) -> None:
    color[pkg] = "gray"

    for dep in graph[pkg]:
        if color[dep] == "white":
            push_dfs(graph, color, stack, dep)

    color[pkg] = "black"
    stack.append(pkg)


def label_dfs(rev_graph: dict[str, list[str]],
              color: dict[str, str],
              scc_pkgs: list[str],
              pkg: str) -> None:
    color[pkg] = "gray"
    scc_pkgs.append(pkg)

    for dep in rev_graph[pkg]:
        if color[dep] == "white":
            label_dfs(rev_graph, color, scc_pkgs, dep)

    color[pkg] = "black"


def get_sccs_kosaraju(graph: dict[str, list[str]]) -> list[list[str]]:
    rev_graph = reverse_graph(graph)
    packages = list(graph.keys())
    color: dict[str, str] = {pkg: "white" for pkg in packages}
    stack: list[str] = []

    for pkg in packages:
        if color[pkg] == "white":
            push_dfs(graph, color, stack, pkg)

    color = {pkg: "white" for pkg in packages}
    sccs: list[list[str]] = []

    while stack:
        pkg = stack.pop()

        if color[pkg] == "white":
            scc_pkgs: list[str] = []
            label_dfs(rev_graph, color, scc_pkgs, pkg)
            sccs.append(scc_pkgs)

    return sccs


def get_cyclic_sccs(graph: dict[str, list[str]]) -> list[list[str]]:
    sccs = get_sccs_kosaraju(graph)
    cycles: list[list[str]] = []

    for pkgs in sccs:
        if len(pkgs) >= 2:
            cycles.append(pkgs)
        elif len(pkgs) == 1:
            pkg = pkgs[0]
            if pkg in graph[pkg]:
                cycles.append(pkgs)

    return cycles


def get_packages(sbom: dict[str, Any]) -> dict[str, str]:
    packages = {}

    for pkg in sbom.get("packages", []):
        spdx_id = pkg.get("SPDXID")
        name = pkg.get("name", spdx_id)
        if spdx_id and not spdx_id.startswith("SPDXRef-DocumentRoot"):
            packages[spdx_id] = name

    return packages


def get_package_spdx_ids(pkg_name: str,
                         packages: dict[str, str]) -> list[str]:
    ids = []

    for spdx_id, name in packages.items():
        if name == pkg_name:
            ids.append(spdx_id)

    return ids


def get_dependencies(sbom: dict[str, Any],
                     packages: dict[str, str]) -> dict[str, list[str]]:
    dependencies = defaultdict(list)

    for rs in sbom.get("relationships", []):
        if rs.get("relationshipType") != "DEPENDENCY_OF":
            continue

        dependency = rs.get("spdxElementId")
        dependent = rs.get("relatedSpdxElement")
        dependencies[dependent].append(dependency)

    for spdx_id in packages:
        if spdx_id not in dependencies:
            dependencies[spdx_id] = []

    return dependencies


def get_duplicates(packages: dict[str, str]) -> dict[str, set[str]]:
    duplicates: dict[str, set[str]] = defaultdict(set)

    for spdx_id, name in packages.items():
        for spdx_id2, name2 in packages.items():
            if name == name2 and spdx_id != spdx_id2:
                if len(duplicates[name]) == 0:
                    duplicates[name].add(spdx_id)
                duplicates[name].add(spdx_id2)

    return duplicates


def get_dependency_frequencies(dependencies: dict[str, list[str]]) \
                               -> dict[str, tuple[int, int]]:
    frequencies: dict[str, tuple[int, int]] = defaultdict(lambda: (0, 0))

    for deps in dependencies.values():
        for dep_id in deps:
            dependent, _ = frequencies[dep_id]
            frequencies[dep_id] = (dependent + 1, len(dependencies[dep_id]))

    for spdx_id, deps in dependencies.items():
        if spdx_id not in frequencies:
            frequencies[spdx_id] = (0, len(deps))

    return frequencies


def print_dependencies(dependencies: dict[str, list[str]],
                       packages: dict[str, str]) -> None:
    print("\nDependencies:")

    for spdx_id, name in packages.items():
        dep_names = [packages[dep] for dep in sorted(dependencies[spdx_id])]
        print(f"{name}: {', '.join(dep_names)}")


def print_duplicates(duplicates: dict[str, set[str]]) -> None:
    print("\nDuplicate package names:")

    for name, spdx_ids in duplicates.items():
        print(f"{name}: {', '.join(sorted(spdx_ids))}")


def print_frequencies(frequencies: dict[str, tuple[int, int]],
                      packages: dict[str, str]) -> None:
    print("\nDependency frequencies (package: dependants - arrows inward, "
          "dependencies - arrows outward):")

    for spdx_id, freq in sorted(frequencies.items(), key=lambda item: item[1],
                                reverse=True):
        dependant, dependencies = freq
        print(f"{packages[spdx_id]}: {dependant}, {dependencies}")


def print_cycles(cycles: list[list[str]],
                 packages: dict[str, str]) -> None:
    print("\nCycles:")

    for i, group in enumerate(cycles, start=1):
        cycle_pkgs = [f"{packages[pkg]}" for pkg in sorted(group)]
        print(f"{i}: {', '.join(cycle_pkgs)}")


def draw_package(spdx_id: str,
                 dependencies: dict[str, list[str]],
                 packages: dict[str, str],
                 to_highlight: list[str],
                 visited: set[str],
                 f: TextIO) -> None:
    visited.add(spdx_id)

    if spdx_id in to_highlight:
        color = "cyan"
    else:
        color = "white"

    f.write(f'"{spdx_id}" ['
            f'label="{packages[spdx_id]}" '
            f'style=filled '
            f'fillcolor="{color}"'
            f']\n')

    for dep_id in dependencies[spdx_id]:
        f.write(f'"{spdx_id}" -> "{dep_id}"\n')
        if dep_id not in visited:
            draw_package(dep_id, dependencies, packages, to_highlight, visited,
                         f)


def draw_dependencies_package(dependencies: dict[str, list[str]],
                              packages: dict[str, str],
                              pkg_spdx_id: str,
                              to_highlight: list[str],
                              filename: str) -> None:
    with open(filename, "w", encoding="utf-8") as f:
        f.write("digraph Dependencies {\n")
        draw_package(pkg_spdx_id, dependencies, packages, to_highlight, set(),
                     f)
        f.write("}\n")


def draw_dependencies_all(dependencies: dict[str, list[str]],
                          packages: dict[str, str],
                          filename: str) -> None:
    with open(filename, "w", encoding="utf-8") as f:
        f.write("digraph Dependencies {\n")

        visited: set[str] = set()
        for spdx_id in packages:
            if spdx_id not in visited:
                draw_package(spdx_id, dependencies, packages, [], visited, f)

        f.write("}\n")


def draw_cycles(dependencies: dict[str, list[str]],
                packages: dict[str, str],
                cycles: list[list[str]]) -> None:
    for i, c in enumerate(cycles):
        pkg_spdx_id = c[0]
        pkg_name = packages[pkg_spdx_id]
        draw_dependencies_package(dependencies, packages, pkg_spdx_id, c,
                                  f'cycle{i + 1}-{pkg_name}.dot')


def main(argv: list[str]) -> None:
    sbom_path = argv[1]

    with open(sbom_path, "r", encoding="utf-8") as s:
        sbom = json.load(s)

    packages = get_packages(sbom)
    dependencies = get_dependencies(sbom, packages)
    duplicates = get_duplicates(packages)
    frequencies = get_dependency_frequencies(dependencies)
    cycles = get_cyclic_sccs(dependencies)

    print_dependencies(dependencies, packages)
    print_duplicates(duplicates)
    print_frequencies(frequencies, packages)
    print_cycles(cycles, packages)

    draw_dependencies_all(dependencies, packages,
                          f"{Path(sbom_path).stem}.dot")
    draw_cycles(dependencies, packages, cycles)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: spdx_deps.py <sbom.spdx.json>")
        sys.exit(1)

    main(sys.argv)
