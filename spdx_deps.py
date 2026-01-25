#!/usr/bin/env python3

import json
import os
import sys
from collections import defaultdict
from typing import Any, TextIO


def print_dependencies(dependencies: dict[str, list[str]],
                       components: dict[str, str]) -> None:
    for spdx_id, name in components.items():
        dep_names = [components[d] for d in sorted(dependencies[spdx_id])]
        print(f"{name}: {', '.join(dep_names)}")


def print_duplicates(duplicates: dict[str, set[str]]) -> None:
    for name, spdx_ids in duplicates.items():
        print(f"{name}: {', '.join(sorted(spdx_ids))}")


def print_frequencies(frequencies: dict[str, tuple[int, int]],
                      components: dict[str, str]) -> None:
    for spdx_id, freq in sorted(frequencies.items(), key=lambda item: item[1],
                                reverse=True):
        dependant, dependencies = freq
        print(f"{components[spdx_id]}: {dependant}, {dependencies}")


def get_components(sbom: dict[str, Any]) -> dict[str, str]:
    components = {}

    for pkg in sbom.get("packages", []):
        spdx_id = pkg.get("SPDXID")
        name = pkg.get("name", spdx_id)
        if spdx_id and not spdx_id.startswith("SPDXRef-DocumentRoot"):
            components[spdx_id] = name

    return components


def get_dependencies(sbom: dict[str, Any],
                     components: dict[str, str]) -> dict[str, list[str]]:
    dependencies = defaultdict(list)

    for rs in sbom.get("relationships", []):
        if rs.get("relationshipType") != "DEPENDENCY_OF":
            continue

        dependency = rs.get("spdxElementId")
        dependent = rs.get("relatedSpdxElement")
        dependencies[dependent].append(dependency)

    for spdx_id in components:
        if spdx_id not in dependencies:
            dependencies[spdx_id] = []

    return dependencies


def get_duplicates(components: dict[str, str]) -> dict[str, set[str]]:
    duplicates: dict[str, set[str]] = defaultdict(set)

    for spdx_id, name in components.items():
        for spdx_id2, name2 in components.items():
            if name == name2 and spdx_id != spdx_id2:
                if len(duplicates[name]) == 0:
                    duplicates[name].add(spdx_id)
                duplicates[name].add(spdx_id2)

    return duplicates


def get_spdx_ids(pkg_name: str,
                 components: dict[str, str]) -> list[str]:
    ids = []

    for spdx_id, name in components.items():
        if name == pkg_name:
            ids.append(spdx_id)

    return ids


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


def draw_dependencies(dependencies: dict[str, list[str]],
                      components: dict[str, str],
                      filename: str) -> None:
    with open(filename, "w", encoding="utf-8") as f:
        f.write("digraph Dependencies {\n")

        visited: set[str] = set()
        for spdx_id in components:
            if spdx_id not in visited:
                draw_component(spdx_id, dependencies, components, visited, f)

        f.write("}\n")


def draw_component(spdx_id: str,
                   dependencies: dict[str, list[str]],
                   components: dict[str, str],
                   visited: set[str],
                   f: TextIO) -> None:
    visited.add(spdx_id)
    f.write(f'"{spdx_id}" [label="{components[spdx_id]}"]\n')

    for dep_id in dependencies[spdx_id]:
        f.write(f'"{spdx_id}" -> "{dep_id}"\n')
        if dep_id not in visited:
            draw_component(dep_id, dependencies, components, visited, f)


def main(argv: list[str]) -> None:
    sbom_path = argv[1]

    with open(sbom_path, "r", encoding="utf-8") as s:
        sbom = json.load(s)

    components = get_components(sbom)
    dependencies = get_dependencies(sbom, components)
    duplicates = get_duplicates(components)
    frequencies = get_dependency_frequencies(dependencies)

    print("\nDependencies (component: dependencies):")
    print_dependencies(dependencies, components)

    print("\nDuplicate Component Names:")
    print_duplicates(duplicates)

    print("\nDependency Frequencies (dependants - arrows inward, "
          "dependencies - arrows outward):")
    print_frequencies(frequencies, components)

    filename = "dependencies.dot"
    dir_path = os.path.dirname(os.path.realpath(__file__))
    draw_dependencies(dependencies, components, filename)
    print(f"\n.dot file saved to {dir_path}/{filename}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: spdx_deps.py <sbom.spdx.json>")
        sys.exit(1)

    main(sys.argv)
