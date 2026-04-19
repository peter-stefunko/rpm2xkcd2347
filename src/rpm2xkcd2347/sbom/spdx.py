import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class Package:
    spdx_id: str
    name: str
    version: str | None = None
    purl: str | None = None


@dataclass
class ParsedSbom:
    packages: dict[str, Package]        # spdx_id → Package
    dependencies: dict[str, list[str]]  # spdx_id → [dep spdx_id, ...]
    duplicates: dict[str, list[str]]    # name → [spdx_id, ...] (only names with >1 package)


def _parse_packages(raw: list[dict[str, Any]]) -> dict[str, Package]:
    packages: dict[str, Package] = {}
    for entry in raw:
        spdx_id = entry.get("SPDXID")
        if not spdx_id or spdx_id.startswith("SPDXRef-DocumentRoot"):
            continue
        name = entry.get("name", spdx_id)
        version = entry.get("versionInfo")
        purl = next(
            (
                ref["referenceLocator"]
                for ref in entry.get("externalRefs", [])
                if ref.get("referenceType") == "purl"
            ),
            None,
        )
        packages[spdx_id] = Package(spdx_id=spdx_id, name=name, version=version, purl=purl)
    return packages


def _parse_dependencies(
    raw: list[dict[str, Any]],
    packages: dict[str, Package],
) -> dict[str, list[str]]:
    dependencies: dict[str, list[str]] = defaultdict(list)
    for rs in raw:
        if rs.get("relationshipType") != "DEPENDENCY_OF":
            continue
        dependency = rs.get("spdxElementId")
        dependent = rs.get("relatedSpdxElement")
        if dependency in packages and dependent in packages:
            dependencies[dependent].append(dependency)
    return dict(dependencies)


def _find_duplicates(packages: dict[str, Package]) -> dict[str, list[str]]:
    name_to_ids: dict[str, list[str]] = defaultdict(list)
    for spdx_id, pkg in packages.items():
        name_to_ids[pkg.name].append(spdx_id)
    return {name: ids for name, ids in name_to_ids.items() if len(ids) > 1}


def load(path: str | Path) -> ParsedSbom:
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    packages = _parse_packages(raw.get("packages", []))
    dependencies = _parse_dependencies(raw.get("relationships", []), packages)
    duplicates = _find_duplicates(packages)
    return ParsedSbom(packages=packages, dependencies=dependencies, duplicates=duplicates)
