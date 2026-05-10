from dataclasses import dataclass


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
