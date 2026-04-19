from dataclasses import dataclass, field

from ..sbom.spdx import Package


@dataclass
class DependencyGraph:
    packages: dict[str, Package]        # spdx_id → Package
    dependencies: dict[str, list[str]]  # spdx_id → [dep spdx_id, ...]
