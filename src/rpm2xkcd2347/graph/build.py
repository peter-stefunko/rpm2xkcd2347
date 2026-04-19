from ..sbom.spdx import ParsedSbom
from .model import DependencyGraph


def build(parsed: ParsedSbom) -> DependencyGraph:
    # Ensure every package has an entry in dependencies, even if empty
    dependencies = dict(parsed.dependencies)
    for spdx_id in parsed.packages:
        if spdx_id not in dependencies:
            dependencies[spdx_id] = []
    return DependencyGraph(packages=parsed.packages, dependencies=dependencies)
