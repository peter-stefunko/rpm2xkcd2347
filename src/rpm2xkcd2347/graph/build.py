from ..sbom.model import ParsedSbom
from .model import DependencyGraph


def build(parsed: ParsedSbom) -> DependencyGraph:
    """Build a DependencyGraph from a parsed SBOM.

    Ensures every package has an entry in the dependencies dict, so callers
    can always look up a package's dependencies without checking for key
    existence first.
    """
    dependencies = dict(parsed.dependencies)
    for spdx_id in parsed.packages:
        if spdx_id not in dependencies:
            dependencies[spdx_id] = []
    return DependencyGraph(packages=parsed.packages, dependencies=dependencies)
