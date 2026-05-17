from ..graph.model import DependencyGraph
from .base import MetricsProvider
from .model import PackageMetrics


class NullProvider(MetricsProvider):
    def fetch(self, graph: DependencyGraph) -> dict[str, PackageMetrics]:
        return {}
