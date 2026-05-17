from abc import ABC, abstractmethod

from ..graph.model import DependencyGraph
from .model import PackageMetrics


class MetricsProvider(ABC):
    @abstractmethod
    def fetch(self, graph: DependencyGraph) -> dict[str, PackageMetrics]:
        """Fetch health metrics for all packages in the graph.

        Returns a dict mapping spdx_id to PackageMetrics. Packages for which
        no data is available may be absent from the result.
        """
        ...
