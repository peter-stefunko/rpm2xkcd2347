from abc import ABC, abstractmethod

from ..graph.model import DependencyGraph
from .model import PackageMetrics


class MetricsProvider(ABC):
    @abstractmethod
    def fetch(self, graph: DependencyGraph) -> dict[str, PackageMetrics]:
        ...
