from abc import ABC, abstractmethod

from ..graph.analysis import AnalysisResult
from ..graph.model import DependencyGraph
from ..metrics.model import PackageMetrics
from .model import RenderOptions


class Renderer(ABC):
    @abstractmethod
    def render(
        self,
        graph: DependencyGraph,
        analysis: AnalysisResult,
        metrics: dict[str, PackageMetrics],
        options: RenderOptions,
    ) -> None:
        """Render the dependency graph to an output file.

        The output path and rendering options are taken from options.
        metrics may be empty if no MetricsProvider was used
        """
        ...
