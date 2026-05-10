from abc import ABC, abstractmethod
from pathlib import Path

from .model import ParsedSbom


class SbomParser(ABC):
    @abstractmethod
    def load(self, path: str | Path) -> ParsedSbom:
        """Parse the SBOM file at path and return its packages and dependency relationships."""
