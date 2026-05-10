import json
from pathlib import Path

from .base import SbomParser
from .spdx.spdx23 import Spdx23Parser


def detect(path: str | Path) -> SbomParser:
    """Return the appropriate parser for the given SBOM file.

    Peeks at the top-level fields of the JSON to identify the format and
    version, then returns the matching parser. Raises ValueError if the
    format is not recognised or not yet supported.
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    spdx_version = data.get("spdxVersion", "")
    if spdx_version == "SPDX-2.3":
        return Spdx23Parser()

    raise ValueError(f"Unsupported SBOM format: {spdx_version!r}.")
