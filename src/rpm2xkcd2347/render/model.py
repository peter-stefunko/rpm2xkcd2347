from dataclasses import dataclass


@dataclass
class RenderOptions:
    output_path: str
    highlight_cycles: bool = True
