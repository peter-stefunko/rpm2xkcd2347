import argparse
import sys
from pathlib import Path

from .graph import analysis as graph_analysis
from .graph import build
from .metrics.null import NullProvider
from .render.dot import DotRenderer
from .render.model import RenderOptions
from .sbom import spdx
from .sbom.spdx import ParsedSbom
from .graph.model import DependencyGraph
from .graph.analysis import AnalysisResult


def _print_dependencies(graph: DependencyGraph) -> None:
    print("\nDependencies:")
    for spdx_id, pkg in sorted(graph.packages.items(), key=lambda x: x[1].name):
        dep_names = sorted(graph.packages[d].name for d in graph.dependencies[spdx_id])
        print(f"{pkg.name}: {', '.join(dep_names)}")


def _print_duplicates(parsed: ParsedSbom) -> None:
    print("\nDuplicate package names:")
    for name, ids in sorted(parsed.duplicates.items()):
        print(f"{name}: {', '.join(sorted(ids))}")


def _print_frequencies(graph: DependencyGraph, analysis: AnalysisResult) -> None:
    print(
        "\nDependency frequencies "
        "(package: dependants - arrows inward, dependencies - arrows outward):"
    )
    for spdx_id, (dependants, deps) in sorted(
        analysis.frequencies.items(), key=lambda x: x[1], reverse=True
    ):
        print(f"{graph.packages[spdx_id].name}: {dependants}, {deps}")


def _print_cycles(graph: DependencyGraph, analysis: AnalysisResult) -> None:
    print("\nCycles:")
    for i, component in enumerate(analysis.cycles, start=1):
        names = sorted(graph.packages[p].name for p in component)
        print(f"{i}: {', '.join(names)}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="rpm2xkcd2347",
        description="Visualize RPM package dependencies from an SPDX 2.3 SBOM.",
    )
    parser.add_argument(
        "sbom",
        metavar="sbom.spdx.json",
        help="SPDX 2.3 JSON SBOM file",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="output .dot file path (default: <sbom-stem>.dot)",
    )
    parser.add_argument(
        "--no-highlight-cycles",
        action="store_true",
        help="do not color cycle participants in the output graph",
    )
    args = parser.parse_args()

    parsed = spdx.load(args.sbom)
    graph = build.build(parsed)
    analysis = graph_analysis.analyze(graph)
    metrics = NullProvider().fetch(graph)

    _print_dependencies(graph)
    _print_duplicates(parsed)
    _print_frequencies(graph, analysis)
    _print_cycles(graph, analysis)

    output_path = args.output or f"{Path(args.sbom).stem}.dot"
    options = RenderOptions(
        output_path=output_path,
        highlight_cycles=not args.no_highlight_cycles,
    )
    DotRenderer().render(graph, analysis, metrics, options)
