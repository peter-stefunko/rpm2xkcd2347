import argparse

from dataclasses import fields
from dotenv import load_dotenv
from pathlib import Path

from .graph import analysis as graph_analysis
from .graph import build
from .graph.analysis import AnalysisResult
from .graph.model import DependencyGraph
from .metrics.base import MetricsProvider
from .metrics.ossf_criticality_score_go import OssfCriticalityScoreGoProvider
from .metrics.model import PackageMetrics
from .metrics.null import NullProvider
from .render.dot import DotRenderer
from .render.model import RenderOptions
from .sbom.detect import detect as detect_parser
from .sbom.model import ParsedSbom


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


def _print_signals(graph: DependencyGraph, metrics: dict[str, PackageMetrics]) -> None:
    if not metrics:
        return
    print("\nRepository signals:")
    for spdx_id, pkg in sorted(graph.packages.items(), key=lambda x: x[1].name):
        m = metrics.get(spdx_id)
        if m is None or m.signals is None:
            continue
        s = m.signals
        print(f"  {pkg.name} ({s.repo_url}):")
        for field in fields(s):
            if field.name == 'repo_url':
                continue
            print(f"    {field.name}: {getattr(s, field.name)}")


def _print_metrics(graph: DependencyGraph, metrics: dict[str, PackageMetrics]) -> None:
    if not metrics:
        return
    print("\nMetrics (name: repository, criticality score):")
    for spdx_id, pkg in sorted(graph.packages.items(), key=lambda x: x[1].name):
        m = metrics.get(spdx_id)
        if m is None or m.signals is None:
            continue
        score = f"{m.criticality_score:.5f}" if m.criticality_score is not None else "n/a"
        print(f"  {pkg.name}: {m.signals.repo_url} ({score})")


def _build_provider(metrics_arg: str) -> MetricsProvider:
    if metrics_arg == 'ossf-criticality-go':
        return OssfCriticalityScoreGoProvider()
    return NullProvider()


def _build_parser() -> argparse.ArgumentParser:
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
        help="output .dot file path (default: out/<sbom-stem>.dot)",
    )
    parser.add_argument(
        "--no-highlight-cycles",
        action="store_true",
        help="do not color cycle participants in the output graph",
    )
    parser.add_argument(
        "--print",
        dest="print_sections",
        action="append",
        default=[],
        choices=["dependencies", "duplicates", "frequencies", "cycles", "signals", "metrics"],
        metavar="SECTION",
        help=(
            "print a section to stdout; can be repeated. "
            "choices: dependencies, duplicates, frequencies, cycles, signals, metrics"
        ),
    )
    parser.add_argument(
        "--metrics",
        choices=["none", "ossf-criticality-go"],
        default="none",
        help=(
            "metrics provider: 'ossf-criticality-go' resolves each package's upstream "
            "repository via Anitya and computes the OpenSSF Criticality Score using "
            "the criticality_score Go binary (requires GITHUB_AUTH_TOKEN). "
            "Default: none."
        ),
    )
    return parser


def main() -> None:
    args = _build_parser().parse_args()

    load_dotenv(Path(args.sbom).parent / '.env')

    parsed = detect_parser(args.sbom).load(args.sbom)
    graph = build.build(parsed)
    analysis = graph_analysis.analyze(graph)
    metrics = _build_provider(args.metrics).fetch(graph)

    sections = set(args.print_sections)
    if "dependencies" in sections:
        _print_dependencies(graph)
    if "duplicates" in sections:
        _print_duplicates(parsed)
    if "frequencies" in sections:
        _print_frequencies(graph, analysis)
    if "cycles" in sections:
        _print_cycles(graph, analysis)
    if "signals" in sections:
        _print_signals(graph, metrics)
    if "metrics" in sections:
        _print_metrics(graph, metrics)

    sbom_stem = Path(args.sbom).stem
    out_dir = Path("out") / sbom_stem
    out_dir.mkdir(parents=True, exist_ok=True)
    output_path = args.output or str(out_dir / f"{sbom_stem}.dot")
    options = RenderOptions(
        output_path=output_path,
        highlight_cycles=not args.no_highlight_cycles,
    )
    DotRenderer().render(graph, analysis, metrics, options)
