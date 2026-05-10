# rpm2xkcd2347

## Project Description

rpm2xkcd2347 is a program that generates a visual representation of dependencies from a list of RPM packages in a two-dimensional layout inspired by the image of Randall Munroe - [xkcd2347 Dependency](https://xkcd.com/2347).  

This is a project developed as part of a bachelor’s thesis.  

Author: Peter Štefunko

## Obtaining an SBOM

Any SPDX 2.3 JSON SBOM can be used as input. One way to generate one is with [syft](https://github.com/anchore/syft).

For example, to generate an SBOM from Red Hat Universal Base Image (UBI) 9.7:

```bash
syft registry.access.redhat.com/ubi9:9.7 -o spdx-json@2.3 > ubi9_7.spdx.json
```

An example SBOM is also available in the `examples/` directory.

## Usage

### Setup

```bash
uv sync
```

### Run

```bash
uv run rpm2xkcd2347 <sbom.spdx.json>
```

### Options

```
positional arguments:
  sbom.spdx.json        SPDX 2.3 JSON SBOM file

options:
  -h, --help            show this help message and exit
  --output, -o FILE     output .dot file path (default: out/<sbom-stem>/<sbom-stem>.dot)
  --no-highlight-cycles
                        do not color cycle participants in the output graph
  --print SECTION       print a section to stdout; can be repeated.
                        choices: dependencies, duplicates, frequencies, cycles, signals, metrics
  --metrics {none,criticality-go}
                        metrics provider: 'criticality-go' resolves each package's upstream
                        GitHub repository via Anitya and computes the OpenSSF Criticality
                        Score using the criticality_score Go binary (requires GITHUB_AUTH_TOKEN).
                        Default: none.
```

### Output files

All output files are written to `out/<sbom-stem>/` by default:

| File | Description |
|---|---|
| `<sbom-stem>.dot` | Full dependency graph with cycles highlighted in color |
| `<sbom-stem>.fas.dot` | Full graph with feedback arc set edges drawn dashed-red |
| `<sbom-stem>.dag.dot` | Acyclic graph with feedback arc set edges removed |
| `cycle<N>-<name>.dot` | Subgraph for each individual cycle |

### Metrics: OpenSSF Criticality Score

The `--metrics criticality-go` option scores each package using the [OpenSSF Criticality Score](https://github.com/ossf/criticality_score) project. It requires the `criticality_score` binary to be installed:

```bash
go install github.com/ossf/criticality_score/v2/cmd/criticality_score@latest
```

A GitHub access token must also be available, either in a `.env` file next to the SBOM or as an environment variable:

```bash
export GITHUB_AUTH_TOKEN=<your token>
```

### Convert output to an image

The output `.dot` file can be converted to an image using [Graphviz](https://graphviz.org/):

```bash
dot -Tsvg <output.dot> -o <output.svg>
```

## License

This project is licensed under the BSD 3-Clause License.  

The complete license text is available in the `LICENSE` file.
