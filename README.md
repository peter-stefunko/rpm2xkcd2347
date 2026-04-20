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
  --output, -o FILE     output .dot file path (default: <sbom-stem>.dot)
  --no-highlight-cycles do not color cycle participants in the output graph
```

### Convert output to an image

The output `.dot` file can be converted to an image using [Graphviz](https://graphviz.org/):

```bash
dot -Tsvg <output.dot> -o <output.svg>
```

## License

This project is licensed under the BSD 3-Clause License.  

The complete license text is available in the `LICENSE` file.
