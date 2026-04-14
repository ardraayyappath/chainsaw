# Chainsaw

Post-compromise forensic reconstruction for supply chain attacks.

## Paper
[https://zenodo.org/records/19562436]

## Status
Research prototype. Under active development.

## Features
- npm lockfile forensics
- PyPI .pth analysis
- cross-artifact correlation

## Usage
Chainsaw connects to a target host over SSH, collects package-manager and host
artifacts, and writes an HTML and JSON report.

```bash
go build ./cmd/chainsaw

./chainsaw \
  --user eval \
  --key ~/chainsaw-eval/keys/eval_key \
  --port 2201 \
  --ecosystem all \
  --output out \
  127.0.0.1

## Disclaimer
For authorized forensic use only.
