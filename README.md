# smpl-bench

Benchmark runner suite for the [SmpL Security](https://github.com/SmpL-Security) engine. Evaluates vulnerability detection accuracy against the **CWE-Bench-Java** dataset — a curated set of real-world CVEs in open-source Java projects.

## Architecture

| File | Purpose |
|---|---|
| `benchmark_common.py` | Shared utilities: Docker lifecycle, CVE project iteration, output isolation, phase execution |
| `run_benchmark_claude.py` | Claude runner — Phase 1 (Haiku triage + CodeQL) → Phase 2 (Sonnet posthoc verdict) |
| `run_benchmark_qwen.py` | Qwen runner — single-phase benchmark using local Qwen model |
| `iris_claude_model.py` | Claude model adapter for the IRIS framework |
| `cwe_bench_manifest.json` | CVE project manifest (Docker images, expected paths, metadata) |

## Prerequisites

- Docker (for CWE-Bench-Java containers)
- Python 3.10+
- `ANTHROPIC_API_KEY` environment variable (for Claude runner)

## Usage

```bash
# Claude benchmark (two-phase: Haiku triage → Sonnet verdict)
python run_benchmark_claude.py --start-project 1 --end-project 10

# Qwen benchmark
python run_benchmark_qwen.py --start-project 1 --end-project 10
```

Results are written to isolated output directories under `/tmp/iris-framework-{model}/data/`.

## License

Private — SmpL Security, Inc.
