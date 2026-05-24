# smpl-bench

Benchmark runner suite for the [SmpL Security](https://github.com/SmpL-Security) IRIS engine. Evaluates vulnerability detection accuracy against the **CWE-Bench-Java** dataset — a curated set of 118 real-world CVEs across open-source Java projects spanning 7 CWE weakness classes.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Running Benchmarks](#running-benchmarks)
7. [Understanding Results](#understanding-results)
8. [The Two-Phase Pipeline (Claude)](#the-two-phase-pipeline-claude)
9. [Docker Images](#docker-images)
10. [Troubleshooting](#troubleshooting)
11. [Project Manifest](#project-manifest)

---

## Overview

smpl-bench drives the IRIS vulnerability-detection framework against a fixed set of known-vulnerable Java projects and measures how accurately the engine identifies each CVE.

For each test case (one CVE in one project version), the runner:

1. Pulls a pre-built Docker image containing the vulnerable Java project and a pre-compiled CodeQL database.
2. Runs the IRIS analysis pipeline inside that container — CodeQL generates data-flow paths, and an LLM (Claude or Qwen) reasons about whether each path is exploitable.
3. Records a pass/fail verdict, writes stage-level JSON artifacts, and cleans up the Docker resources to avoid disk accumulation.

At the end of a run, results are saved to a single JSON summary file.

### Dataset at a glance

| CWE | Type | Count |
|-----|------|-------|
| CWE-022 | Path Traversal | ~50 |
| CWE-079 | Cross-site Scripting (XSS) | ~25 |
| CWE-094 | Code Injection | ~22 |
| CWE-078 | OS Command Injection | ~10 |
| CWE-918 | Server-Side Request Forgery (SSRF) | 2 |
| CWE-089 | SQL Injection | 2 |
| CWE-502 | Deserialization of Untrusted Data | 1 |
| **Total** | | **118** |

Projects range from 2011 to 2025 CVEs and include Apache, Spring, Keycloak, Jenkins, XWiki, and many other widely-used open-source Java libraries.

---

## Architecture

```
smpl-bench/
├── benchmark_common.py      # Shared core: Docker lifecycle, CVE loading,
│                            #   stage execution, result serialisation
├── run_benchmark_claude.py  # Claude runner (two-phase: Haiku → Sonnet)
├── run_benchmark_qwen.py    # Qwen runner (single-phase: Qwen Coder)
├── iris_claude_model.py     # Claude adapter for the IRIS LLM interface
└── cwe_bench_manifest.json  # 118-entry CVE manifest
```

### `benchmark_common.py`

The shared foundation imported by both runners. Provides:

| Component | Description |
|-----------|-------------|
| `BenchmarkConfig` | Dataclass holding all runtime settings: data directories, Docker limits, model names, CVE filters. Each runner gets an isolated base directory under `/tmp/iris-framework-{runner}/data/`. |
| `CVEProject` | Dataclass representing one CVE test case: CVE ID, project name, image tag, CWE IDs, and metadata. Derives the Docker image name `irissast/cwe-bench-java-containers-v2:<slug>` and container name from the CVE ID. |
| `load_cve_projects()` | Parses `cwe_bench_manifest.json` and applies `--include`/`--exclude` CVE ID filters. |
| `docker_run()` | Thin wrapper around `docker run` with memory limits and volume/env injection. |
| `docker_cleanup()` | Removes a container and its image; always called in a `finally` block so resources are freed even on failure. |
| `run_iris_stage()` | Launches one IRIS analysis stage inside Docker, forwarding auth tokens and data-directory volume mounts. |
| `rebuild_codeql_db()` | Rebuilds the CodeQL database for a project when it's absent or incomplete. Required before Phase 2 when earlier stages were cached. |
| `is_stage_cached()` | Returns `True` when `results/<cve_id>/stage{N}.json` already exists on disk, allowing incremental reruns to skip completed work. |
| `CVEResult` / `save_results()` | Track per-CVE outcomes and serialise the final benchmark summary to JSON. |
| `setup_logging()` | Configures timestamped structured logging; `--verbose` enables `DEBUG` level. |

### `run_benchmark_claude.py`

The Claude runner. Implements a **two-phase** strategy:

- **Phase 1** (stages 1–7): Claude Haiku performs initial triage and drives the CodeQL data-flow analysis.
- **Phase 2** (stage 8): Claude Sonnet applies the posthoc filter to produce the final vulnerability verdict.

Key behaviours:
- Reads `CLAUDE_CODE_OAUTH_TOKEN` from the environment; falls back to `/root/workspace/bridge-demo/.env` if not set.
- Always passes `--overwrite-posthoc-filter` to stage 8 to prevent a known empty-iterator failure when Phase 1 results are cached.
- Cleans up all Docker containers and images in a `finally` block after each CVE.

### `run_benchmark_qwen.py`

The Qwen runner. Implements a **single-phase** strategy: one model (`qwen-coder` by default) handles all 8 stages. Applies the same `--overwrite-posthoc-filter` fix for stage 8 and the same Docker cleanup discipline.

### `iris_claude_model.py`

Claude adapter that plugs into the IRIS `LLM` base class. Key features:

| Feature | Detail |
|---------|--------|
| **Model aliases** | `claude-sonnet` → `claude-sonnet-4-20250514`; `claude-haiku` → `claude-haiku-4-5-20251001` |
| **Auth priority** | `anthropic_api_key` kwarg → `CLAUDE_CODE_OAUTH_TOKEN` env → `ANTHROPIC_API_KEY` env |
| **Transport selection** | OAT token + `claude` CLI on PATH → CLI mode (preferred, higher rate limits). OAT token without CLI → Bearer/httpx. API key → `anthropic` SDK. |
| **CLI mode** | Invokes `claude -p --model <alias> --system-prompt … --output-format text --no-session-persistence`. Uses Claude Code infrastructure, which has higher effective rate limits than raw API calls. |
| **Retry logic** | Up to 5 retries with exponential back-off on transient errors (overloaded, rate limit, 429). CLI calls time out after 600 s per request. |
| **Concurrency** | Batch prediction uses `thread_map`; CLI mode caps concurrency at 2 to avoid hammering the endpoint. |

### `cwe_bench_manifest.json`

The 118-entry CVE registry. Each entry describes one test case. See [Project Manifest](#project-manifest) for the schema.

---

## Prerequisites

### Docker

Docker Engine must be installed and the daemon must be running. The runner pulls images from Docker Hub automatically.

```bash
docker --version   # any recent Engine version works
docker info        # daemon must respond
```

### Python

Python 3.10 or later is required (the code uses `str | None` union syntax and `list[str]` generics without `from __future__ import annotations`).

Install Python dependencies:

```bash
pip install anthropic httpx tqdm
```

The `iris_claude_model.py` adapter also imports from the IRIS framework (`src.models.llm`, `src.utils.mylogger`). Those modules are provided by the IRIS framework installation that the Docker containers expect on their Python path — you only need them locally if you are running `iris_claude_model.py` directly outside a container.

### API Keys

**Claude runner** — one of the following must be set:

| Variable | Description |
|----------|-------------|
| `CLAUDE_CODE_OAUTH_TOKEN` | OAuth Access Token (starts with `sk-ant-oat`). **Preferred** — routes through Claude Code infrastructure with higher rate limits. |
| `ANTHROPIC_API_KEY` | Standard Anthropic API key. Fallback when no OAT token is present. |

If neither is in the environment, the Claude runner checks `/root/workspace/bridge-demo/.env` before exiting with an error.

**Qwen runner** — no Anthropic key needed. The Qwen model is loaded inside the Docker container; ensure your Qwen endpoint or local model is reachable from within the container.

### System Requirements

| Resource | Requirement |
|----------|-------------|
| **RAM** | Each Docker container is limited to 4 GB (`--memory 4g`). Running one container at a time (the default, sequential) requires ~4 GB free. Do not run the Claude and Qwen runners simultaneously against the same machine without raising available RAM. |
| **Disk** | Each CVE image is 1–4 GB depending on project size. Running the full suite sequentially pulls ~118 images. Images are deleted after each CVE, so peak disk usage is roughly the size of the largest single image (~4 GB) plus the accumulated CodeQL databases and result artifacts in `/tmp/iris-framework-{runner}/`. Allow at least 20 GB of free disk. |
| **CPU** | No hard requirement. CodeQL database building (inside the container) is CPU-intensive; a machine with ≥ 4 cores finishes stages faster. |
| **OS** | Linux (native Docker). macOS with Docker Desktop works but is slower due to VM overhead. Windows is not tested. |
| **Network** | Outbound HTTPS to `registry.hub.docker.com` (image pulls) and `api.anthropic.com` (Claude API calls). |

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/SmpL-Security/smpl-bench.git
cd smpl-bench

# 2. (Optional) Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install Python dependencies
pip install anthropic httpx tqdm

# 4. Verify Docker is running
docker info

# 5. Set your Anthropic credentials (Claude runner only)
export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat...
# OR
export ANTHROPIC_API_KEY=sk-ant-api...
```

---

## Configuration

All configuration is passed via CLI flags; there are no config files to edit. The environment variables below are the only external requirements.

### Environment variables

| Variable | Runner | Required | Description |
|----------|--------|----------|-------------|
| `CLAUDE_CODE_OAUTH_TOKEN` | Claude | Preferred | OAT token for Claude API access. Enables CLI-mode routing with higher rate limits. |
| `ANTHROPIC_API_KEY` | Claude | Fallback | Standard API key. Used when `CLAUDE_CODE_OAUTH_TOKEN` is absent. |
| `IRIS_USE_RAW_API` | Claude | No | Set to `1` to force the httpx Bearer path even when the `claude` CLI is available on PATH. |

### Output directories (automatic)

Directories are created automatically under `/tmp/` before the first CVE runs.

| Runner | Base directory |
|--------|---------------|
| Claude | `/tmp/iris-framework-claude/data/` |
| Qwen | `/tmp/iris-framework-qwen/data/` |

Each base directory contains:

```
<base>/
├── codeql-dbs/      # CodeQL databases, one sub-directory per CVE ID
├── results/         # Stage artifacts (stage{N}.json) and final summary
└── cache/           # Intermediate cached data
```

The two runners use **isolated** directories so that running them concurrently or sequentially never causes one runner to delete a CodeQL database the other runner needs.

---

## Running Benchmarks

### Claude runner

```
python run_benchmark_claude.py --manifest <path> [options]
```

**Required flag:**

| Flag | Description |
|------|-------------|
| `--manifest PATH` | Path to the CVE manifest JSON file (e.g. `cwe_bench_manifest.json`). |

**Optional flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--output PATH` | `<base_data_dir>/results/claude_results.json` | Where to write the final results JSON. |
| `--base-data-dir PATH` | `/tmp/iris-framework-claude/data` | Override the base output directory. |
| `--include CVE-ID …` | _(all)_ | Space-separated list of CVE IDs to run. All others are skipped. |
| `--exclude CVE-ID …` | _(none)_ | Space-separated list of CVE IDs to skip. |
| `--docker-timeout N` | `600` | Maximum seconds a single Docker container may run before it is killed. |
| `--docker-memory MEM` | `4g` | Docker memory limit per container (Docker notation: `4g`, `2048m`, etc.). |
| `--phase1-model NAME` | `claude-haiku` | IRIS model alias for Phase 1 (stages 1–7). |
| `--phase2-model NAME` | `claude-sonnet` | IRIS model alias for Phase 2 (stage 8). |
| `--overwrite-posthoc-filter` | `True` | Force stage 8 to re-run even when earlier stages are cached. Should always be `True`; changing it can cause empty-iterator failures. |
| `--verbose` / `-v` | off | Enable `DEBUG`-level logging (very verbose; useful for diagnosing failures). |

### Qwen runner

```
python run_benchmark_qwen.py --manifest <path> [options]
```

Same flags as the Claude runner, except:

| Flag | Default | Description |
|------|---------|-------------|
| `--model NAME` | `qwen-coder` | Model for all 8 stages (Qwen is single-phase). |

The `--phase1-model` / `--phase2-model` / `--overwrite-posthoc-filter` flags are replaced by `--model`.

---

### Example commands

**Quick smoke test — 3 CVEs:**

```bash
python run_benchmark_claude.py \
  --manifest cwe_bench_manifest.json \
  --include CVE-2022-31192 CVE-2022-42889 CVE-2020-17530 \
  --verbose
```

**Run a specific CWE class (all path-traversal CVEs):**

You can assemble your own include list from the manifest. For example, to run only CWE-022 entries, pass the relevant CVE IDs with `--include`.

**Full suite — Claude runner:**

```bash
python run_benchmark_claude.py \
  --manifest cwe_bench_manifest.json \
  --output /results/claude_$(date +%Y%m%d).json
```

**Full suite — Qwen runner:**

```bash
python run_benchmark_qwen.py \
  --manifest cwe_bench_manifest.json \
  --output /results/qwen_$(date +%Y%m%d).json
```

**Override models:**

```bash
python run_benchmark_claude.py \
  --manifest cwe_bench_manifest.json \
  --phase1-model claude-haiku \
  --phase2-model claude-sonnet
```

**Custom output directory:**

```bash
python run_benchmark_claude.py \
  --manifest cwe_bench_manifest.json \
  --base-data-dir /mnt/data/iris-claude
```

---

### What happens during a run

For each CVE project in the manifest (in order):

1. **Docker pull** — the container image `irissast/cwe-bench-java-containers-v2:<slug>` is pulled from Docker Hub if not already cached locally. (First pull can take several minutes per image.)
2. **Stage loop** — stages 1–7 (Phase 1) run sequentially. Each stage launches a Docker container with the `iris-analyze` command, passing the CVE ID, stage number, and volume-mounted output directories.
   - If `results/<cve_id>/stage{N}.json` already exists on disk, that stage is skipped (cached run resumption).
3. **Phase 2** (Claude runner only) — stage 8 runs with Sonnet to apply the posthoc verdict filter. The CodeQL database is rebuilt if it is no longer present on disk.
4. **Docker cleanup** — the container and its image are force-removed from the local Docker registry so disk does not accumulate. Per-stage containers (`*-stage{N}`) are also cleaned up.
5. **Result recorded** — a `CVEResult` entry (pass/fail, phase reached, stage reached, wall-clock time, any error) is appended to the in-memory list.

After all CVEs complete, the results are saved to the output JSON file and a summary line is logged.

---

### Expected runtime and API cost estimates

These are rough estimates; actual numbers depend on project complexity, model latency, and Docker pull times.

| Scope | Duration | Claude API cost |
|-------|----------|-----------------|
| 3 CVEs (smoke test) | 10–30 min | < $0.10 |
| 20 CVEs | 1–3 hours | $0.50–$2.00 |
| Full suite (118 CVEs) | 12–24 hours | $5–$20 |

Phase 1 (Haiku) is cheap; Phase 2 (Sonnet) costs more but runs only once per CVE. The largest cost driver is Phase 1 prompt volume across 7 CodeQL stages.

---

## Understanding Results

### Output files

After a run, two categories of output exist under the base data directory:

**1. Per-CVE stage artifacts** — written by the IRIS framework inside each container and volume-mounted back to the host:

```
/tmp/iris-framework-claude/data/results/<CVE-ID>/
    stage1.json   # IRIS stage 1 output
    stage2.json
    …
    stage8.json   # Posthoc verdict (Claude runner)
```

These JSON files are produced by the IRIS framework. Their internal schema is defined by the IRIS codebase, not by smpl-bench; fields typically include `num_vulnerable_paths`, per-path verdicts, and LLM reasoning.

**2. Benchmark summary** — written by smpl-bench at the end of the run:

```
/tmp/iris-framework-claude/data/results/claude_results.json
```

### Summary file schema

```json
{
  "timestamp": "2026-05-24T10:00:00Z",
  "total": 118,
  "passed": 95,
  "failed": 23,
  "results": [
    {
      "cve_id": "CVE-2022-31192",
      "passed": true,
      "phase": 2,
      "stage_reached": 8,
      "duration_secs": 412.5,
      "error": null
    },
    {
      "cve_id": "CVE-2019-0222",
      "passed": false,
      "phase": 1,
      "stage_reached": 3,
      "duration_secs": 87.2,
      "error": "Stage 3 failed with exit code 1"
    }
  ]
}
```

### Field descriptions

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | ISO-8601 UTC timestamp when results were saved. |
| `total` | int | Number of CVEs attempted. |
| `passed` | int | CVEs that completed all stages successfully. |
| `failed` | int | CVEs that encountered an error in at least one stage. |
| `results[].cve_id` | string | The CVE identifier. |
| `results[].passed` | bool | `true` if all phases completed without error. |
| `results[].phase` | int | Last phase attempted: `1` = Phase 1 only, `2` = both phases (Claude runner). Qwen always records `1`. |
| `results[].stage_reached` | int | Highest stage number that was attempted (1–8). A failure at stage 3 records `3`. |
| `results[].duration_secs` | float | Wall-clock seconds for this CVE, including Docker pull time and all stage runtimes. |
| `results[].error` | string\|null | Error message from the first failing stage, or `null` on success. |

### Interpreting scores

A **passed** result means the IRIS framework completed all 8 stages without a non-zero exit code for that CVE. Whether the engine's verdict was correct (true positive vs false positive/negative) is determined by comparing IRIS's stage 8 posthoc verdict against the ground-truth label in the CWE-Bench-Java dataset — that comparison lives in the IRIS evaluation layer, not in smpl-bench itself.

A **failed** result indicates an infrastructure error (Docker issue, timeout, CodeQL failure, API error) rather than necessarily a wrong vulnerability verdict.

---

## The Two-Phase Pipeline (Claude)

The Claude runner applies a deliberate two-model strategy to balance cost and accuracy:

```
┌──────────────────────────────────────────────────┐
│  Phase 1: Haiku triage (stages 1–7)              │
│                                                  │
│  Stage 1: CodeQL query selection                 │
│  Stage 2: CodeQL database build (if needed)      │
│  Stage 3: CodeQL analysis run                    │
│  Stage 4: Path extraction                        │
│  Stage 5: LLM path triage (Haiku)                │
│  Stage 6: Candidate filtering                    │
│  Stage 7: Pre-verdict ranking                    │
└─────────────────────┬────────────────────────────┘
                      │ Pass/fail
                      ▼
┌──────────────────────────────────────────────────┐
│  Phase 2: Sonnet verdict (stage 8)               │
│                                                  │
│  Stage 8: Posthoc filter + final verdict (Sonnet)│
└──────────────────────────────────────────────────┘
```

**Why two phases?**
- Stages 1–7 generate and filter many candidate paths. Claude Haiku is fast and cheap for this bulk triage work.
- Stage 8 makes the final exploitability verdict, where higher reasoning quality matters. Claude Sonnet provides better accuracy for this decision.

**Stage caching and resumption**

Each stage writes its output to `results/<cve_id>/stage{N}.json`. If a run is interrupted, restarting the runner will skip completed stages and resume from the first missing one. Stage 8 is always re-run (`--overwrite-posthoc-filter` is `True` by default) because a partial Phase 2 state can leave stale completion markers that would cause the posthoc filter to silently produce an empty result set.

**CodeQL database availability**

The CodeQL database is built inside the Docker container during Phase 1 and volume-mounted to the host. If Phase 1 results are cached from a prior run (but the database was cleaned up), `rebuild_codeql_db()` will relaunch the container to recreate the database before Phase 2 runs.

---

## Docker Images

Each CVE project has a dedicated pre-built Docker image hosted on Docker Hub under the `irissast/cwe-bench-java-containers-v2` repository:

```
irissast/cwe-bench-java-containers-v2:<slug>
```

Where `<slug>` is the `slug` field from the manifest, for example:

```
irissast/cwe-bench-java-containers-v2:apache__struts_CVE-2020-17530_2.5.25
```

Each image contains:
- The vulnerable version of the Java project (source code and compiled artifacts).
- A pre-built CodeQL database (`db-java/`) for that project version.
- The IRIS analysis toolchain (`iris-analyze`, `codeql-db-build`, CodeQL CLI).

Images are pulled on demand during the run and force-removed from the local registry after each CVE completes. This keeps peak disk usage bounded to roughly the largest single image rather than accumulating all 118 images simultaneously.

If a pull fails (network error, image not found), `docker run` will return a non-zero exit code, the stage will be marked as failed with the Docker error message, and the runner will move on to the next CVE.

---

## Troubleshooting

### Docker daemon not running

```
Error response from daemon: Cannot connect to the Docker daemon at unix:///var/run/docker.sock.
```

Start the Docker daemon:
```bash
sudo systemctl start docker     # Linux (systemd)
open -a Docker                  # macOS
```

Verify: `docker info`

---

### Out of memory — container killed

```
Stage N failed with exit code 137
```

Exit code 137 means the container was OOM-killed. Either raise the memory limit:

```bash
python run_benchmark_claude.py --manifest cwe_bench_manifest.json --docker-memory 8g
```

Or close other memory-consuming processes on the host before running.

---

### API key not found

```
ERROR: CLAUDE_CODE_OAUTH_TOKEN is not set.
```

Export your token before running:

```bash
export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat...
python run_benchmark_claude.py --manifest cwe_bench_manifest.json
```

Or add it to `/root/workspace/bridge-demo/.env` (on the SmpL Security VPS), and the runner will load it automatically.

---

### Container image pull failure

```
Unable to find image 'irissast/cwe-bench-java-containers-v2:<slug>' locally
Error response from daemon: pull access denied
```

Ensure you are logged in to Docker Hub:

```bash
docker login
```

If the image tag does not exist, verify the `slug` field in `cwe_bench_manifest.json` matches the tag published to Docker Hub.

---

### Stage fails at 99–100% with empty iterator

This is a known issue with cached Phase 1 results. It is fixed by the default `--overwrite-posthoc-filter True` behaviour. If you see it, confirm the flag is not being overridden and that `stage8.json` is not left in a partially-written state; delete it and rerun.

---

### Disk full mid-run

If a run is interrupted before Docker cleanup completes, orphaned containers and images may remain:

```bash
# List orphaned bench containers
docker ps -a --filter "name=cwe-bench-"

# Remove them
docker rm -f $(docker ps -aq --filter "name=cwe-bench-")

# Remove orphaned images
docker images --filter "reference=irissast/cwe-bench-java-containers-v2*" -q | xargs docker rmi -f
```

---

### Verbose logging

Pass `--verbose` (or `-v`) for `DEBUG`-level output, which prints the exact `docker run` command for each stage and full stderr from failing containers:

```bash
python run_benchmark_claude.py --manifest cwe_bench_manifest.json --include CVE-2022-31192 --verbose
```

---

## Project Manifest

`cwe_bench_manifest.json` is a single JSON object with a `projects` array. Each entry describes one CVE test case.

### Schema

```json
{
  "projects": [
    {
      "slug":    "<org>__<repo>_<CVE-ID>_<version>",
      "cve_id":  "CVE-YYYY-NNNNN",
      "cwe_id":  "CWE-NNN",
      "query":   "cwe-NNNwLLM"
    }
  ]
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `slug` | Yes | Unique identifier used as the Docker image tag: `irissast/cwe-bench-java-containers-v2:<slug>`. Format: `{org}__{repo}_{CVE-ID}_{version}`. |
| `cve_id` | Yes | The CVE identifier (e.g. `CVE-2022-31192`). Used as the container name prefix and the output directory name. |
| `cwe_id` | Yes | The primary CWE weakness class (e.g. `CWE-022`). Stored as metadata. |
| `query` | Yes | The IRIS CodeQL query template to use (e.g. `cwe-022wLLM`). Stored as metadata and passed to the analysis stages. |
| `project` | No | Human-readable project name. Defaults to `slug` if omitted. |
| `image_tag` | No | Override the Docker image tag. Defaults to `slug`. |
| `language` | No | Source language. Defaults to `"java"`. |
| `cwe_ids` | No | List of CWE IDs when a CVE maps to multiple weaknesses. Takes precedence over `cwe_id`. |
| `metadata` | No | Arbitrary key-value pairs forwarded to the analysis stages. |

### Adding a new project

1. Build and push a Docker image to `irissast/cwe-bench-java-containers-v2:<slug>` containing the vulnerable project, its CodeQL database, and the IRIS toolchain.

2. Add an entry to `cwe_bench_manifest.json`:

```json
{
  "slug":   "myorg__myrepo_CVE-2024-12345_1.0.0",
  "cve_id": "CVE-2024-12345",
  "cwe_id": "CWE-079",
  "query":  "cwe-079wLLM"
}
```

3. Test the single entry:

```bash
python run_benchmark_claude.py \
  --manifest cwe_bench_manifest.json \
  --include CVE-2024-12345 \
  --verbose
```

---

## License

Private — SmpL Security, Inc.
