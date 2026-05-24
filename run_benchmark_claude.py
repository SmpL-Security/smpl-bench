#!/usr/bin/env python3
"""
CWE-Bench-Java benchmark runner — Claude variant.

Phase 1: Claude Haiku for initial triage + CodeQL analysis (stages 1-7).
Phase 2: Claude Sonnet for posthoc filtering + final verdict (stage 8).

Fixes applied:
  1. Docker container + image cleanup after every CVE (finally block).
  2. Phase 2 forces --overwrite-posthoc-filter to avoid empty iterator
     when earlier stages are cached. Also rebuilds CodeQL DB if needed.
  3. Isolated output directory (/tmp/iris-framework-claude/data/) so the
     Qwen runner can't delete databases this runner needs.
"""

import argparse
import logging
import os
import sys
import time
from pathlib import Path

from benchmark_common import (
    BenchmarkConfig,
    CVEProject,
    CVEResult,
    docker_cleanup,
    docker_run,
    is_stage_cached,
    load_cve_projects,
    rebuild_codeql_db,
    run_iris_stage,
    save_results,
    setup_logging,
)

logger = logging.getLogger("cwe-bench.claude")

# Default models for the two-phase Claude pipeline
PHASE1_MODEL = "claude-haiku"
PHASE2_MODEL = "claude-sonnet"


def run_phase1(config: BenchmarkConfig, project: CVEProject) -> tuple[bool, int, str | None]:
    """
    Phase 1: Run stages 1-7 with Claude Haiku.

    Returns (success, last_stage_completed, error_message).
    """
    for stage in range(1, 8):
        if is_stage_cached(config, project, stage):
            logger.info("[%s] Stage %d cached, skipping", project.cve_id, stage)
            continue

        logger.info("[%s] Running Phase 1 stage %d", project.cve_id, stage)
        result = run_iris_stage(stage, config, project)

        if result.returncode != 0:
            error = result.stderr.strip() or f"Stage {stage} failed with exit code {result.returncode}"
            logger.error("[%s] Phase 1 stage %d failed: %s", project.cve_id, stage, error)
            return False, stage, error

        logger.info("[%s] Stage %d complete", project.cve_id, stage)

    return True, 7, None


def run_phase2(config: BenchmarkConfig, project: CVEProject) -> tuple[bool, int, str | None]:
    """
    Phase 2: Run stage 8 (posthoc filter) with Claude Sonnet.

    Fix 2: When Phase 1 results are cached, the posthoc filter stage may
    produce an empty iterator because it thinks stage 8 already ran (when
    in reality, a prior run called exit(1) and never completed it). We
    force --overwrite-posthoc-filter to ensure stage 8 always re-runs.

    We also ensure the CodeQL database exists — it may have been cleaned
    up by a prior run's Docker cleanup or by the Qwen runner.
    """
    stage = 8

    # Fix 2: Ensure CodeQL database is available for Phase 2.
    # When Phase 1 was cached from a prior run, the DB might have been
    # removed during that run's cleanup, or the Qwen runner might have
    # deleted it (before Fix 3 was applied).
    if not rebuild_codeql_db(config, project):
        return False, stage, "Failed to rebuild CodeQL DB for Phase 2"

    # Fix 2: Always pass --overwrite-posthoc-filter for Phase 2.
    # This forces stage 8 to re-run even when earlier stages are cached,
    # preventing the empty iterator error at 99-100% progress.
    # Without this flag, the script sees cached Phase 1 results, assumes
    # stage 8 was already done, and calls exit(1) — leaving Phase 2
    # in a broken state where the posthoc filter never actually executes.
    extra_args = [
        "--overwrite-posthoc-filter",
        "--model", PHASE2_MODEL,
        "--phase", "2",
    ]

    # Also request DB rebuild in the stage itself in case the container
    # needs a fresh database reference.
    extra_args.append("--rebuild-db-if-missing")

    logger.info("[%s] Running Phase 2 stage %d (posthoc filter) with %s",
                project.cve_id, stage, PHASE2_MODEL)

    result = run_iris_stage(stage, config, project, extra_args=extra_args)

    if result.returncode != 0:
        error = result.stderr.strip() or f"Stage {stage} posthoc filter failed"
        logger.error("[%s] Phase 2 stage %d failed: %s", project.cve_id, stage, error)
        return False, stage, error

    logger.info("[%s] Phase 2 complete", project.cve_id)
    return True, stage, None


def run_cve_project(config: BenchmarkConfig, project: CVEProject) -> CVEResult:
    """
    Run both phases for a single CVE project.

    Fix 1: Docker containers and images are cleaned up in a finally block
    so they don't accumulate even when the analysis fails.
    """
    start = time.monotonic()
    container_name = project.container_name
    image_name = project.image_name

    try:
        # Phase 1: Haiku triage + CodeQL (stages 1-7)
        p1_ok, p1_stage, p1_err = run_phase1(config, project)
        if not p1_ok:
            return CVEResult(
                cve_id=project.cve_id,
                passed=False,
                phase=1,
                stage_reached=p1_stage,
                duration_secs=time.monotonic() - start,
                error=p1_err,
            )

        # Phase 2: Sonnet posthoc filter (stage 8)
        p2_ok, p2_stage, p2_err = run_phase2(config, project)
        return CVEResult(
            cve_id=project.cve_id,
            passed=p2_ok,
            phase=2,
            stage_reached=p2_stage,
            duration_secs=time.monotonic() - start,
            error=p2_err,
        )

    finally:
        # Fix 1: ALWAYS clean up Docker resources after each CVE completes,
        # regardless of pass/fail. Without this, containers and images
        # accumulate and eventually fill the disk.
        logger.info("[%s] Cleaning up Docker resources", project.cve_id)
        docker_cleanup(container_name, image_name)

        # Also clean up any per-stage containers that might be leftover
        for stage in range(1, 9):
            stage_container = f"{container_name}-stage{stage}"
            docker_cleanup(stage_container, "")


def _load_env_file(path: str) -> dict[str, str]:
    """Parse a KEY=VALUE .env file, ignoring comments and blank lines."""
    env = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                # Strip optional surrounding quotes
                value = value.strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                    value = value[1:-1]
                env[key] = value
    except FileNotFoundError:
        pass
    return env


def _ensure_claude_token() -> None:
    """
    Ensure CLAUDE_CODE_OAUTH_TOKEN is available in os.environ.

    Checks the host environment first. If not set, attempts to load it from
    /root/workspace/bridge-demo/.env (the standard location on the VPS).
    Exits with a clear error if still not found.
    """
    if os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"):
        logger.info("CLAUDE_CODE_OAUTH_TOKEN found in environment")
        return

    # Try loading from the bridge-demo .env file
    env_path = "/root/workspace/bridge-demo/.env"
    logger.info("CLAUDE_CODE_OAUTH_TOKEN not in environment, trying %s", env_path)
    dotenv = _load_env_file(env_path)

    if dotenv.get("CLAUDE_CODE_OAUTH_TOKEN"):
        os.environ["CLAUDE_CODE_OAUTH_TOKEN"] = dotenv["CLAUDE_CODE_OAUTH_TOKEN"]
        logger.info("Loaded CLAUDE_CODE_OAUTH_TOKEN from %s", env_path)

        # Also load ANTHROPIC_API_KEY if present as a fallback
        if dotenv.get("ANTHROPIC_API_KEY") and not os.environ.get("ANTHROPIC_API_KEY"):
            os.environ["ANTHROPIC_API_KEY"] = dotenv["ANTHROPIC_API_KEY"]
            logger.info("Loaded ANTHROPIC_API_KEY from %s", env_path)
        return

    print(
        "ERROR: CLAUDE_CODE_OAUTH_TOKEN is not set.\n"
        "Either export it before running:\n"
        "  export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat...\n"
        "  python run_benchmark_claude.py --manifest ...\n"
        f"Or ensure it is defined in {env_path}",
        file=sys.stderr,
    )
    sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CWE-Bench-Java benchmark runner (Claude)"
    )
    parser.add_argument(
        "--manifest", required=True,
        help="Path to the CVE manifest JSON file",
    )
    parser.add_argument(
        "--output", default=None,
        help="Path for the results JSON (default: <base_data_dir>/results/claude_results.json)",
    )
    parser.add_argument(
        "--base-data-dir", default=None,
        help="Base data directory (default: /tmp/iris-framework-claude/data)",
    )
    parser.add_argument(
        "--include", nargs="*", default=[],
        help="Only run these CVE IDs",
    )
    parser.add_argument(
        "--exclude", nargs="*", default=[],
        help="Skip these CVE IDs",
    )
    parser.add_argument(
        "--docker-timeout", type=int, default=600,
        help="Docker container timeout in seconds (default: 600)",
    )
    parser.add_argument(
        "--docker-memory", default="4g",
        help="Docker memory limit (default: 4g)",
    )
    parser.add_argument(
        "--phase1-model", default=PHASE1_MODEL,
        help=f"Model for Phase 1 (default: {PHASE1_MODEL})",
    )
    parser.add_argument(
        "--phase2-model", default=PHASE2_MODEL,
        help=f"Model for Phase 2 (default: {PHASE2_MODEL})",
    )
    parser.add_argument(
        "--overwrite-posthoc-filter", action="store_true", default=True,
        help="Force Phase 2 to re-run posthoc filter even if cached (default: True)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    setup_logging(args.verbose)

    # Ensure Claude API token is available before doing any work.
    # Loads from os.environ first, falls back to bridge-demo/.env.
    _ensure_claude_token()

    # Fix 3: Build config with runner-specific isolated directory.
    # Claude runner uses /tmp/iris-framework-claude/data/ by default.
    config = BenchmarkConfig(
        runner_name="claude",
        phase1_model=args.phase1_model,
        phase2_model=args.phase2_model,
        docker_timeout=args.docker_timeout,
        docker_memory_limit=args.docker_memory,
        overwrite_posthoc_filter=args.overwrite_posthoc_filter,
        cve_include=args.include,
        cve_exclude=args.exclude,
    )

    # Allow overriding the base data dir from CLI
    if args.base_data_dir:
        config.base_data_dir = Path(args.base_data_dir)
        config.codeql_db_dir = config.base_data_dir / "codeql-dbs"
        config.results_dir = config.base_data_dir / "results"
        config.cache_dir = config.base_data_dir / "cache"

    config.ensure_dirs()

    # Load CVE projects
    projects = load_cve_projects(
        args.manifest,
        include=args.include or None,
        exclude=args.exclude or None,
    )

    if not projects:
        logger.error("No CVE projects to run")
        sys.exit(1)

    # Run benchmark
    results: list[CVEResult] = []
    total = len(projects)

    logger.info("Starting Claude benchmark: %d CVE projects", total)
    logger.info("Phase 1 model: %s", config.phase1_model)
    logger.info("Phase 2 model: %s", config.phase2_model)
    logger.info("Base data dir: %s", config.base_data_dir)
    logger.info("Overwrite posthoc filter: %s", config.overwrite_posthoc_filter)

    for idx, project in enumerate(projects, 1):
        logger.info(
            "=== [%d/%d] %s (%s) ===",
            idx, total, project.cve_id, project.project_name,
        )
        result = run_cve_project(config, project)
        results.append(result)

        status = "PASS" if result.passed else "FAIL"
        logger.info(
            "[%d/%d] %s: %s (phase %d, stage %d, %.1fs)",
            idx, total, project.cve_id, status,
            result.phase, result.stage_reached, result.duration_secs,
        )

    # Save results
    output_path = Path(args.output) if args.output else config.results_dir / "claude_results.json"
    save_results(results, output_path)

    # Summary
    passed = sum(1 for r in results if r.passed)
    failed = total - passed
    logger.info("Benchmark complete: %d/%d passed, %d failed", passed, total, failed)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
