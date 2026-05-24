#!/usr/bin/env python3
"""
CWE-Bench-Java benchmark runner — Qwen variant.

Single-phase runner: Qwen model handles all stages (1-8) in one pass.

Fixes applied:
  1. Docker container + image cleanup after every CVE (finally block).
  2. Phase 2 posthoc filter uses --overwrite-posthoc-filter to avoid
     empty iterator when earlier stages are cached.
  3. Isolated output directory (/tmp/iris-framework-qwen/data/) so the
     Claude runner can't collide with databases this runner needs.
"""

import argparse
import logging
import sys
import time
from pathlib import Path

from benchmark_common import (
    BenchmarkConfig,
    CVEProject,
    CVEResult,
    docker_cleanup,
    is_stage_cached,
    load_cve_projects,
    rebuild_codeql_db,
    run_iris_stage,
    save_results,
    setup_logging,
)

logger = logging.getLogger("cwe-bench.qwen")

# Qwen uses a single model for all stages
DEFAULT_MODEL = "qwen-coder"


def run_all_stages(config: BenchmarkConfig, project: CVEProject) -> tuple[bool, int, str | None]:
    """
    Run all 8 stages with the Qwen model.

    Stages 1-7 are the standard analysis pipeline.
    Stage 8 is the posthoc filter — same empty-iterator fix as the Claude
    runner applies here.

    Returns (success, last_stage_completed, error_message).
    """
    for stage in range(1, 9):
        extra_args: list[str] = []

        if stage == 8:
            # Fix 2: Force posthoc filter re-run for stage 8.
            # Same root cause as the Claude runner — when stages 1-7 are
            # cached, stage 8 may see stale completion markers and produce
            # an empty iterator at 99-100% progress. The fix is to always
            # pass --overwrite-posthoc-filter so the filter actually executes.
            extra_args.append("--overwrite-posthoc-filter")
            extra_args.append("--rebuild-db-if-missing")

            # Fix 2: Rebuild CodeQL DB if needed before the posthoc stage.
            if not rebuild_codeql_db(config, project):
                return False, stage, "Failed to rebuild CodeQL DB for stage 8"

        if is_stage_cached(config, project, stage) and stage < 8:
            logger.info("[%s] Stage %d cached, skipping", project.cve_id, stage)
            continue

        logger.info("[%s] Running stage %d", project.cve_id, stage)
        result = run_iris_stage(stage, config, project, extra_args=extra_args or None)

        if result.returncode != 0:
            error = result.stderr.strip() or f"Stage {stage} failed with exit code {result.returncode}"
            logger.error("[%s] Stage %d failed: %s", project.cve_id, stage, error)
            return False, stage, error

        logger.info("[%s] Stage %d complete", project.cve_id, stage)

    return True, 8, None


def run_cve_project(config: BenchmarkConfig, project: CVEProject) -> CVEResult:
    """
    Run all stages for a single CVE project.

    Fix 1: Docker containers and images are cleaned up in a finally block
    so they don't accumulate even when the analysis fails mid-run.
    """
    start = time.monotonic()
    container_name = project.container_name
    image_name = project.image_name

    try:
        ok, last_stage, error = run_all_stages(config, project)
        return CVEResult(
            cve_id=project.cve_id,
            passed=ok,
            phase=1,  # Qwen uses single-phase
            stage_reached=last_stage,
            duration_secs=time.monotonic() - start,
            error=error,
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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CWE-Bench-Java benchmark runner (Qwen)"
    )
    parser.add_argument(
        "--manifest", required=True,
        help="Path to the CVE manifest JSON file",
    )
    parser.add_argument(
        "--output", default=None,
        help="Path for the results JSON (default: <base_data_dir>/results/qwen_results.json)",
    )
    parser.add_argument(
        "--base-data-dir", default=None,
        help="Base data directory (default: /tmp/iris-framework-qwen/data)",
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
        "--model", default=DEFAULT_MODEL,
        help=f"Model for all stages (default: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--overwrite-posthoc-filter", action="store_true", default=True,
        help="Force stage 8 to re-run posthoc filter even if cached (default: True)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging",
    )
    args = parser.parse_args()

    setup_logging(args.verbose)

    # Fix 3: Build config with runner-specific isolated directory.
    # Qwen runner uses /tmp/iris-framework-qwen/data/ by default.
    config = BenchmarkConfig(
        runner_name="qwen",
        phase1_model=args.model,
        phase2_model=args.model,
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

    logger.info("Starting Qwen benchmark: %d CVE projects", total)
    logger.info("Model: %s", config.phase1_model)
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
            "[%d/%d] %s: %s (stage %d, %.1fs)",
            idx, total, project.cve_id, status,
            result.stage_reached, result.duration_secs,
        )

    # Save results
    output_path = Path(args.output) if args.output else config.results_dir / "qwen_results.json"
    save_results(results, output_path)

    # Summary
    passed = sum(1 for r in results if r.passed)
    failed = total - passed
    logger.info("Benchmark complete: %d/%d passed, %d failed", passed, total, failed)

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
