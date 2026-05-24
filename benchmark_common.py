"""
CWE-Bench-Java benchmark runner — shared utilities.

Provides Docker lifecycle management, CVE project iteration,
output directory isolation, and phase execution helpers used
by both the Claude and Qwen runners.
"""

import json
import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("cwe-bench")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class BenchmarkConfig:
    """Runtime configuration for a benchmark run."""

    # Identity
    runner_name: str  # "claude" or "qwen"

    # Paths — each runner gets its own isolated base directory (Fix 3)
    base_data_dir: Path = field(default_factory=lambda: Path("/tmp/iris-framework/data"))
    codeql_db_dir: Path = field(init=False)
    results_dir: Path = field(init=False)
    cache_dir: Path = field(init=False)

    # Docker
    docker_timeout: int = 600  # seconds per container
    docker_memory_limit: str = "4g"

    # Phases
    phase1_model: str = ""
    phase2_model: str = ""
    overwrite_posthoc_filter: bool = False

    # CVE filtering
    cve_list_file: Optional[str] = None
    cve_include: list[str] = field(default_factory=list)
    cve_exclude: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Fix 3: Each runner uses an isolated base directory so Claude and
        # Qwen never collide on CodeQL databases or intermediate artifacts.
        self.base_data_dir = Path(f"/tmp/iris-framework-{self.runner_name}/data")
        self.codeql_db_dir = self.base_data_dir / "codeql-dbs"
        self.results_dir = self.base_data_dir / "results"
        self.cache_dir = self.base_data_dir / "cache"

    def ensure_dirs(self) -> None:
        """Create all output directories if they don't exist."""
        for d in (self.codeql_db_dir, self.results_dir, self.cache_dir):
            d.mkdir(parents=True, exist_ok=True)
        logger.info("Output dirs ready under %s", self.base_data_dir)


# ---------------------------------------------------------------------------
# Docker helpers (Fix 1)
# ---------------------------------------------------------------------------

def docker_run(
    image: str,
    container_name: str,
    cmd: list[str],
    *,
    timeout: int = 600,
    memory_limit: str = "4g",
    volumes: Optional[dict[str, str]] = None,
    env_vars: Optional[dict[str, str]] = None,
) -> subprocess.CompletedProcess[str]:
    """
    Run a Docker container and return the CompletedProcess.

    Does NOT handle cleanup — callers must use docker_cleanup() in a finally
    block so containers and images are removed even on failure.
    """
    docker_cmd = [
        "docker", "run",
        "--name", container_name,
        "--memory", memory_limit,
    ]

    if volumes:
        for host_path, container_path in volumes.items():
            docker_cmd.extend(["-v", f"{host_path}:{container_path}"])

    if env_vars:
        for key, val in env_vars.items():
            docker_cmd.extend(["-e", f"{key}={val}"])

    docker_cmd.append(image)
    docker_cmd.extend(cmd)

    logger.info("Starting container %s from image %s", container_name, image)
    logger.debug("Command: %s", " ".join(docker_cmd))

    return subprocess.run(
        docker_cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def docker_cleanup(container_name: str, image_name: str) -> None:
    """
    Remove a Docker container and its image.

    Fix 1: This MUST be called in a finally block after every CVE iteration
    so containers and images don't accumulate and fill the disk.

    Failures are logged but never raised — cleanup is best-effort so it
    doesn't mask the real error from the CVE analysis.
    """
    # Remove container (force in case it's still running)
    try:
        result = subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            logger.info("Removed container: %s", container_name)
        else:
            logger.warning(
                "Failed to remove container %s: %s",
                container_name,
                result.stderr.strip(),
            )
    except subprocess.TimeoutExpired:
        logger.warning("Timeout removing container %s", container_name)
    except Exception as exc:
        logger.warning("Error removing container %s: %s", container_name, exc)

    # Remove image
    try:
        result = subprocess.run(
            ["docker", "rmi", "-f", image_name],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            logger.info("Removed image: %s", image_name)
        else:
            logger.warning(
                "Failed to remove image %s: %s",
                image_name,
                result.stderr.strip(),
            )
    except subprocess.TimeoutExpired:
        logger.warning("Timeout removing image %s", image_name)
    except Exception as exc:
        logger.warning("Error removing image %s: %s", image_name, exc)


# ---------------------------------------------------------------------------
# CVE project discovery
# ---------------------------------------------------------------------------

@dataclass
class CVEProject:
    """A single CVE test case from the benchmark suite."""

    cve_id: str
    project_name: str
    image_tag: str
    language: str = "java"
    cwe_ids: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    @property
    def container_name(self) -> str:
        return f"cwe-bench-{self.cve_id.lower().replace('-', '_')}"

    @property
    def image_name(self) -> str:
        return f"irissast/cwe-bench-java-containers-v2:{self.image_tag}"


def load_cve_projects(
    manifest_path: str,
    *,
    include: Optional[list[str]] = None,
    exclude: Optional[list[str]] = None,
) -> list[CVEProject]:
    """
    Load CVE projects from the benchmark manifest JSON.

    Args:
        manifest_path: Path to the JSON manifest listing all CVE test cases.
        include: If set, only run these CVE IDs.
        exclude: If set, skip these CVE IDs.

    Returns:
        Filtered list of CVEProject instances.
    """
    manifest = Path(manifest_path)
    if not manifest.exists():
        logger.error("Manifest not found: %s", manifest_path)
        sys.exit(1)

    with open(manifest) as f:
        raw = json.load(f)

    projects: list[CVEProject] = []
    for entry in raw.get("projects", []):
        cve_id = entry.get("cve_id", "")
        slug = entry.get("slug", "")

        # Filter by CVE ID
        if include and cve_id not in include:
            continue
        if exclude and cve_id in exclude:
            continue

        # Derive project_name and image_tag from the slug if available,
        # falling back to explicit fields or CVE ID defaults.
        project_name = entry.get("project", slug or cve_id)
        image_tag = entry.get("image_tag", slug or cve_id.lower())

        # Collect CWE IDs from either the legacy list or the single cwe_id field.
        cwe_ids = entry.get("cwe_ids", [])
        if not cwe_ids and entry.get("cwe_id"):
            cwe_ids = [entry["cwe_id"]]

        # Preserve query and other fields as metadata.
        metadata = entry.get("metadata", {})
        if entry.get("query"):
            metadata["query"] = entry["query"]
        if entry.get("cwe_id"):
            metadata["cwe_id"] = entry["cwe_id"]

        projects.append(
            CVEProject(
                cve_id=cve_id,
                project_name=project_name,
                image_tag=image_tag,
                language=entry.get("language", "java"),
                cwe_ids=cwe_ids,
                metadata=metadata,
            )
        )

    logger.info("Loaded %d CVE projects (filtered from %d total)",
                len(projects), len(raw.get("projects", [])))
    return projects


# ---------------------------------------------------------------------------
# Phase execution (Fix 2)
# ---------------------------------------------------------------------------

def run_iris_stage(
    stage: int,
    config: BenchmarkConfig,
    project: CVEProject,
    *,
    extra_args: Optional[list[str]] = None,
) -> subprocess.CompletedProcess[str]:
    """
    Run a single iris-framework analysis stage inside Docker.

    The command template follows the iris-framework CLI:
      iris-analyze --stage <N> --db-path <path> --output <path> [extra_args...]
    """
    container_name = f"{project.container_name}-stage{stage}"
    image_name = project.image_name

    cmd = [
        "iris-analyze",
        "--stage", str(stage),
        "--db-path", f"/data/codeql-dbs/{project.cve_id}",
        "--output", f"/data/results/{project.cve_id}",
        "--cve-id", project.cve_id,
    ]

    if extra_args:
        cmd.extend(extra_args)

    volumes = {
        str(config.codeql_db_dir): "/data/codeql-dbs",
        str(config.results_dir): "/data/results",
        str(config.cache_dir): "/data/cache",
    }

    env_vars = {}
    if config.phase1_model:
        env_vars["IRIS_MODEL"] = config.phase1_model
    if config.phase2_model and stage >= 8:
        env_vars["IRIS_MODEL"] = config.phase2_model

    # Forward API tokens from host environment so containers can call Claude.
    # CLAUDE_CODE_OAUTH_TOKEN is the primary auth mechanism;
    # ANTHROPIC_API_KEY is the fallback for direct API key auth.
    oauth_token = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
    if oauth_token:
        env_vars["CLAUDE_CODE_OAUTH_TOKEN"] = oauth_token
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        env_vars["ANTHROPIC_API_KEY"] = api_key

    try:
        result = docker_run(
            image_name,
            container_name,
            cmd,
            timeout=config.docker_timeout,
            memory_limit=config.docker_memory_limit,
            volumes=volumes,
            env_vars=env_vars,
        )
        return result
    finally:
        # Fix 1: Always clean up the per-stage container.
        # Image cleanup happens at the project level (see run_cve_project).
        docker_cleanup(container_name, "")  # empty string = skip image removal


def is_stage_cached(config: BenchmarkConfig, project: CVEProject, stage: int) -> bool:
    """Check whether a stage's output already exists in the results dir."""
    result_file = config.results_dir / project.cve_id / f"stage{stage}.json"
    return result_file.exists()


def rebuild_codeql_db(config: BenchmarkConfig, project: CVEProject) -> bool:
    """
    Rebuild the CodeQL database for a project if it's missing or corrupt.

    Fix 2: Phase 2 may need the DB rebuilt when earlier stages were cached
    but the DB was cleaned up or is from a different runner.
    """
    db_path = config.codeql_db_dir / project.cve_id
    if db_path.exists() and (db_path / "db-java").exists():
        logger.info("CodeQL DB exists for %s, skipping rebuild", project.cve_id)
        return True

    logger.info("Rebuilding CodeQL DB for %s", project.cve_id)
    container_name = f"{project.container_name}-db-rebuild"
    image_name = project.image_name

    volumes = {
        str(config.codeql_db_dir): "/data/codeql-dbs",
    }

    try:
        result = docker_run(
            image_name,
            container_name,
            ["codeql-db-build", "--project", project.cve_id,
             "--output", f"/data/codeql-dbs/{project.cve_id}"],
            timeout=config.docker_timeout,
            memory_limit=config.docker_memory_limit,
            volumes=volumes,
        )
        if result.returncode != 0:
            logger.error("DB rebuild failed for %s: %s",
                         project.cve_id, result.stderr)
            return False
        return True
    finally:
        docker_cleanup(container_name, "")


# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------

@dataclass
class CVEResult:
    """Outcome of a single CVE benchmark run."""

    cve_id: str
    passed: bool
    phase: int
    stage_reached: int
    duration_secs: float
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "passed": self.passed,
            "phase": self.phase,
            "stage_reached": self.stage_reached,
            "duration_secs": round(self.duration_secs, 2),
            "error": self.error,
        }


def save_results(results: list[CVEResult], output_path: Path) -> None:
    """Write benchmark results to a JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": len(results),
        "passed": sum(1 for r in results if r.passed),
        "failed": sum(1 for r in results if not r.passed),
        "results": [r.to_dict() for r in results],
    }
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    logger.info("Results saved to %s", output_path)


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging(verbose: bool = False) -> None:
    """Configure structured logging for the benchmark runner."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
