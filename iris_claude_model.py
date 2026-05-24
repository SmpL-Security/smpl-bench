import os
import shutil
import subprocess
import time
from tqdm.contrib.concurrent import thread_map
import anthropic
import httpx

from src.models.llm import LLM
from src.utils.mylogger import MyLogger

_model_name_map = {
    "claude-sonnet": "claude-sonnet-4-20250514",
    "claude-haiku": "claude-haiku-4-5-20251001",
}

# Map full model IDs back to CLI aliases for `claude -p --model <alias>`
_CLI_ALIAS_MAP = {
    "claude-sonnet-4-20250514": "sonnet",
    "claude-haiku-4-5-20251001": "haiku",
}

_ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"
_MAX_RETRIES = 5
_REQUEST_TIMEOUT = 300.0
_CLI_TIMEOUT = 600  # 10 min per CLI call (generous for deep analysis)
_CLI_MAX_CONCURRENCY = 2


def _is_oat_token(token: str) -> bool:
    """Return True if *token* is an OAT (OAuth Access Token)."""
    return token.startswith("sk-ant-oat")


def _resolve_token(**kwargs) -> str:
    """Resolve the API token from kwargs / environment.

    Priority:
      1. Explicit kwarg ``anthropic_api_key``
      2. ``CLAUDE_CODE_OAUTH_TOKEN`` env var
      3. ``ANTHROPIC_API_KEY`` env var

    Raises ``ValueError`` when no token can be found.
    """
    token = (
        kwargs.get("anthropic_api_key")
        or os.getenv("CLAUDE_CODE_OAUTH_TOKEN")
        or os.getenv("ANTHROPIC_API_KEY")
    )
    if not token:
        raise ValueError(
            "No Anthropic API token found. Set CLAUDE_CODE_OAUTH_TOKEN "
            "or ANTHROPIC_API_KEY, or pass anthropic_api_key= kwarg."
        )
    return token


def _has_claude_cli() -> bool:
    """Check whether the `claude` CLI binary is on PATH."""
    return shutil.which("claude") is not None


class ClaudeModel(LLM):
    def __init__(self, model_name, logger: MyLogger, **kwargs):
        super().__init__(model_name, logger, _model_name_map, **kwargs)
        self._token = _resolve_token(**kwargs)
        self._use_bearer = _is_oat_token(self._token)

        # Prefer CLI when OAT token detected and CLI is available.
        # Set IRIS_USE_RAW_API=1 to force the old httpx path.
        self._use_cli = (
            self._use_bearer
            and _has_claude_cli()
            and not os.getenv("IRIS_USE_RAW_API")
        )

        if self._use_cli:
            self.client = None
            self._cli_model = _CLI_ALIAS_MAP.get(self.model_id, self.model_id)
            self.log(
                f">>>Using Claude CLI (claude -p --model {self._cli_model}) "
                f"— routes through Claude Code infrastructure, avoids raw API rate limits"
            )
        elif self._use_bearer:
            self.client = None
            self.log(
                ">>>Using OAT Bearer auth (httpx) for Anthropic Messages API"
            )
        else:
            self.client = anthropic.Anthropic(
                api_key=self._token, max_retries=_MAX_RETRIES
            )

    # ── public interface ────────────────────────────────────────────────

    def predict(self, prompt, expect_json=False, batch_size=0, no_progress_bar=False):
        if batch_size == 0:
            return self._predict(prompt)
        # Cap concurrency when using CLI to avoid hammering
        if self._use_cli:
            batch_size = min(batch_size, _CLI_MAX_CONCURRENCY)
        args = range(0, len(prompt))
        responses = thread_map(
            lambda x: self._predict(prompt[x]),
            args,
            max_workers=batch_size,
            disable=no_progress_bar,
        )
        return responses

    def _predict(self, main_prompt):
        # assuming 0 is system and 1 is user
        system_prompt = main_prompt[0]["content"]
        user_prompt = main_prompt[1]["content"]

        if self._use_cli:
            return self._predict_cli(system_prompt, user_prompt)

        if self._use_bearer:
            return self._predict_bearer(system_prompt, user_prompt)

        response = self.client.messages.create(
            model=self.model_id,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
            max_tokens=4096,
            temperature=0,
        )
        return response.content[0].text

    # ── Claude CLI path ────────────────────────────────────────────────

    def _predict_cli(self, system_content: str, user_content: str) -> str:
        """Route through the Claude CLI binary (`claude -p`).

        This uses the same auth pathway as Claude Code interactive sessions
        and factory sub-agents, which have much higher effective rate limits
        than raw API calls with an OAT token.
        """
        cmd = [
            "claude", "-p",
            "--model", self._cli_model,
            "--system-prompt", system_content,
            "--output-format", "text",
            "--no-session-persistence",
        ]

        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                result = subprocess.run(
                    cmd,
                    input=user_content,
                    capture_output=True,
                    text=True,
                    timeout=_CLI_TIMEOUT,
                )
                if result.returncode == 0:
                    return result.stdout.strip()

                stderr = result.stderr.strip()
                # Retry on transient errors (overloaded, rate limits)
                if any(s in stderr.lower() for s in ["overloaded", "rate", "429", "retry"]):
                    raise RuntimeError(f"CLI transient error: {stderr[:200]}")

                raise RuntimeError(
                    f"claude CLI exited {result.returncode}: {stderr[:500]}"
                )
            except subprocess.TimeoutExpired as exc:
                last_exc = exc
                self.log(
                    f">>>CLI timeout ({_CLI_TIMEOUT}s) on attempt {attempt + 1}"
                )
                if attempt < _MAX_RETRIES:
                    time.sleep(5)
            except RuntimeError as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES:
                    wait = 2 ** (attempt + 1)
                    self.log(
                        f">>>CLI attempt {attempt + 1} failed ({exc}), "
                        f"retrying in {wait}s…"
                    )
                    time.sleep(wait)

        raise RuntimeError(
            f"Claude CLI failed after {_MAX_RETRIES + 1} attempts"
        ) from last_exc

    # ── OAT / Bearer auth path (httpx) — fallback if CLI unavailable ──

    def _predict_bearer(self, system_content: str, user_content: str) -> str:
        """Call the Anthropic Messages API with Bearer auth + retry."""
        headers = {
            "Authorization": f"Bearer {self._token}",
            "anthropic-version": _ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
        payload = {
            "model": self.model_id,
            "system": system_content,
            "messages": [{"role": "user", "content": user_content}],
            "max_tokens": 4096,
            "temperature": 0,
        }

        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = httpx.post(
                    _ANTHROPIC_MESSAGES_URL,
                    headers=headers,
                    json=payload,
                    timeout=_REQUEST_TIMEOUT,
                )
                response.raise_for_status()
                result = response.json()
                return result["content"][0]["text"]
            except (httpx.HTTPStatusError, httpx.TransportError) as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES:
                    wait = 2**attempt
                    self.log(
                        f">>>Bearer request attempt {attempt + 1} failed "
                        f"({exc}), retrying in {wait}s…"
                    )
                    time.sleep(wait)

        raise RuntimeError(
            f"Anthropic Messages API (Bearer) failed after "
            f"{_MAX_RETRIES + 1} attempts"
        ) from last_exc
