"""GitHub Copilot chat completions client (offline / CI usage).

Authentication supports github.com Copilot tokens and self-hosted GHES
endpoints via the ``endpoint`` parameter.

The client does NOT silently fall back to unverified SSL — TLS errors raise
a typed exception with an actionable message (A1).

Per-agent model selection is supported via ``from_config(agent=...)`` so the
orchestrator can route cheap work to Haiku-class models and prose/reporting to
Sonnet/Opus-class models, optimizing the 4,000-credit monthly budget.
"""
from __future__ import annotations

import json
import os
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from typing import Any

from logging_setup import get_logger

logger = get_logger()


class SSLCertificateError(RuntimeError):
    """Raised when TLS verification fails. The user must install root certs."""


class AuthenticationError(RuntimeError):
    """Raised when no usable GitHub token is available."""


class CopilotAPIError(RuntimeError):
    """Raised when the chat endpoint returns a non-recoverable HTTP error."""


class BudgetExhaustedError(RuntimeError):
    """Raised when the configured request/token credit budget is exhausted.

    Carried separately so the CLI can exit with a distinct code (5) rather
    than the generic internal-error code (3).
    """


class CopilotClient:
    DEFAULT_ENDPOINT = "https://api.githubcopilot.com"
    DEFAULT_MODEL = "gpt-4o"

    # Per-agent temperature: deterministic for structured-output agents, looser
    # for the prose documenter.
    _AGENT_TEMPERATURES: dict[str, float] = {
        "semantic": 0.0,
        "fixer": 0.0,
        "documenter": 0.3,
        "portfolio": 0.3,
    }

    def __init__(
        self,
        model_name: str | None = None,
        token: str | None = None,
        timeout: float = 30.0,
        endpoint: str | None = None,
        _max_retries: int = 3,
    ) -> None:
        self.model_name = model_name or self.DEFAULT_MODEL
        self.timeout = timeout
        self._max_retries = _max_retries
        self.endpoint = (endpoint or self.DEFAULT_ENDPOINT).rstrip("/")
        self.token = token or self._retrieve_token()
        # Last observed usage block (token accounting).
        self.last_usage: dict[str, int] = {}

    def __repr__(self) -> str:
        return f"CopilotClient(model={self.model_name!r}, endpoint={self.endpoint!r}, token=***)"

    @classmethod
    def from_config(
        cls,
        rules_config: dict[str, Any] | None = None,
        cli_model: str | None = None,
        cli_endpoint: str | None = None,
        agent: str | None = None,
    ) -> "CopilotClient":
        cfg = rules_config or {}
        models = cfg.get("models") or {}
        model: str | None = None
        if agent and agent in models:
            model = models[agent]
        model = model or cli_model or cfg.get("model")
        endpoint = cli_endpoint or cfg.get("endpoint")
        return cls(model_name=model, endpoint=endpoint)

    def _retrieve_token(self) -> str:
        """Resolve a GitHub token from env, config files, or `gh` CLI."""
        token = os.environ.get("COPILOT_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if token:
            return token

        home = os.path.expanduser("~")
        for path in (
            os.path.join(home, ".config", "github-copilot", "apps.json"),
            os.path.join(home, "AppData", "Local", "github-copilot", "apps.json"),
        ):
            token = self._read_oauth_from_json(path, keys=("oauth_token",))
            if token:
                return token

        for path in (
            os.path.join(home, ".config", "github-copilot", "hosts.json"),
            os.path.join(home, "AppData", "Local", "github-copilot", "hosts.json"),
        ):
            # For GHES, the OAuth session is stored under the GHES hostname
            # (e.g. "github.mycompany.com"); for github.com it is under
            # "github.com". Try the GHES host first (if configured), then fall
            # back to "github.com".
            hosts_to_try: list[str] = []
            ghes_host = self._ghes_host()
            if ghes_host and ghes_host != "github.com":
                hosts_to_try.append(ghes_host)
            hosts_to_try.append("github.com")
            for host in hosts_to_try:
                token = self._read_oauth_from_json(
                    path, keys=("oauth_token",), nested_keys=(host,)
                )
                if token:
                    return token

        # Final fallback: gh auth token (default host, or GHES host if endpoint set)
        try:
            cmd = ["gh", "auth", "token"]
            host = self._ghes_host()
            if host:
                cmd += ["--hostname", host]
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
                timeout=10,
            )
            cli_token = result.stdout.strip()
            if cli_token:
                return cli_token
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            pass

        raise AuthenticationError(
            "Could not retrieve GitHub credentials. Run `gh auth login`, "
            "set $GITHUB_TOKEN, or sign into the VS Code Copilot extension."
        )

    def _ghes_host(self) -> str | None:
        """Extract a hostname from the configured endpoint if it's a GHES URL."""
        if not self.endpoint or self.endpoint == self.DEFAULT_ENDPOINT:
            return None
        try:
            from urllib.parse import urlparse
            parsed = urlparse(self.endpoint)
            return parsed.hostname
        except Exception:
            return None

    @staticmethod
    def _read_oauth_from_json(
        path: str,
        keys: tuple[str, ...],
        nested_keys: tuple[str, ...] = (),
    ) -> str | None:
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return None

        node: Any = data
        for nk in nested_keys:
            if isinstance(node, dict) and nk in node:
                node = node[nk]
            else:
                return None
        if not isinstance(node, dict):
            return None
        for k in keys:
            if k in node and isinstance(node[k], str):
                return node[k]
        return None

    def request_completion(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        agent: str | None = None,
        temperature: float | None = None,
        _attempt: int = 0,
    ) -> str:
        """Send a chat completion request. Returns the assistant text content.

        ``agent`` selects the temperature preset (semantic/fixer = deterministic,
        documenter/portfolio = looser) and is also used for logging. ``temperature``
        overrides the preset when explicitly provided.
        """
        if temperature is None:
            temperature = self._AGENT_TEMPERATURES.get(agent or "", 0.1)
        url = f"{self.endpoint}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Copilot-Integration-Id": "vscode-chat",
            "Editor-Version": "vscode/1.95.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
        }
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")
        context = ssl.create_default_context()

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=context) as resp:
                body = resp.read()
                # Honor Retry-After for HTTP 429 even on success path is N/A; handled below.
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            # Auth errors: refresh token and retry once.
            if e.code in (401, 403) and _attempt < 1 and self._try_refresh_token():
                return self.request_completion(
                    system_prompt, user_prompt, agent=agent, temperature=temperature,
                    _attempt=_attempt + 1,
                )
            # Rate limiting (429) and transient 5xx: exponential backoff.
            if e.code == 429 or (e.code >= 500 and _attempt < self._max_retries):
                retry_after = self._parse_retry_after(e.headers.get("Retry-After"), _attempt)
                logger.warning(
                    "Copilot API %d (attempt %d); retrying in %.2fs",
                    e.code, _attempt, retry_after,
                )
                time.sleep(retry_after)
                return self.request_completion(
                    system_prompt, user_prompt, agent=agent, temperature=temperature,
                    _attempt=_attempt + 1,
                )
            raise CopilotAPIError(
                f"Copilot API error {e.code} {e.reason}: {err_body[:500]}"
            ) from e
        except ssl.SSLCertVerificationError as e:
            raise SSLCertificateError(
                "TLS certificate verification failed. On macOS run "
                "'/Applications/Python\\ 3.x/Install\\ Certificates.command' "
                "or set $SSL_CERT_FILE to your CA bundle. "
                f"Underlying error: {e}"
            ) from e
        except TimeoutError as e:
            if _attempt < self._max_retries:
                time.sleep(self._backoff_seconds(_attempt))
                return self.request_completion(
                    system_prompt, user_prompt, agent=agent, temperature=temperature,
                    _attempt=_attempt + 1,
                )
            raise CopilotAPIError(f"Copilot request timed out: {e}") from e
        except urllib.error.URLError as e:
            if isinstance(e.reason, ssl.SSLCertVerificationError):
                raise SSLCertificateError(
                    "TLS certificate verification failed. On macOS run "
                    "'/Applications/Python\\ 3.x/Install\\ Certificates.command' "
                    "or set $SSL_CERT_FILE to your CA bundle. "
                    f"Underlying error: {e.reason}"
                ) from e
            if _attempt < self._max_retries:
                time.sleep(self._backoff_seconds(_attempt))
                return self.request_completion(
                    system_prompt, user_prompt, agent=agent, temperature=temperature,
                    _attempt=_attempt + 1,
                )
            raise CopilotAPIError(f"Copilot request failed: {e}") from e

        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            raise CopilotAPIError(f"Copilot returned non-JSON body: {e}") from e

        # Record usage for credit accounting (tokens). Some Copilot responses
        # omit usage; treat absence as zero rather than failing.
        usage = data.get("usage")
        if isinstance(usage, dict):
            self.last_usage = {
                "prompt_tokens": int(usage.get("prompt_tokens", 0)),
                "completion_tokens": int(usage.get("completion_tokens", 0)),
                "total_tokens": int(usage.get("total_tokens", 0)),
            }

        choices = data.get("choices") or []
        if not choices:
            raise CopilotAPIError("Empty response choices received from Copilot API.")
        content = choices[0].get("message", {}).get("content", "")
        if not content:
            raise CopilotAPIError("Copilot returned an empty message content.")
        return content

    @staticmethod
    def _backoff_seconds(attempt: int) -> float:
        return min(0.5 * (2 ** attempt), 8.0)

    @staticmethod
    def _parse_retry_after(header_value: str | None, attempt: int) -> float:
        if not header_value:
            return CopilotClient._backoff_seconds(attempt)
        try:
            return float(header_value)
        except (TypeError, ValueError):
            return CopilotClient._backoff_seconds(attempt)

    def _try_refresh_token(self) -> bool:
        """Attempt to refresh the OAuth token by re-running `gh auth token`.

        Returns True on refresh.
        """
        cmd = ["gh", "auth", "token"]
        host = self._ghes_host()
        if host:
            cmd += ["--hostname", host]
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
                timeout=10,
            )
        except (subprocess.SubprocessError, FileNotFoundError, OSError):
            return False
        new_token = result.stdout.strip()
        if new_token and new_token != self.token:
            self.token = new_token
            logger.info("Refreshed Copilot OAuth token from `gh auth token`.")
            return True
        return False