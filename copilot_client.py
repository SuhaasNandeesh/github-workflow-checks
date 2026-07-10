"""GitHub Copilot / GHES chat completions client.

Authentication supports github.com Copilot and self-hosted GHES endpoints.
The client does NOT silently fall back to unverified SSL — TLS errors raise
a typed exception with an actionable message (A1).
"""
from __future__ import annotations

import json
import os
import ssl
import subprocess
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


class CopilotClient:
    DEFAULT_ENDPOINT = "https://api.githubcopilot.com"
    DEFAULT_MODEL = "gpt-4o"

    def __init__(
        self,
        model_name: str | None = None,
        endpoint: str | None = None,
        token: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.model_name = model_name or self.DEFAULT_MODEL
        self.endpoint = (endpoint or self.DEFAULT_ENDPOINT).rstrip("/")
        self.timeout = timeout
        self.token = token or self._retrieve_token()

    @classmethod
    def from_config(
        cls,
        rules_config: dict[str, Any] | None = None,
        cli_endpoint: str | None = None,
        cli_model: str | None = None,
    ) -> "CopilotClient":
        cfg = rules_config or {}
        endpoint = cli_endpoint or cfg.get("endpoint")
        model = cli_model or cfg.get("model")
        return cls(model_name=model, endpoint=endpoint)

    def _is_ghes(self) -> bool:
        """Return True if the endpoint is not github.com (i.e., self-hosted GHES)."""
        return "github.com" not in self.endpoint and self.endpoint != self.DEFAULT_ENDPOINT

    def _ghes_host(self) -> str | None:
        """Extract the hostname from the GHES endpoint URL (e.g., 'github.mycompany.com')."""
        if not self._is_ghes():
            return None
        from urllib.parse import urlparse
        parsed = urlparse(self.endpoint)
        return parsed.hostname

    def _retrieve_token(self) -> str:
        """Resolve a GitHub token from env, config files, or `gh` CLI.

        For GHES, also looks up host-specific tokens via `gh auth token --hostname <host>`.
        """
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

        ghes_host = self._ghes_host()
        if ghes_host:
            # Try GHES-specific hosts.json first
            for path in (
                os.path.join(home, ".config", "github-copilot", "hosts.json"),
                os.path.join(home, "AppData", "Local", "github-copilot", "hosts.json"),
            ):
                token = self._read_oauth_from_json(
                    path, keys=("oauth_token",), nested_keys=(ghes_host,)
                )
                if token:
                    return token
            # Fall back to gh auth token --hostname <host>
            try:
                result = subprocess.run(
                    ["gh", "auth", "token", "--hostname", ghes_host],
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
        else:
            for path in (
                os.path.join(home, ".config", "github-copilot", "hosts.json"),
                os.path.join(home, "AppData", "Local", "github-copilot", "hosts.json"),
            ):
                token = self._read_oauth_from_json(
                    path, keys=("oauth_token",), nested_keys=("github.com",)
                )
                if token:
                    return token

        # Final fallback: gh auth token (default host)
        try:
            result = subprocess.run(
                ["gh", "auth", "token"],
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

    def request_completion(self, system_prompt: str, user_prompt: str) -> str:
        """Send a chat completion request. Returns the assistant text content."""
        url = f"{self.endpoint}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Copilot-Integration-Id": "vscode-chat",
        }
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
        }
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")
        context = ssl.create_default_context()

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=context) as resp:
                body = resp.read()
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            if e.code in (401, 403) and self._try_refresh_token():
                return self.request_completion(system_prompt, user_prompt)
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
        except urllib.error.URLError as e:
            if isinstance(e.reason, ssl.SSLCertVerificationError):
                raise SSLCertificateError(
                    "TLS certificate verification failed. On macOS run "
                    "'/Applications/Python\\ 3.x/Install\\ Certificates.command' "
                    "or set $SSL_CERT_FILE to your CA bundle. "
                    f"Underlying error: {e.reason}"
                ) from e
            raise CopilotAPIError(f"Copilot request failed: {e}") from e

        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            raise CopilotAPIError(f"Copilot returned non-JSON body: {e}") from e

        choices = data.get("choices") or []
        if not choices:
            raise CopilotAPIError("Empty response choices received from Copilot API.")
        content = choices[0].get("message", {}).get("content", "")
        if not content:
            raise CopilotAPIError("Copilot returned an empty message content.")
        return content

    def _try_refresh_token(self) -> bool:
        """Attempt to refresh the OAuth token by re-running `gh auth token`.

        For GHES, uses `gh auth token --hostname <host>`. Returns True on refresh.
        """
        ghes_host = self._ghes_host()
        cmd = (
            ["gh", "auth", "token", "--hostname", ghes_host]
            if ghes_host
            else ["gh", "auth", "token"]
        )
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
