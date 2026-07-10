"""JSON Schema for .github-rules.json validation.

Defines the canonical schema for the rules configuration. Used to fail fast on
misconfiguration (B14 - single source of truth for severities/config).

Supports:
- ``endpoint``: GHES / custom Copilot + GitHub API base URL.
- ``models``: per-agent LLM model selection (semantic / documenter / fixer /
  portfolio). Falls back to top-level ``model`` then the client default.
- ``semantic_audit``: global enable/disable for the LLM semantic auditor.
- ``applies_to``: per-rule trigger scope (``source``, ``image``, ``deploy``,
  ``all``) controlling when global-gate rules fire.
"""
from __future__ import annotations

from typing import Any

try:
    from jsonschema import Draft202012Validator
    _HAS_JSONSCHEMA = True
except ImportError:
    Draft202012Validator = None
    _HAS_JSONSCHEMA = False


SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "GitHub Actions Rules Configuration",
    "type": "object",
    "required": ["rules"],
    "additionalProperties": False,
    "properties": {
        "model": {
            "type": "string",
            "description": "Fallback LLM model identifier when no per-agent model is set.",
        },
        "models": {
            "type": "object",
            "description": "Per-agent LLM model identifiers.",
            "additionalProperties": {"type": "string"},
            "properties": {
                "semantic": {"type": "string"},
                "documenter": {"type": "string"},
                "fixer": {"type": "string"},
                "portfolio": {"type": "string"},
            },
        },
        "endpoint": {
            "type": "string",
            "description": (
                "Custom Copilot chat endpoint base URL for GHES. "
                "Used for both LLM completions and GitHub API SHA resolution "
                "unless ``api_endpoint`` is set separately."
            ),
        },
        "api_endpoint": {
            "type": "string",
            "description": (
                "GitHub API base URL for action SHA resolution (defaults to "
                "endpoint when set, otherwise https://api.github.com)."
            ),
        },
        "secret_keyword_pattern": {
            "type": "string",
            "description": "Regex applied to variable names to detect probable secrets.",
        },
        "semantic_audit": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "enabled": {
                    "type": "boolean",
                    "default": False,
                    "description": "Globally enable the LLM semantic auditor.",
                },
            },
        },
        "rules": {
            "type": "object",
            "additionalProperties": {"$ref": "#/$defs/rule"},
        },
        "suppressions": {
            "type": "object",
            "required": ["global", "by_repository"],
            "additionalProperties": False,
            "properties": {
                "global": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "by_repository": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
            },
        },
    },
    "$defs": {
        "rule": {
            "type": "object",
            "required": ["severity"],
            "additionalProperties": False,
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["error", "warning", "info", "ignore"],
                },
                "description": {
                    "type": "string",
                },
                "semantic": {
                    "type": "boolean",
                    "default": False,
                    "description": "Whether this rule requires the LLM semantic auditor.",
                },
                "applies_to": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["source", "image", "deploy", "all"],
                    },
                    "default": ["all"],
                    "description": (
                        "Workflow scopes this rule applies to. Global-gate rules "
                        "(coverity, bdba, image-signing, image-build-jfrog) use this "
                        "to decide whether to fire."
                    ),
                },
            },
        },
    },
}


# Valid applies_to scopes (kept here so non-schema code can reference one source).
VALID_APPLIES_TO: tuple[str, ...] = ("source", "image", "deploy", "all")


class RulesSchemaError(ValueError):
    """Raised when .github-rules.json fails schema validation."""


def validate_rules_config(config: dict[str, Any]) -> None:
    """Validate a parsed rules configuration against the canonical schema.

    Raises RulesSchemaError with a human-readable message on failure.
    When jsonschema is not installed, validation is skipped (with a warning
    emitted by the caller).
    """
    if not _HAS_JSONSCHEMA:
        return
    validator = Draft202012Validator(SCHEMA)
    errors = sorted(validator.iter_errors(config), key=lambda e: e.path)
    if errors:
        lines = []
        for err in errors:
            path = "/".join(str(p) for p in err.absolute_path) or "<root>"
            lines.append(f"  - at '{path}': {err.message}")
        raise RulesSchemaError(
            "Invalid .github-rules.json:\n" + "\n".join(lines)
        )