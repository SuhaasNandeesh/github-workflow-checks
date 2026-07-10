"""JSON Schema for .github-rules.json validation.

Defines the canonical schema for the rules configuration. Used to fail fast on
misconfiguration (B14 - single source of truth for severities/config).
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
    "required": ["rules", "suppressions"],
    "additionalProperties": False,
    "properties": {
        "model": {
            "type": "string",
            "description": "LLM model identifier for the Copilot client.",
        },
        "endpoint": {
            "type": "string",
            "format": "uri",
            "description": "Base URL of the Copilot-compatible chat endpoint.",
        },
        "secret_keyword_pattern": {
            "type": "string",
            "description": "Regex applied to variable names to detect probable secrets.",
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
                "endpoint": {
                    "type": "string",
                    "format": "uri",
                },
            },
        },
    },
}


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
