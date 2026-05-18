"""Utility functions for pwndbg-mcp: ANSI stripping and output formatting."""

from __future__ import annotations

import re

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\].*?\x07|\x1b\[.*?[@-~]")


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    return _ANSI_RE.sub("", text)


def format_responses(responses: list[dict[str, object]]) -> str:
    """Extract and format GDB/MI response payloads into clean text.
    Collects 'console' stream output and result payloads from pygdbmi responses.
    """
    lines: list[str] = []
    for resp in responses:
        msg_type = resp.get("type")
        payload = resp.get("payload")
        if payload is None:
            continue
        if msg_type == "console":
            lines.append(strip_ansi(str(payload)).rstrip())
        elif msg_type == "result":
            if isinstance(payload, dict):
                # GDB/MI results often have a 'value' key for the actual data
                value = payload.get("value")
                if value is not None:
                    lines.append(strip_ansi(str(value)).rstrip())
                else:
                    # Fallback for other result types, skip 'done'
                    if payload != {"value": "done"}:
                        lines.append(str(payload))
            elif isinstance(payload, str) and payload != "done":
                lines.append(strip_ansi(payload).rstrip())
    return "\n".join(lines)


def format_console_output(responses: list[dict[str, object]]) -> str:
    """Format output from console commands (pwndbg, etc.).
    Collects console, log, target, and output stream records from GDB/MI responses.
    Different pwndbg commands may emit output via different streams.
    """
    lines: list[str] = []
    for resp in responses:
        if resp.get("type") in ("console", "log", "output", "target"):
            payload = resp.get("payload")
            if payload is not None:
                lines.append(strip_ansi(str(payload)).rstrip())
    return "\n".join(lines)


def format_error(e: Exception) -> str:
    """Format an exception as an error string for tool output."""
    return f"Error: {type(e).__name__}: {e}"
