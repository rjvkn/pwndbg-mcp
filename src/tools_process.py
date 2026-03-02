"""Process I/O tools: send/receive data and signals to the debugged process."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TypeAlias

from mcp.server.fastmcp import FastMCP

from .gdb_controller import AsyncGdbController
from .utils import format_error

ControllerGetter: TypeAlias = Callable[[], Awaitable[AsyncGdbController]]


def register_process_tools(mcp: FastMCP, get_controller: ControllerGetter) -> None:
    """Register process I/O tools on the FastMCP instance."""

    @mcp.tool()
    async def send_to_process(data: str) -> str:
        """Send a string to the debugged process's stdin.

        Supports escape sequences: \\n (newline), \\t (tab), \\x41 (hex byte).

        Args:
            data: String to send. Use \\n for newline.
        """
        try:
            gdb = await get_controller()
            encoded = data.encode("utf-8").decode("unicode_escape").encode("latin-1")
            await gdb.send_to_process(encoded)
            return f"Sent {len(encoded)} bytes."
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def eval_to_send(expression: str) -> str:
        """Evaluate a Python/pwntools expression and send the result as bytes to the process.

        The expression has access to pwntools functions: p8, p16, p32, p64,
        flat, cyclic, bytes, etc.

        Examples:
            'p64(0xdeadbeef)' — sends 8-byte little-endian packed value
            'b"A" * 40 + p64(0x401234)' — buffer overflow payload
            'cyclic(100)' — De Bruijn pattern

        Args:
            expression: Python expression that evaluates to bytes.
        """
        try:
            # Build a restricted namespace with pwntools packing utilities
            ns: dict[str, object] = {"__builtins__": __builtins__}
            try:
                from pwnlib.util.packing import p8, p16, p32, p64, flat  # type: ignore[import-untyped]
                from pwnlib.util.cyclic import cyclic  # type: ignore[import-untyped]
                ns.update({"p8": p8, "p16": p16, "p32": p32, "p64": p64, "flat": flat, "cyclic": cyclic})
            except ImportError:
                pass

            result = eval(expression, ns)  # noqa: S307
            if isinstance(result, str):
                result = result.encode("utf-8")
            if not isinstance(result, bytes):
                return f"Error: expression must evaluate to bytes, got {type(result).__name__}"

            gdb = await get_controller()
            await gdb.send_to_process(result)
            return f"Sent {len(result)} bytes: {result[:64]!r}{'...' if len(result) > 64 else ''}"
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def read_from_process(size: int = 4096, timeout: int = 1000) -> str:
        """Read output from the debugged process's stdout.

        Returns text if printable, hex dump if binary, or 'No data' on timeout.

        Args:
            size: Maximum bytes to read (default 4096).
            timeout: Timeout in milliseconds (default 1000).
        """
        try:
            gdb = await get_controller()
            result = await gdb.read_from_process(size=size, timeout_ms=timeout)
            return result or "(no data available)"
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def interrupt_process(signal: str = "c") -> str:
        """Send a control signal to the debugged process via the terminal.

        Args:
            signal: 'c' for Ctrl-C (SIGINT), 'd' for Ctrl-D (EOF), 'z' for Ctrl-Z (SIGTSTP).
        """
        try:
            gdb = await get_controller()
            await gdb.interrupt_process(signal=signal)
            labels = {"c": "Ctrl-C (SIGINT)", "d": "Ctrl-D (EOF)", "z": "Ctrl-Z (SIGTSTP)"}
            return f"Sent {labels.get(signal.lower(), signal)}."
        except Exception as e:
            return format_error(e)
