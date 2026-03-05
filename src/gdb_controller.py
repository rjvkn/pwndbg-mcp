"""Async GDB controller using pygdbmi with PTY support for process I/O."""

from __future__ import annotations

import asyncio
import os
import pty

import select
import termios
import tty
from concurrent.futures import ThreadPoolExecutor
from enum import StrEnum
from typing import Any

from pygdbmi.gdbcontroller import GdbController

from .utils import strip_ansi

# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

class GdbState(StrEnum):
    DEAD = "dead"
    STOPPED = "stopped"
    RUNNING = "running"


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------

_NOISE_NOTIFY = {"cmd-param-changed", "library-loaded", "library-unloaded", "thread-group-added"}


def _update_state(responses: list[dict[str, Any]], current: GdbState) -> GdbState:
    """Scan responses for notify messages that indicate state transitions."""
    state = current
    for r in responses:
        if r.get("type") != "notify":
            continue
        msg = r.get("message", "")
        if msg in ("stopped", "thread-selected", "thread-group-exited"):
            state = GdbState.STOPPED
        elif msg in ("running",):
            state = GdbState.RUNNING
    return state


def _clean_responses(responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove noisy GDB/MI messages and strip ANSI from payloads."""
    cleaned: list[dict[str, Any]] = []
    for r in responses:
        msg = r.get("message", "")
        rtype = r.get("type", "")
        # Skip noisy notifications
        if rtype == "notify" and msg in _NOISE_NOTIFY:
            continue
        # Strip ANSI from payloads
        payload = r.get("payload")
        if isinstance(payload, str):
            r = {**r, "payload": strip_ansi(payload)}
        cleaned.append(r)
    return cleaned


# ---------------------------------------------------------------------------
# Controller
# ---------------------------------------------------------------------------

class AsyncGdbController:
    """Manages a GDB subprocess via pygdbmi with PTY for inferior I/O.

    All pygdbmi calls are sync — we run them in a single-threaded executor
    to avoid blocking the async event loop.
    """

    def __init__(self, gdb_path: str = "gdb") -> None:
        self.gdb_path = gdb_path
        self.state = GdbState.DEAD
        self._controller: GdbController | None = None
        self._executor = ThreadPoolExecutor(max_workers=1)
        self._pty_master: int = -1
        self._pty_slave: int = -1
        self._pty_name: str = ""
        self._orig_attrs: list[Any] | None = None
        self._poll: select.poll | None = None

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def start(self) -> None:
        """Spawn GDB with PTY for inferior I/O."""
        if self.state != GdbState.DEAD:
            return

        # Create PTY pair
        self._pty_master, self._pty_slave = pty.openpty()
        self._pty_name = os.ttyname(self._pty_slave)

        # Save original terminal attributes, then set raw mode
        self._orig_attrs = termios.tcgetattr(self._pty_slave)
        # Disable echo on slave
        attrs = termios.tcgetattr(self._pty_slave)
        attrs[3] = attrs[3] & ~termios.ECHO  # type: ignore[operator]
        termios.tcsetattr(self._pty_slave, termios.TCSANOW, attrs)
        tty.setraw(self._pty_master)
        tty.setraw(self._pty_slave)

        # Set up poll for non-blocking reads
        self._poll = select.poll()
        self._poll.register(self._pty_master, select.POLLIN)

        # Spawn GDB
        gdb_command = [
            self.gdb_path, "-q", "--interpreter=mi3",
            "-ex", f"set inferior-tty {self._pty_name}",
        ]
        loop = asyncio.get_running_loop()
        self._controller = await loop.run_in_executor(
            self._executor,
            lambda: GdbController(command=gdb_command),
        )
        self.state = GdbState.STOPPED

        # Enable async MI mode so commands can be sent while target is running
        await self.execute("-gdb-set mi-async on")

    async def close(self) -> None:
        """Shut down GDB and clean up resources."""
        if self._controller is not None:
            loop = asyncio.get_running_loop()
            try:
                await loop.run_in_executor(self._executor, self._controller.exit)
            except Exception:
                pass
            self._controller = None

        for fd in (self._pty_master, self._pty_slave):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self._pty_master = -1
        self._pty_slave = -1
        self._poll = None
        self.state = GdbState.DEAD

    async def restart(self) -> None:
        """Kill and restart GDB."""
        await self.close()
        await self.start()

    # -----------------------------------------------------------------------
    # GDB communication
    # -----------------------------------------------------------------------

    async def get_responses(self, timeout_sec: float = 0.5) -> list[dict[str, Any]]:
        """Non-blocking poll for pending GDB responses."""
        if self._controller is None:
            return []
        loop = asyncio.get_running_loop()
        try:
            raw = await loop.run_in_executor(
                self._executor,
                lambda: self._controller.get_gdb_response(  # type: ignore[union-attr]
                    timeout_sec=timeout_sec,
                    raise_error_on_timeout=False,
                ),
            )
        except Exception:
            return []
        responses = _clean_responses(raw)
        self.state = _update_state(responses, self.state)
        return responses

    async def execute(self, command: str, timeout_sec: float = 10) -> list[dict[str, Any]]:
        """Execute a GDB/MI command (e.g. '-exec-run', '-break-insert main').

        Returns the list of cleaned responses. Does not block on RUNNING state —
        GDB/MI handles command queueing and errors natively.
        """
        if self._controller is None:
            return [{"type": "error", "payload": "GDB not started. Load a binary first."}]

        # Drain any pending responses to keep state accurate
        if self.state == GdbState.RUNNING:
            await self.get_responses(timeout_sec=0.5)

        loop = asyncio.get_running_loop()
        try:
            raw = await loop.run_in_executor(
                self._executor,
                lambda: self._controller.write(  # type: ignore[union-attr]
                    command,
                    timeout_sec=timeout_sec,
                    raise_error_on_timeout=False,
                ),
            )
        except BrokenPipeError:
            self.state = GdbState.DEAD
            return [{"type": "error", "payload": "GDB process died. Use pwndbg_hard_reset() to restart."}]

        responses = _clean_responses(raw)
        self.state = _update_state(responses, self.state)

        # Handle quit
        cmd_lower = command.strip().lower()
        if cmd_lower in ("quit", "q", "-gdb-exit"):
            await self.close()

        return responses

    async def execute_console(self, command: str, timeout_sec: float = 10) -> list[dict[str, Any]]:
        """Execute a console/CLI command (pwndbg, plain GDB commands) via MI.

        Sends the command directly — pygdbmi and GDB/MI handle CLI commands
        natively (no -interpreter-exec wrapper needed).
        """
        return await self.execute(command, timeout_sec)

    async def drain_responses(self, timeout_sec: float = 3.0, max_rounds: int = 15) -> list[dict[str, Any]]:
        """Poll for pending GDB responses multiple times to catch async notifications.

        Useful after execution commands (-exec-run, -exec-interrupt) where the
        *stopped notification arrives asynchronously after the ^running/^done result.
        """
        all_responses: list[dict[str, Any]] = []
        per_round = timeout_sec / max_rounds
        for _ in range(max_rounds):
            responses = await self.get_responses(timeout_sec=per_round)
            if not responses:
                break
            all_responses.extend(responses)
            # If we got a stopped notification, we're done waiting
            if any(r.get("type") == "notify" and r.get("message") in ("stopped", "thread-group-exited")
                   for r in responses):
                break
        return all_responses

    # -----------------------------------------------------------------------
    # Process I/O via PTY
    # -----------------------------------------------------------------------

    async def send_to_process(self, data: bytes) -> None:
        """Send bytes to the inferior process stdin via PTY."""
        if self._pty_master < 0:
            raise RuntimeError("No PTY available — load and run a binary first.")
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            self._executor,
            lambda: os.write(self._pty_master, data),
        )

    async def read_from_process(self, size: int = 4096, timeout_ms: int = 1000) -> str | None:
        """Read from the inferior process stdout via PTY.

        Returns decoded text if printable, hex dump if binary, or None on timeout.
        """
        if self._poll is None or self._pty_master < 0:
            return None

        loop = asyncio.get_running_loop()
        ready = await loop.run_in_executor(
            self._executor,
            lambda: self._poll.poll(timeout_ms) if self._poll else [],  # type: ignore[union-attr]
        )
        if not ready:
            return None

        data = await loop.run_in_executor(
            self._executor,
            lambda: os.read(self._pty_master, size),
        )
        if not data:
            return None

        # Determine if output is printable text
        if all(b >= 32 or b in (0x0A, 0x0D, 0x09, 0x1B) for b in data):
            text = data.decode("utf-8", errors="replace")
            # Replace ESC for readability
            return text.replace("\x1b", "^[")
        else:
            return _hexdump(data)

    async def interrupt_process(self, signal: str = "c") -> None:
        """Send a control character to the inferior via PTY.

        signal: 'c' for Ctrl-C, 'd' for Ctrl-D, 'z' for Ctrl-Z
        """
        ctrl_map = {"c": b"\x03", "d": b"\x04", "z": b"\x1a"}
        char = ctrl_map.get(signal.lower(), b"\x03")

        if self._pty_master < 0:
            raise RuntimeError("No PTY available.")

        loop = asyncio.get_running_loop()

        def _send_ctrl() -> None:
            # Temporarily restore cooked mode so control char is interpreted
            try:
                if self._orig_attrs is not None:
                    termios.tcsetattr(self._pty_slave, termios.TCSANOW, self._orig_attrs)
                os.write(self._pty_master, char)
            finally:
                # Always restore raw mode
                if self._pty_slave >= 0:
                    tty.setraw(self._pty_slave)

        await loop.run_in_executor(self._executor, _send_ctrl)


# ---------------------------------------------------------------------------
# Hex dump helper
# ---------------------------------------------------------------------------

def _hexdump(data: bytes, width: int = 16) -> str:
    """Simple hex dump of binary data."""
    lines: list[str] = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        ascpart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hexpart:<{width * 3}}  {ascpart}")
    return "\n".join(lines)
