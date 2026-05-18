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

class GdbState(StrEnum):
    DEAD = "dead"
    STOPPED = "stopped"
    RUNNING = "running"

_NOISE_NOTIFY = {"cmd-param-changed", "library-loaded", "library-unloaded", "thread-group-added"}

def _update_state(responses: list[dict[str, Any]], current: GdbState) -> GdbState:
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

def _clean_responses(responses: Any) -> list[dict[str, Any]]:
    if responses is None:
        return []
    if not isinstance(responses, list):
        return []
    
    cleaned: list[dict[str, Any]] = []
    for r in responses:
        if not isinstance(r, dict):
            continue
        msg = r.get("message", "")
        rtype = r.get("type", "")
        if rtype == "notify" and msg in _NOISE_NOTIFY:
            continue
        payload = r.get("payload")
        if isinstance(payload, str):
            r = {**r, "payload": strip_ansi(payload)}
        cleaned.append(r)
    return cleaned

class AsyncGdbController:
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

    async def start(self) -> None:
        if self.state != GdbState.DEAD:
            return
        self._pty_master, self._pty_slave = pty.openpty()
        self._pty_name = os.ttyname(self._pty_slave)
        self._orig_attrs = termios.tcgetattr(self._pty_slave)
        attrs = termios.tcgetattr(self._pty_slave)
        attrs[3] = attrs[3] & ~termios.ECHO
        termios.tcsetattr(self._pty_slave, termios.TCSANOW, attrs)
        tty.setraw(self._pty_master)
        tty.setraw(self._pty_slave)
        self._poll = select.poll()
        self._poll.register(self._pty_master, select.POLLIN)
        gdb_command = [self.gdb_path, "-q", "--interpreter=mi3", "-ex", f"set inferior-tty {self._pty_name}"]
        loop = asyncio.get_running_loop()
        self._controller = await loop.run_in_executor(self._executor, lambda: GdbController(command=gdb_command))
        self.state = GdbState.STOPPED
        await self.execute("-gdb-set mi-async on")

    async def close(self) -> None:
        if self._controller is not None:
            loop = asyncio.get_running_loop()
            try:
                await loop.run_in_executor(self._executor, self._controller.exit)
            except Exception:
                pass
            self._controller = None
        for fd in (self._pty_master, self._pty_slave):
            if fd >= 0:
                try: os.close(fd)
                except OSError: pass
        self._pty_master = -1
        self._pty_slave = -1
        self._poll = None
        self.state = GdbState.DEAD

    async def get_responses(self, timeout_sec: float = 0.5) -> list[dict[str, Any]]:
        if self._controller is None:
            return []
        loop = asyncio.get_running_loop()
        try:
            raw = await loop.run_in_executor(
                self._executor,
                lambda: self._controller.get_gdb_response(timeout_sec=timeout_sec, raise_error_on_timeout=False),
            )
        except Exception:
            return []
        responses = _clean_responses(raw)
        self.state = _update_state(responses, self.state)
        return responses

    async def execute(self, command: str, timeout_sec: float = 10) -> list[dict[str, Any]]:
        if self._controller is None:
            return [{"type": "error", "payload": "GDB not started."}]
        
        if self.state == GdbState.RUNNING:
            await self.get_responses(timeout_sec=0.1)

        loop = asyncio.get_running_loop()
        try:
            raw = await loop.run_in_executor(
                self._executor,
                lambda: self._controller.write(command, timeout_sec=timeout_sec, raise_error_on_timeout=False),
            )
        except BrokenPipeError:
            self.state = GdbState.DEAD
            return [{"type": "error", "payload": "GDB process died."}]
        except Exception as e:
            return [{"type": "error", "payload": f"MI Error: {e}"}]

        responses = _clean_responses(raw)
        self.state = _update_state(responses, self.state)
        
        cmd_lower = command.strip().lower()
        if cmd_lower in ("quit", "q", "-gdb-exit"):
            await self.close()

        return responses

    async def execute_console(self, command: str, timeout_sec: float = 10) -> list[dict[str, Any]]:
        all_responses = []
        lines = command.strip().splitlines()
        for line in lines:
            cmd = line.strip()
            if not cmd: continue
            
            if cmd.startswith("-"):
                wrapped = cmd
            else:
                safe_cmd = cmd.replace('"', '\\"')
                wrapped = f'-interpreter-exec console "{safe_cmd}"'
            
            res = await self.execute(wrapped, timeout_sec)
            
            # Mandatory drain for console commands to avoid "No Output"
            # We wait until we see no more responses or hit a small timeout
            start = asyncio.get_event_loop().time()
            while (asyncio.get_event_loop().time() - start) < 1.0:
                extra = await self.get_responses(timeout_sec=0.1)
                if not extra: break
                res.extend(extra)
            
            all_responses.extend(res)
        return all_responses

    async def drain_responses(self, timeout_sec: float = 3.0, max_rounds: int = 15) -> list[dict[str, Any]]:
        all_responses: list[dict[str, Any]] = []
        per_round = timeout_sec / max_rounds
        for _ in range(max_rounds):
            responses = await self.get_responses(timeout_sec=per_round)
            if not responses: break
            all_responses.extend(responses)
            if any(r.get("type") == "notify" and r.get("message") in ("stopped", "thread-group-exited") for r in responses):
                break
        return all_responses

    async def send_to_process(self, data: bytes) -> None:
        if self._pty_master < 0: raise RuntimeError("No PTY available.")
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._executor, lambda: os.write(self._pty_master, data))

    async def read_from_process(self, size: int = 4096, timeout_ms: int = 1000) -> str | None:
        if self._poll is None or self._pty_master < 0: return None
        loop = asyncio.get_running_loop()
        ready = await loop.run_in_executor(self._executor, lambda: self._poll.poll(timeout_ms) if self._poll else [])
        if not ready: return None
        data = await loop.run_in_executor(self._executor, lambda: os.read(self._pty_master, size))
        if not data: return None
        if all(b >= 32 or b in (0x0A, 0x0D, 0x09, 0x1B) for b in data):
            return data.decode("utf-8", errors="replace").replace("\\x1b", "^[")
        return _hexdump(data)

    async def interrupt_process(self, signal: str = "c") -> None:
        ctrl_map = {"c": b"\\x03", "d": b"\\x04", "z": b"\\x1a"}
        char = ctrl_map.get(signal.lower(), b"\\x03")
        if self._pty_master < 0: raise RuntimeError("No PTY available.")
        loop = asyncio.get_running_loop()
        def _send_ctrl() -> None:
            try:
                if self._orig_attrs is not None: termios.tcsetattr(self._pty_slave, termios.TCSANOW, self._orig_attrs)
                os.write(self._pty_master, char)
            finally:
                if self._pty_slave >= 0: tty.setraw(self._pty_slave)
        await loop.run_in_executor(self._executor, _send_ctrl)

def _hexdump(data: bytes, width: int = 16) -> str:
    lines: list[str] = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        ascpart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hexpart:<{width * 3}}  {ascpart}")
    return "\\n".join(lines)
