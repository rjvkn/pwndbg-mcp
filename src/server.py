"""pwndbg-mcp MCP server — GDB/pwndbg debugging and pwntools utilities."""

from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP

from .gdb_controller import AsyncGdbController, GdbState
from .tools_gdb import register_gdb_tools
from .tools_process import register_process_tools
from .tools_pwndbg import register_pwndbg_tools
from .tools_pwntools import register_pwntools_tools

mcp = FastMCP("pwndbg-mcp")

GDB_PATH = os.environ.get("PWNDBG_MCP_GDB_PATH", "gdb")

# ---------------------------------------------------------------------------
# Lazy singleton controller
# ---------------------------------------------------------------------------

_controller: AsyncGdbController | None = None


async def get_controller() -> AsyncGdbController:
    """Get or create the GDB controller singleton, starting GDB if needed."""
    global _controller
    if _controller is None:
        _controller = AsyncGdbController(gdb_path=GDB_PATH)
        await _controller.start()
    elif _controller.state == GdbState.DEAD:
        await _controller.close()
        _controller = AsyncGdbController(gdb_path=GDB_PATH)
        await _controller.start()
    return _controller


async def reset_controller() -> str:
    """Kill and restart the GDB controller."""
    global _controller
    if _controller is not None:
        await _controller.close()
        _controller = None
    _controller = AsyncGdbController(gdb_path=GDB_PATH)
    await _controller.start()
    return "GDB restarted."


# ---------------------------------------------------------------------------
# Register all tool groups
# ---------------------------------------------------------------------------

register_gdb_tools(mcp, get_controller)
register_pwndbg_tools(mcp, get_controller)
register_pwntools_tools(mcp)
register_process_tools(mcp, get_controller)

if __name__ == "__main__":
    try:
        mcp.run()
    except KeyboardInterrupt:
        pass
