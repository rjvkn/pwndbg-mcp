import pytest

from mcp.server.fastmcp import FastMCP
from src.tools_pwntools import register_pwntools_tools


@pytest.fixture
def mcp():
    m = FastMCP("test")
    register_pwntools_tools(m)
    return m


async def call_tool(mcp_instance: FastMCP, name: str, **kwargs) -> str:
    """Call a registered tool by function name."""
    for tool in mcp_instance._tool_manager._tools.values():
        if tool.fn.__name__ == name:
            return await tool.fn(**kwargs)
    raise ValueError(f"Tool {name} not found")


@pytest.mark.asyncio
async def test_pack_64bit(mcp):
    result = await call_tool(mcp, "pack", value=0xdeadbeef, bits=64)
    assert "efbeadde" in result


@pytest.mark.asyncio
async def test_pack_32bit(mcp):
    result = await call_tool(mcp, "pack", value=0x41414141, bits=32)
    assert "41414141" in result


@pytest.mark.asyncio
async def test_unpack_64bit(mcp):
    result = await call_tool(mcp, "unpack", data="efbeadde00000000")
    assert "0xdeadbeef" in result


@pytest.mark.asyncio
async def test_pwn_cyclic(mcp):
    result = await call_tool(mcp, "pwn_cyclic", length=20, n=4)
    assert len(result) == 20


@pytest.mark.asyncio
async def test_pwn_cyclic_find(mcp):
    result = await call_tool(mcp, "pwn_cyclic_find", value="0x61616162")
    assert "Offset:" in result


@pytest.mark.asyncio
async def test_hex_encode(mcp):
    result = await call_tool(mcp, "hex_encode", data="ABC")
    assert result == "414243"


@pytest.mark.asyncio
async def test_hex_decode(mcp):
    result = await call_tool(mcp, "hex_decode", hex_str="414243")
    assert result == "ABC"


@pytest.mark.asyncio
async def test_hex_decode_binary(mcp):
    result = await call_tool(mcp, "hex_decode", hex_str="80ff")
    assert "\\x" in result  # Should show byte repr since non-UTF8


@pytest.mark.asyncio
async def test_xor_data(mcp):
    result = await call_tool(mcp, "xor_data", data="4142", key="ff")
    assert result == "bebd"
