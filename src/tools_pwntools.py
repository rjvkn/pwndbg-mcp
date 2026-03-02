"""pwntools utility tools: packing, cyclic, ELF, ROP, shellcode, format strings, encoding."""

from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from .utils import format_error


def register_pwntools_tools(mcp: FastMCP) -> None:
    """Register pwntools utility tools on the FastMCP instance."""

    # ===================================================================
    # Packing
    # ===================================================================

    @mcp.tool()
    async def pack(value: int, bits: int = 64, endian: str = "little") -> str:
        """Pack an integer into bytes.

        Args:
            value: Integer value to pack.
            bits: Bit width (8, 16, 32, 64). Default 64.
            endian: Byte order — 'little' or 'big'. Default 'little'.
        """
        try:
            from pwnlib.util.packing import pack as _pack

            result = _pack(value, bits, endianness=endian)  # type: ignore[call-arg]
            return result.hex()
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def unpack(data: str, bits: int = 64, endian: str = "little") -> str:
        """Unpack a hex string into an integer.

        Args:
            data: Hex-encoded byte string (e.g. '4142434445464748').
            bits: Bit width (8, 16, 32, 64). Default 64.
            endian: Byte order — 'little' or 'big'. Default 'little'.
        """
        try:
            from pwnlib.util.packing import unpack as _unpack

            raw = bytes.fromhex(data)
            result = _unpack(raw, bits, endianness=endian)  # type: ignore[call-arg]
            return hex(result)
        except Exception as e:
            return format_error(e)

    # ===================================================================
    # Cyclic
    # ===================================================================

    @mcp.tool()
    async def pwn_cyclic(length: int = 200, n: int = 4) -> str:
        """Generate a De Bruijn cyclic pattern for buffer overflow offset finding.

        Args:
            length: Length of the pattern in bytes. Default 200.
            n: Size of the subsequence (4 for 32-bit, 8 for 64-bit). Default 4.
        """
        try:
            from pwnlib.util.cyclic import cyclic

            result = cyclic(length, n=n)
            if isinstance(result, bytes):
                return result.decode("latin-1")
            return str(result)
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def pwn_cyclic_find(value: str, n: int = 4) -> str:
        """Find the offset of a value in the De Bruijn cyclic pattern.

        Args:
            value: Value to find — hex integer like '0x61616162' or raw bytes like 'aaab'.
            n: Subsequence size used when generating the pattern. Default 4.
        """
        try:
            from pwnlib.util.cyclic import cyclic_find

            if value.startswith("0x"):
                lookup: int | bytes = int(value, 16)
            else:
                lookup = value.encode("latin-1")
            offset = cyclic_find(lookup, n=n)
            return f"Offset: {offset}"
        except Exception as e:
            return format_error(e)

    # ===================================================================
    # ELF Analysis
    # ===================================================================

    @mcp.tool()
    async def elf_info(path: str) -> str:
        """Get basic ELF info: architecture, bits, endianness, and security checksec results.

        Args:
            path: Path to the ELF binary.
        """
        try:
            from pwnlib.context import context
            from pwnlib.elf import ELF

            context.log_level = "error"
            elf = ELF(path)
            checksec_result = elf.checksec()
            lines = [
                f"Arch:   {elf.arch}",
                f"Bits:   {elf.bits}",
                f"Endian: {elf.endian}",
                "Checksec:",
            ]
            if isinstance(checksec_result, dict):
                for key, val in checksec_result.items():
                    lines.append(f"  {key}: {val}")
            else:
                lines.append(f"  {checksec_result}")
            return "\n".join(lines)
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def elf_symbols(path: str, pattern: str = "") -> str:
        """List symbols defined in an ELF binary.

        Args:
            path: Path to the ELF binary.
            pattern: Optional substring filter — only symbols containing this string are shown.
        """
        try:
            from pwnlib.context import context
            from pwnlib.elf import ELF

            context.log_level = "error"
            elf = ELF(path)
            syms = elf.symbols
            if pattern:
                syms = {k: v for k, v in syms.items() if pattern in k}
            if not syms:
                return "No matching symbols found."
            lines = [f"  {name}: {hex(addr)}" for name, addr in sorted(syms.items(), key=lambda x: x[1])]
            return f"Symbols ({len(lines)}):\n" + "\n".join(lines)
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def elf_got(path: str) -> str:
        """Show Global Offset Table (GOT) entries of an ELF binary.

        Args:
            path: Path to the ELF binary.
        """
        try:
            from pwnlib.context import context
            from pwnlib.elf import ELF

            context.log_level = "error"
            elf = ELF(path)
            got = elf.got
            if not got:
                return "No GOT entries found."
            lines = [f"  {name}: {hex(addr)}" for name, addr in sorted(got.items(), key=lambda x: x[1])]
            return f"GOT entries ({len(lines)}):\n" + "\n".join(lines)
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def elf_plt(path: str) -> str:
        """Show Procedure Linkage Table (PLT) entries of an ELF binary.

        Args:
            path: Path to the ELF binary.
        """
        try:
            from pwnlib.context import context
            from pwnlib.elf import ELF

            context.log_level = "error"
            elf = ELF(path)
            plt = elf.plt
            if not plt:
                return "No PLT entries found."
            lines = [f"  {name}: {hex(addr)}" for name, addr in sorted(plt.items(), key=lambda x: x[1])]
            return f"PLT entries ({len(lines)}):\n" + "\n".join(lines)
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def elf_search(path: str, value: str, writable: bool = False) -> str:
        """Search an ELF binary for a byte string.

        Args:
            path: Path to the ELF binary.
            value: String to search for (will be encoded to bytes).
            writable: If true, only search writable segments.
        """
        try:
            from pwnlib.context import context
            from pwnlib.elf import ELF

            context.log_level = "error"
            elf = ELF(path)
            results = list(elf.search(value.encode(), writable=writable))
            if not results:
                return f"No matches found for {value!r}."
            lines = [f"  {hex(addr)}" for addr in results]
            return f"Found {len(results)} match(es):\n" + "\n".join(lines)
        except Exception as e:
            return format_error(e)

    # ===================================================================
    # ROP
    # ===================================================================

    @mcp.tool()
    async def rop_find_gadgets(path: str, regex: str = "") -> str:
        """Find ROP gadgets in an ELF binary.

        Args:
            path: Path to the ELF binary.
            regex: Optional regex to filter gadgets (e.g. 'pop rdi').
        """
        try:
            from pwnlib.context import context
            from pwnlib.elf import ELF
            from pwnlib.rop import ROP

            context.log_level = "error"
            elf = ELF(path)
            rop = ROP(elf)
            if regex:
                import re

                pattern = re.compile(regex, re.IGNORECASE)
                gadgets = []
                for gadget in rop.gadgets.values():
                    insns = "; ".join(gadget.insns)
                    if pattern.search(insns):
                        gadgets.append(f"  {hex(gadget.address)}: {insns}")
                if not gadgets:
                    return f"No gadgets matching {regex!r}."
                return f"Gadgets ({len(gadgets)}):\n" + "\n".join(gadgets)
            else:
                gadgets = []
                for gadget in rop.gadgets.values():
                    insns = "; ".join(gadget.insns)
                    gadgets.append(f"  {hex(gadget.address)}: {insns}")
                if not gadgets:
                    return "No gadgets found."
                return f"Gadgets ({len(gadgets)}):\n" + "\n".join(gadgets)
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def rop_build_chain(path: str, chain_spec: str) -> str:
        """Build a ROP chain from a JSON specification.

        Args:
            path: Path to the ELF binary.
            chain_spec: JSON string — a list of objects with 'call' (function name)
                        and 'args' (list of arguments). Example:
                        [{"call": "puts", "args": ["0x400000"]}, {"call": "main", "args": []}]
        """
        try:
            from pwnlib.context import context
            from pwnlib.elf import ELF
            from pwnlib.rop import ROP

            context.log_level = "error"
            elf = ELF(path)
            rop = ROP(elf)

            spec = json.loads(chain_spec)
            for entry in spec:
                func_name = entry["call"]
                args = []
                for a in entry.get("args", []):
                    if isinstance(a, str):
                        args.append(int(a, 0))
                    else:
                        args.append(int(a))
                rop.call(func_name, args)

            chain_bytes = rop.chain()
            return f"ROP chain ({len(chain_bytes)} bytes):\n{chain_bytes.hex()}"
        except Exception as e:
            return format_error(e)

    # ===================================================================
    # Shellcode
    # ===================================================================

    @mcp.tool()
    async def shellcraft_generate(arch: str = "amd64", os: str = "linux", payload: str = "sh") -> str:
        """Generate shellcode assembly source from pwntools shellcraft templates.

        Args:
            arch: Target architecture — 'amd64', 'i386', 'arm', 'aarch64', etc. Default 'amd64'.
            os: Target OS — 'linux', 'freebsd', etc. Default 'linux'.
            payload: Payload template name — 'sh', 'cat', 'dupsh', etc. Default 'sh'.
        """
        try:
            from pwnlib import shellcraft
            from pwnlib.context import context

            context.log_level = "error"
            arch_mod = getattr(shellcraft, arch)
            os_mod = getattr(arch_mod, os)
            func = getattr(os_mod, payload)
            source = func()
            return source
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def asm_encode(code: str, arch: str = "amd64") -> str:
        """Assemble instructions into machine code bytes.

        Args:
            code: Assembly source code (e.g. 'nop; ret' or multiline).
            arch: Target architecture. Default 'amd64'.
        """
        try:
            from pwnlib.asm import asm
            from pwnlib.context import context

            context.log_level = "error"
            context.arch = arch
            result = asm(code)
            return result.hex()
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def asm_decode(hex_bytes: str, arch: str = "amd64") -> str:
        """Disassemble machine code bytes into assembly instructions.

        Args:
            hex_bytes: Hex string of machine code (e.g. '90c3' for nop; ret).
            arch: Target architecture. Default 'amd64'.
        """
        try:
            from pwnlib.asm import disasm
            from pwnlib.context import context

            context.log_level = "error"
            context.arch = arch
            raw = bytes.fromhex(hex_bytes)
            result = disasm(raw)
            return result
        except Exception as e:
            return format_error(e)

    # ===================================================================
    # Format Strings
    # ===================================================================

    @mcp.tool()
    async def fmtstr_payload(offset: int, writes: str, numbwritten: int = 0, bits: int = 64) -> str:
        """Generate a format string exploit payload.

        Args:
            offset: The format string parameter offset (found by testing with %p).
            writes: JSON string of {address: value} pairs to write. Both address and
                    value can be decimal or hex strings (e.g. '{"0x404020": "0xdeadbeef"}').
            numbwritten: Number of bytes already written before the format string. Default 0.
            bits: Target architecture bit width (32 or 64). Default 64.
        """
        try:
            from pwnlib.context import context
            from pwnlib.fmtstr import fmtstr_payload as _fmtstr

            context.log_level = "error"
            context.bits = bits

            writes_dict: dict[int, int] = {}
            for addr_str, val_str in json.loads(writes).items():
                writes_dict[int(addr_str, 0)] = int(val_str, 0)

            payload = _fmtstr(offset, writes_dict, numbwritten=numbwritten)
            hex_repr = payload.hex()
            # Build ASCII preview — replace non-printable bytes with dots
            ascii_preview = "".join(chr(b) if 32 <= b < 127 else "." for b in payload)
            return f"Payload ({len(payload)} bytes):\nHex: {hex_repr}\nASCII: {ascii_preview}"
        except Exception as e:
            return format_error(e)

    # ===================================================================
    # Encoding
    # ===================================================================

    @mcp.tool()
    async def hex_encode(data: str) -> str:
        """Encode a string to its hex representation.

        Args:
            data: String to encode.
        """
        try:
            return data.encode().hex()
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def hex_decode(hex_str: str) -> str:
        """Decode a hex string back to text or byte representation.

        Args:
            hex_str: Hex-encoded string (e.g. '48656c6c6f').
        """
        try:
            raw = bytes.fromhex(hex_str)
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                return repr(raw)
        except Exception as e:
            return format_error(e)

    @mcp.tool()
    async def xor_data(data: str, key: str) -> str:
        """XOR a hex data string with a hex key string.

        Args:
            data: Hex-encoded data to XOR.
            key: Hex-encoded key (will be cycled if shorter than data).
        """
        try:
            from pwnlib.util.fiddling import xor

            raw_data = bytes.fromhex(data)
            raw_key = bytes.fromhex(key)
            result = xor(raw_data, raw_key)
            return result.hex()
        except Exception as e:
            return format_error(e)
