# pwndbg-mcp

[Model Context Protocol](https://modelcontextprotocol.io/) server that gives AI agents full access to GDB/pwndbg debugging and pwntools exploit development utilities. 96 tools across live debugging, heap analysis, and offline binary analysis.

## What it does

- **Live debugging** -- Load binaries, set breakpoints, step through code, inspect registers/memory/stack
- **pwndbg integration** -- Context display, telescope, vmmap, heap visualization, ROP gadgets, exploit helpers
- **Process I/O** -- Send/receive data to the debugged process stdin/stdout via PTY
- **pwntools offline** -- Packing, cyclic patterns, ELF analysis, ROP chain building, shellcode generation, format string payloads

## Requirements

- Python >= 3.11
- GDB with [pwndbg](https://github.com/pwndbg/pwndbg) installed
- [`uv`](https://docs.astral.sh/uv/) package manager

## Quick start

```bash
git clone https://github.com/echo8134/pwndbg-mcp.git && cd pwndbg-mcp
uv run pwndbg-mcp install
```

This installs dependencies and registers the server in `~/.claude.json`. Restart Claude Code to pick it up.

## CLI

```
pwndbg-mcp              # run the MCP server (default)
pwndbg-mcp install      # uv sync + register in ~/.claude.json
pwndbg-mcp uninstall    # unregister from ~/.claude.json
pwndbg-mcp config       # show registration status and JSON config
pwndbg-mcp run          # run the MCP server (explicit)
pwndbg-mcp path         # add pwndbg-mcp to shell PATH (zsh/bash/fish)
```

## Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `PWNDBG_MCP_GDB_PATH` | `gdb` | Path to GDB binary (with pwndbg loaded) |

## Tools (96)

### GDB Core (33)

| Tool | Description |
|---|---|
| `load_binary` | Load an ELF binary into GDB for debugging |
| `attach_process` | Attach GDB to a running process by PID |
| `detach_process` | Detach GDB from the current process |
| `remote_connect` | Connect to a remote GDB server (gdbserver) |
| `remote_disconnect` | Disconnect from a remote GDB target |
| `run_program` | Start running the loaded program from the beginning |
| `continue_execution` | Continue program execution until next breakpoint or exit |
| `step_into` | Step into the next source line (enters function calls) |
| `step_over` | Step over the next source line (skips into function calls) |
| `step_instruction` | Step one machine instruction (enters calls) |
| `next_instruction` | Step one machine instruction (skips calls) |
| `finish_function` | Execute until the current function returns |
| `interrupt_execution` | Interrupt a running program (like Ctrl-C in GDB) |
| `kill_program` | Kill the running program |
| `set_breakpoint` | Set a breakpoint at the specified location |
| `delete_breakpoint` | Delete a breakpoint by its number |
| `enable_breakpoint` | Enable a disabled breakpoint |
| `disable_breakpoint` | Disable a breakpoint without deleting it |
| `list_breakpoints` | List all breakpoints, watchpoints, and catchpoints |
| `set_watchpoint` | Set a watchpoint on a memory expression |
| `read_registers` | Read CPU register values |
| `write_register` | Write a value to a CPU register |
| `read_memory` | Read raw memory bytes at an address |
| `write_memory` | Write bytes to memory at an address |
| `disassemble` | Disassemble instructions at an address or range |
| `evaluate_expression` | Evaluate an expression in the current context |
| `backtrace` | Show the call stack (backtrace) |
| `stack_locals` | Show local variables in the current stack frame |
| `stack_args` | Show function arguments in the current stack frame |
| `select_frame` | Select a stack frame by number |
| `list_threads` | List all threads in the debugged process |
| `switch_thread` | Switch to a different thread |
| `execute_command` | Execute any raw GDB/MI or console command |

### pwndbg Extensions (41)

| Tool | Description |
|---|---|
| `pwndbg_context` | Show pwndbg context display: registers, disassembly, stack, backtrace |
| `telescope` | Dereference pointers recursively starting from an address |
| `vmmap` | Show virtual memory map of the process |
| `hexdump_memory` | Hex dump memory at an address |
| `xinfo` | Show information about what a memory address belongs to |
| `search_memory` | Search process memory for a value |
| `probeleak` | Probe memory for pointers to known regions (heap, stack, libc, etc.) |
| `leakfind` | Find chains of pointers starting from an address to known regions |
| `distance` | Calculate the distance between two addresses |
| `heap_bins` | Show all free list bins (tcache, fast, unsorted, small, large) |
| `heap_overview` | Show an overview of the heap state |
| `vis_heap_chunks` | Visual representation of heap chunks with color-coded boundaries |
| `malloc_chunk` | Inspect a specific malloc chunk header and metadata |
| `top_chunk` | Show the top (wilderness) chunk of the heap |
| `heap_arenas` | List all malloc arenas |
| `tcachebins` | Show tcache bin entries and their contents |
| `fastbins` | Show fast bin entries and their contents |
| `unsortedbin` | Show unsorted bin entries |
| `smallbins` | Show small bin entries and their contents |
| `largebins` | Show large bin entries and their contents |
| `find_fake_fast` | Find candidate locations for fake fastbin chunks near an address |
| `try_free` | Simulate what free() would do on a chunk, checking for errors |
| `checksec` | Show binary security features: NX, PIE, RELRO, stack canary, FORTIFY |
| `got_table` | Show Global Offset Table entries and their resolved addresses |
| `plt_table` | Show Procedure Linkage Table entries |
| `piebase` | Show the PIE base address of the loaded binary |
| `elf_sections` | List all ELF sections of the loaded binary |
| `libcinfo` | Show libc version and path information |
| `rop_gadgets` | Find ROP gadgets in the loaded binary |
| `cyclic_pattern` | Generate a De Bruijn cyclic pattern for finding offsets |
| `cyclic_find` | Find the offset of a value in the De Bruijn cyclic pattern |
| `onegadget` | Find one-gadget RCE candidates in libc |
| `canary` | Show the current stack canary value |
| `retaddr` | Show return addresses on the stack for the current frame |
| `sigreturn_frame` | Generate a sigreturn frame for SROP exploitation |
| `dumpargs` | Dump function arguments at the current position based on calling convention |
| `patch_instruction` | Patch an instruction in memory at the given address |
| `nearpc` | Show disassembly around an address with context |
| `emulate` | Emulate execution of instructions without actually running them |
| `pwndbg_status` | Return the current GDB state and drain any pending messages |
| `pwndbg_hard_reset` | Kill and restart the GDB process completely |

### Process I/O (4)

| Tool | Description |
|---|---|
| `send_to_process` | Send a string to the debugged process's stdin |
| `eval_to_send` | Evaluate a Python/pwntools expression and send the result as bytes to the process |
| `read_from_process` | Read output from the debugged process's stdout |
| `interrupt_process` | Send a control signal to the debugged process via the terminal |

### pwntools Utilities (18)

Offline helpers that don't require a running GDB session.

| Tool | Description |
|---|---|
| `pack` | Pack an integer into bytes |
| `unpack` | Unpack a hex string into an integer |
| `pwn_cyclic` | Generate a De Bruijn cyclic pattern for buffer overflow offset finding |
| `pwn_cyclic_find` | Find the offset of a value in the De Bruijn cyclic pattern |
| `elf_info` | Get basic ELF info: architecture, bits, endianness, and security checksec results |
| `elf_symbols` | List symbols defined in an ELF binary |
| `elf_got` | Show Global Offset Table (GOT) entries of an ELF binary |
| `elf_plt` | Show Procedure Linkage Table (PLT) entries of an ELF binary |
| `elf_search` | Search an ELF binary for a byte string |
| `rop_find_gadgets` | Find ROP gadgets in an ELF binary |
| `rop_build_chain` | Build a ROP chain from a JSON specification |
| `shellcraft_generate` | Generate shellcode assembly source from pwntools shellcraft templates |
| `asm_encode` | Assemble instructions into machine code bytes |
| `asm_decode` | Disassemble machine code bytes into assembly instructions |
| `fmtstr_payload` | Generate a format string exploit payload |
| `hex_encode` | Encode a string to its hex representation |
| `hex_decode` | Decode a hex string back to text or byte representation |
| `xor_data` | XOR a hex data string with a hex key string |

## Architecture

```
src/
  server.py           MCP server entry point, GDB controller lifecycle
  gdb_controller.py   Async GDB/MI protocol handler with PTY for process I/O
  tools_gdb.py        GDB core tools (33)
  tools_pwndbg.py     pwndbg extension tools (41)
  tools_pwntools.py   Offline pwntools utilities (18)
  tools_process.py    Process stdin/stdout tools (4)
  utils.py            ANSI stripping, response formatting
  cli.py              CLI: install/uninstall/config/run/path
```
