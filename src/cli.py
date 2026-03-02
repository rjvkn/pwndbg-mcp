"""CLI for pwndbg-mcp: install, uninstall, config, run."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

SERVER_NAME = "pwndbg-mcp"
SERVER_DIR = Path(__file__).resolve().parent.parent
CLAUDE_CONFIG = Path.home() / ".claude.json"


def _load_config() -> dict:
    if not CLAUDE_CONFIG.exists():
        return {}
    return json.loads(CLAUDE_CONFIG.read_text())


def _save_config(config: dict) -> None:
    CLAUDE_CONFIG.write_text(json.dumps(config, indent=2) + "\n")


def _server_entry() -> dict:
    uv = shutil.which("uv")
    if uv is None:
        print("Error: uv not found in PATH", file=sys.stderr)
        sys.exit(1)
    return {
        "type": "stdio",
        "command": uv,
        "args": ["run", "--directory", str(SERVER_DIR), "python", "-m", "src.server"],
    }


def _is_registered() -> bool:
    config = _load_config()
    return SERVER_NAME in config.get("mcpServers", {})


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_install(args: argparse.Namespace) -> None:
    """Install dependencies and register in ~/.claude.json."""
    print(f"Installing {SERVER_NAME}...")
    subprocess.run(["uv", "sync"], cwd=SERVER_DIR, check=True)

    config = _load_config()
    config.setdefault("mcpServers", {})
    config["mcpServers"][SERVER_NAME] = _server_entry()
    _save_config(config)

    print()
    print(f"{SERVER_NAME} installed successfully!")
    print(f"  Registered in {CLAUDE_CONFIG}")
    print("  Restart Claude Code to pick up the new server.")


def cmd_uninstall(args: argparse.Namespace) -> None:
    """Unregister from ~/.claude.json."""
    config = _load_config()
    servers = config.get("mcpServers", {})
    if SERVER_NAME in servers:
        del servers[SERVER_NAME]
        _save_config(config)
        print(f"{SERVER_NAME} unregistered from {CLAUDE_CONFIG}")
    else:
        print(f"{SERVER_NAME} is not registered.")


def cmd_config(args: argparse.Namespace) -> None:
    """Show the MCP server configuration."""
    registered = _is_registered()
    entry = _server_entry()

    print(f"Server:     {SERVER_NAME}")
    print(f"Directory:  {SERVER_DIR}")
    print(f"Registered: {'yes' if registered else 'no'}")
    print()
    print("Config for ~/.claude.json:")
    print(json.dumps({"mcpServers": {SERVER_NAME: entry}}, indent=2))


def cmd_run(args: argparse.Namespace) -> None:
    """Run the MCP server (stdio mode)."""
    env = {**os.environ}
    env.pop("VIRTUAL_ENV", None)
    os.execvpe("uv", ["uv", "run", "--directory", str(SERVER_DIR), "python", "-m", "src.server"], env)


def cmd_setup(args: argparse.Namespace) -> None:
    """Add pwndbg-mcp to shell PATH so it can be run from anywhere."""
    shell = os.environ.get("SHELL", "")
    venv_bin = SERVER_DIR / ".venv" / "bin"
    path_line = f'export PATH="{venv_bin}:$PATH"'

    if "zsh" in shell:
        rc_file = Path.home() / ".zshrc"
        reload_cmd = "source ~/.zshrc"
    elif "bash" in shell:
        rc_file = Path.home() / ".bashrc"
        reload_cmd = "source ~/.bashrc"
    elif "fish" in shell:
        rc_file = Path.home() / ".config" / "fish" / "config.fish"
        path_line = f'set -gx PATH "{venv_bin}" $PATH'
        reload_cmd = "source ~/.config/fish/config.fish"
    else:
        print(f"Unknown shell: {shell}")
        print(f"Add this to your shell rc file manually:")
        print(f"  {path_line}")
        return

    # Check if already installed
    if rc_file.exists() and str(venv_bin) in rc_file.read_text():
        print("pwndbg-mcp is already in your PATH.")
        return

    # Append
    with open(rc_file, "a") as f:
        f.write(f"\n# pwndbg-mcp\n{path_line}\n")

    print(f"Added to {rc_file}")
    print(f"Run: {reload_cmd}")
    print("Then use 'pwndbg-mcp' from anywhere.")


def main() -> None:
    parser = argparse.ArgumentParser(prog="pwndbg-mcp", description="pwndbg-mcp server manager")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("install", help="Install deps and register in ~/.claude.json")
    sub.add_parser("uninstall", help="Unregister from ~/.claude.json")
    sub.add_parser("config", help="Show server configuration")
    sub.add_parser("run", help="Run the MCP server (default)")
    sub.add_parser("path", help="Add pwndbg-mcp to shell PATH")

    args = parser.parse_args()

    commands = {
        "install": cmd_install,
        "uninstall": cmd_uninstall,
        "config": cmd_config,
        "run": cmd_run,
        "path": cmd_setup,
    }
    commands[args.command or "run"](args)


if __name__ == "__main__":
    main()
