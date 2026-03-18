# Contributing to pwndbg-mcp

Thanks for your interest in contributing! This project is maintained by a single developer, so contributions are welcome but reviewed on a best-effort basis.

## Reporting Issues

If you run into a bug or unexpected behavior, please [open an issue](https://github.com/echo8134/pwndbg-mcp/issues/new) with:

- **What you were doing** — the tool call or command that triggered the issue
- **What happened** — error messages, unexpected output, or incorrect behavior
- **What you expected** — how it should have worked
- **Environment** — OS, Python version, GDB version, pwndbg version

The more detail, the easier it is to reproduce and fix.

## Pull Requests

PRs are welcome for bug fixes. If you'd like to add a feature, open an issue first so we can discuss the approach before you put in the work.

### Setup

```bash
git clone https://github.com/echo8134/pwndbg-mcp.git && cd pwndbg-mcp
uv sync --dev
```

### Before Submitting

- Run the linter: `uv run ruff check src/`
- Run type checks: `uv run pyright src/`
- Run tests: `uv run pytest`
- Keep changes focused — one fix per PR

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
