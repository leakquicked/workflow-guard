# Workflow Guard

**A read-only static security linter for GitHub Actions workflow YAML.**

Workflow Guard reviews workflow files for common CI/CD security footguns. It is built for maintainers and security learners who want actionable findings before a workflow runs.

## Checks

| Rule | Severity | Description |
|---|---|---|
| WG001 | High | Missing explicit workflow permissions |
| WG002 | Medium | External action not pinned to a full 40-character commit SHA |
| WG003 | High | Privileged `pull_request_target` trigger |
| WG004 | High | Common untrusted GitHub event data interpolated directly into a shell script |
| WG005 | Medium | Checkout credentials explicitly persisted |
| WG006 | High | `write-all` token permissions |

## Requirements and setup

Python 3.10+ and PyYAML 6+.

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

```bash
python workflow_guard.py .github/workflows
python workflow_guard.py examples/unsafe.yml --format json
python workflow_guard.py .github/workflows --strict
```

Exit codes: `0` analysis completed, `1` strict mode found findings, `2` invalid input or unreadable files.

## Example

```text
examples/unsafe.yml:4: WG006 HIGH Workflow grants write-all token permissions.
examples/unsafe.yml:10: WG002 MEDIUM Action 'actions/checkout@v4' is not pinned to a full 40-character commit SHA.
...
```

## Tests

```bash
python -m unittest discover -s tests -v
```

A GitHub Actions workflow runs the same test suite on pushes and pull requests.

## Safety and limitations

- Reads local YAML files only; it never connects to GitHub or executes workflow commands.
- Uses PyYAML BaseLoader so the YAML key `on` remains a string.
- Reports heuristic indicators, not confirmed vulnerabilities.
- Does not resolve reusable workflows, inspect action source, evaluate every expression, or perform complete taint analysis.
- Review each finding in context; false positives and missed cases are possible.

See [docs/rules.md](docs/rules.md) and [examples/unsafe.yml](examples/unsafe.yml).

## License

MIT.
