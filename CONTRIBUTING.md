# Contributing

Thank you for your interest in contributing to **envault-cli**!

## Getting Started

1. **Fork** the repository and clone your fork
2. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature
   ```
3. Make your changes
4. Commit using [Conventional Commits](https://www.conventionalcommits.org/):
   ```
   feat: add new widget
   fix: handle nil pointer in parser
   chore: update CI action versions
   ```
5. Push and **open a Pull Request** against `main`

## Development Setup

CI installs the hash-locked versions in `requirements/dev.txt`, then the package
without its dependencies; do the same locally:

```bash
python -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary :all: -r requirements/dev.txt
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
.venv/bin/python -m pip check
source .venv/bin/activate
```

The hooks in `.pre-commit-config.yaml` (detect-secrets, ruff, and file checks) run
with [pre-commit](https://pre-commit.com/), which is not part of the lock: install
it separately and run `pre-commit install`.

Before opening a PR, run the checks CI runs:

```bash
pytest tests/unit/ -v
ruff check src/ tests/ infra/
ruff format --check src/ tests/ infra/
mypy src/envault/
```

Changes under `infra/` also need the CDK assertion tests and a strict synth; see
the Development section of [README.md](README.md). After changing a dependency,
regenerate the lock with the `uv pip compile` command next to the `dev` extra in
`pyproject.toml`.

## Code Style

- Follow existing patterns in the codebase
- Keep PRs focused and small
- Write tests for non-trivial changes

## Pull Request Guidelines

- Fill out the PR template completely
- Link any related issues (`Closes #123`)
- Ensure CI passes before requesting review
- Address review feedback promptly
