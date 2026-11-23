"""The committed gitleaks config must extend the default rule set."""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_GITLEAKS = _REPO_ROOT / ".gitleaks.toml"


def test_gitleaks_config_extends_default_rules() -> None:
    """A config with only [allowlist] replaces the default rules and scans nothing."""
    text = _GITLEAKS.read_text()
    assert re.search(r"(?m)^useDefault\s*=\s*true\s*$", text)
    assert "[extend]" in text
    assert "[allowlist]" in text
