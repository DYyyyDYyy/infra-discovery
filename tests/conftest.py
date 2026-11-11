from __future__ import annotations

from pathlib import Path

import pytest

from infra_discovery.collector import load_raw
from infra_discovery.dsl import Rule, load_rules
from infra_discovery.models import RawScan

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
RULES = ROOT / "rules"
HOSTS = ("web", "db", "cache", "app")


@pytest.fixture(scope="session")
def rules() -> list[Rule]:
    return load_rules(RULES)


@pytest.fixture(scope="session")
def raws() -> dict[str, RawScan]:
    """Real command output captured from the lab (`discover scan --save-raw tests/fixtures`)."""
    return {h: load_raw(FIXTURES / f"{h}.json") for h in HOSTS}
