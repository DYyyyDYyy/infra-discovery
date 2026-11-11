"""Property tests for the rule parser."""

from __future__ import annotations

import contextlib
import json
import re

from hypothesis import given
from hypothesis import strategies as st

from infra_discovery.collector import SOURCES
from infra_discovery.dsl import RuleError, parse_rules

KEYWORDS = {"rule", "kind", "when", "extract", "from", "regex", "set", "not", "matches"}
names = st.from_regex(r"[a-z_][a-z0-9_]{0,10}", fullmatch=True).filter(lambda s: s not in KEYWORDS)
sources = st.sampled_from(sorted(SOURCES))
# regex bodies without '/' or newlines, guaranteed to compile
literals = st.text(alphabet=st.characters(categories=["L", "N"]) | st.sampled_from(" -_.:"), min_size=1, max_size=12)
values = st.text(alphabet=st.characters(blacklist_categories=["Cs", "Cc"]), max_size=20)


@st.composite
def rule_specs(draw: st.DrawFn) -> dict[str, object]:
    return {
        "name": draw(names),
        "kind": draw(st.sampled_from(["host", "software"])),
        "when": draw(st.lists(st.tuples(sources, literals, st.booleans()), min_size=1, max_size=3)),
        "extract": draw(st.lists(st.tuples(names, sources, literals), max_size=3)),
        "set": draw(st.dictionaries(names, values, max_size=3)),
    }


def render(spec: dict[str, object]) -> str:
    lines = [f"rule {spec['name']} {{", f"  kind {spec['kind']}"]
    for src, lit, neg in spec["when"]:  # type: ignore[attr-defined]
        lines.append(f"  when {src} {'not ' if neg else ''}matches /{re.escape(lit).replace('/', '')}/")
    for field, src, lit in spec["extract"]:  # type: ignore[attr-defined]
        lines.append(f"  extract {field} from {src} regex /({re.escape(lit).replace('/', '')})/")
    sets = dict(spec["set"])  # type: ignore[call-overload]
    if spec["kind"] == "software":
        sets.setdefault("name", "x")
    for field, value in sets.items():
        lines.append(f"  set {field} = {json.dumps(value)}")
    return "\n".join([*lines, "}"])


@given(rule_specs())
def test_rendered_rules_round_trip(spec: dict[str, object]) -> None:
    (rule,) = parse_rules(render(spec))
    assert rule.name == spec["name"]
    assert rule.kind == spec["kind"]
    assert [(c.source, c.negate) for c in rule.conditions] == [(s, n) for s, _, n in spec["when"]]  # type: ignore[attr-defined]
    assert [e.field for e in rule.extracts] == [f for f, _, _ in spec["extract"]]  # type: ignore[attr-defined]
    for field, value in spec["set"].items():  # type: ignore[attr-defined]
        assert rule.sets[field] == value


@given(rule_specs())
def test_extract_finds_its_literal(spec: dict[str, object]) -> None:
    (rule,) = parse_rules(render(spec))
    for ex, (_, src, lit) in zip(rule.extracts, spec["extract"], strict=True):  # type: ignore[call-overload]
        assert ex.apply({src: f"before {lit} after"}) == lit.strip()


@given(st.text(max_size=200))
def test_parser_never_crashes(text: str) -> None:
    with contextlib.suppress(RuleError):
        parse_rules(text)
