from __future__ import annotations

from pathlib import Path

import pytest

from infra_discovery.dsl import RuleError, load_rules, parse_rules

OK = """
# comment
rule demo {
    kind software
    when ps matches /demo-server/
    when ps not matches /demo-disabled/
    set name = "demo \\"x\\""
    extract version from packages regex /^demo (\\S+)/
    extract version from packages regex /^demo-(\\S+)$/
    extract path from ps regex /--path=(\\S+\\/bin)/
    extract flavour from uname regex /(LINUX)/i
}
"""


def test_parse_and_evaluate() -> None:
    (rule,) = parse_rules(OK)
    assert rule.name == "demo"
    assert rule.kind == "software"
    out = {"ps": "1 root demo-server --path=/opt/demo/bin", "packages": "x 1\ndemo-2.0\n", "uname": "Linux h"}
    assert rule.evaluate(out) == {"name": 'demo "x"', "version": "2.0", "path": "/opt/demo/bin", "flavour": "Linux"}


def test_negated_condition() -> None:
    (rule,) = parse_rules(OK)
    assert rule.evaluate({"ps": "demo-server demo-disabled"}) is None
    assert rule.evaluate({}) is None


def test_first_extract_wins() -> None:
    (rule,) = parse_rules(OK)
    attrs = rule.evaluate({"ps": "demo-server", "packages": "demo 1.0\ndemo-2.0"})
    assert attrs is not None
    assert attrs["version"] == "1.0"


def test_set_overrides_extract() -> None:
    (rule,) = parse_rules(
        'rule r { kind host when uname matches /L/ set os = "fixed" extract os from uname regex /(L)/ }'
    )
    assert rule.evaluate({"uname": "L"}) == {"os": "fixed"}


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("rule r { kind host when uname matches /x/ ", "unexpected end of file"),
        ("rule r { kind host when uname maches /x/ }", "1:31: unexpected 'maches', expected one of: 'matches', 'not'"),
        ("rule r {\n  kind host\n  when uname matches /x/\n  set a = 1\n}", "4:11: unexpected character"),
        ("rule r { kind host when nope matches /x/ }", "1:25: unknown source 'nope'"),
        ("rule r { kind host when uname matches /(/ }", "invalid regex /(/"),
        ("rule r { kind host when uname matches /x/ extract a from uname regex /x/ }", "needs a (group)"),
        ("rule r { kind thing when uname matches /x/ }", "kind must be one of"),
        ("rule r { when uname matches /x/ }", "has no 'kind'"),
        ("rule r { kind host }", "needs at least one 'when'"),
        ("rule r { kind software when ps matches /x/ }", "needs 'set name"),
    ],
)
def test_errors_are_readable(text: str, message: str) -> None:
    with pytest.raises(RuleError, match=None) as info:
        parse_rules(text, "t.rule")
    assert message in str(info.value)
    assert str(info.value).startswith("t.rule:")


def test_duplicate_rule_names(tmp_path: Path) -> None:
    body = 'rule same { kind host when uname matches /x/ set a = "b" }\n'
    (tmp_path / "a.rule").write_text(body)
    (tmp_path / "b.rule").write_text(body)
    with pytest.raises(RuleError, match="duplicate rule 'same'"):
        load_rules(tmp_path)


def test_empty_file() -> None:
    assert parse_rules("# nothing here\n") == []
