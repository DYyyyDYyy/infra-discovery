"""A tiny TPL-like rule language for discovery patterns.

    rule nginx {
        kind software
        when ps matches /nginx: master process/
        extract version from packages regex /^nginx (\\S+)/
        set name = "nginx"
        set process = "nginx"
    }

``when`` lines must all hold for a rule to fire, ``extract`` takes group 1 of the
first matching regex (several extracts of one field act as fallbacks), ``set``
assigns a constant. Regexes are multiline; a trailing ``i`` makes them case-insensitive.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from lark import Lark, Token, Tree, UnexpectedCharacters, UnexpectedEOF, UnexpectedInput, UnexpectedToken
from lark.lexer import PatternStr

from .collector import SOURCES

GRAMMAR = r"""
start: rule*
rule: "rule" NAME "{" stmt* "}"
?stmt: kind | when | extract | assign
kind: "kind" NAME
when: "when" NAME NOT? "matches" REGEX
extract: "extract" NAME "from" NAME "regex" REGEX
assign: "set" NAME "=" STRING

NOT: "not"
NAME: /[A-Za-z_][A-Za-z0-9_]*/
REGEX: /\/(?:\\.|[^\/\\\n])+\/i?/
STRING: /"(?:\\.|[^"\\\n])*"/
COMMENT: /#[^\n]*/
%import common.WS
%ignore WS
%ignore COMMENT
"""

KINDS = ("host", "software")
_parser = Lark(GRAMMAR, parser="lalr")


class RuleError(Exception):
    """A syntax or semantic error in a rule file, with file:line:column."""


@dataclass(frozen=True)
class Condition:
    source: str
    pattern: re.Pattern[str]
    negate: bool = False

    def holds(self, outputs: dict[str, str]) -> bool:
        found = self.pattern.search(outputs.get(self.source, "")) is not None
        return found != self.negate


@dataclass(frozen=True)
class Extract:
    field: str
    source: str
    pattern: re.Pattern[str]

    def apply(self, outputs: dict[str, str]) -> str | None:
        m = self.pattern.search(outputs.get(self.source, ""))
        return m.group(1).strip() if m and m.group(1) is not None else None


@dataclass
class Rule:
    name: str
    kind: str
    origin: str
    conditions: list[Condition] = field(default_factory=list)
    extracts: list[Extract] = field(default_factory=list)
    sets: dict[str, str] = field(default_factory=dict)

    def evaluate(self, outputs: dict[str, str]) -> dict[str, str] | None:
        """Return the attributes this rule produces, or None if it does not fire."""
        if not all(c.holds(outputs) for c in self.conditions):
            return None
        attrs = dict(self.sets)
        for ex in self.extracts:
            if ex.field not in attrs:
                value = ex.apply(outputs)
                if value:
                    attrs[ex.field] = value
        return attrs


def _regex(tok: Token, where: str) -> re.Pattern[str]:
    text = str(tok)
    flags = re.MULTILINE
    if text.endswith("i"):
        flags |= re.IGNORECASE
        text = text[:-1]
    body = text[1:-1].replace(r"\/", "/")
    try:
        return re.compile(body, flags)
    except re.error as exc:
        raise RuleError(f"{where}:{tok.line}:{tok.column}: invalid regex {text}: {exc}") from None


def _source(tok: Token, where: str) -> str:
    if str(tok) not in SOURCES:
        known = ", ".join(sorted(SOURCES))
        raise RuleError(f"{where}:{tok.line}:{tok.column}: unknown source {str(tok)!r} (known: {known})")
    return str(tok)


def _describe(terminal: str) -> str:
    """Keyword terminals as they are written (``'matches'``), others by name (``regex``)."""
    if terminal == "$END":
        return "end of file"
    pattern = _parser.get_terminal(terminal).pattern
    return repr(pattern.value) if isinstance(pattern, PatternStr) else terminal.lower()


def _syntax_error(exc: UnexpectedInput, text: str, where: str) -> RuleError:
    if isinstance(exc, UnexpectedEOF) or (isinstance(exc, UnexpectedToken) and exc.token.type == "$END"):
        return RuleError(f"{where}: unexpected end of file (missing '}}'?)")
    ctx = exc.get_context(text).rstrip()
    if isinstance(exc, UnexpectedToken):
        expected = ", ".join(sorted(_describe(t) for t in (exc.accepts or exc.expected)))
        what = f"unexpected {str(exc.token)!r}, expected one of: {expected}"
    elif isinstance(exc, UnexpectedCharacters):
        what = f"unexpected character {exc.char!r}"
    else:  # pragma: no cover - lark has no other subclasses today
        what = str(exc)
    return RuleError(f"{where}:{exc.line}:{exc.column}: {what}\n{ctx}")


def parse_rules(text: str, where: str = "<string>") -> list[Rule]:
    try:
        tree = _parser.parse(text)
    except UnexpectedInput as exc:
        raise _syntax_error(exc, text, where) from None

    rules: list[Rule] = []
    for node in tree.children:
        assert isinstance(node, Tree)
        name_tok, stmts = cast(Token, node.children[0]), node.children[1:]
        origin = f"{where}:{name_tok.line}"
        kind: str | None = None
        rule = Rule(name=str(name_tok), kind="", origin=origin)
        for st in cast("list[Tree[Token]]", stmts):
            args = cast("list[Token]", st.children)
            if st.data == "kind":
                if str(args[0]) not in KINDS:
                    raise RuleError(f"{where}:{args[0].line}:{args[0].column}: kind must be one of {KINDS}")
                kind = str(args[0])
            elif st.data == "when":
                negate = len(args) == 3
                rule.conditions.append(Condition(_source(args[0], where), _regex(args[-1], where), negate))
            elif st.data == "extract":
                pat = _regex(args[2], where)
                if pat.groups < 1:
                    raise RuleError(f"{where}:{args[2].line}:{args[2].column}: extract regex needs a (group)")
                rule.extracts.append(Extract(str(args[0]), _source(args[1], where), pat))
            else:  # assign
                rule.sets[str(args[0])] = json.loads(str(args[1]))
        if kind is None:
            raise RuleError(f"{origin}: rule {rule.name!r} has no 'kind'")
        rule.kind = kind
        if not rule.conditions:
            raise RuleError(f"{origin}: rule {rule.name!r} needs at least one 'when'")
        if kind == "software" and "name" not in rule.sets:
            raise RuleError(f"{origin}: software rule {rule.name!r} needs 'set name = \"...\"'")
        rules.append(rule)
    return rules


def load_rules(directory: Path) -> list[Rule]:
    rules: list[Rule] = []
    seen: dict[str, str] = {}
    for path in sorted(directory.glob("*.rule")):
        for rule in parse_rules(path.read_text(), str(path)):
            if rule.name in seen:
                raise RuleError(f"{rule.origin}: duplicate rule {rule.name!r} (first at {seen[rule.name]})")
            seen[rule.name] = rule.origin
            rules.append(rule)
    return rules
