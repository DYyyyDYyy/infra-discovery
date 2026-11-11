from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import asyncssh
import pytest

from infra_discovery import collector
from infra_discovery.collector import COMMANDS, Credentials, Target
from infra_discovery.models import RawScan


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("10.0.0.1", Target("10.0.0.1", 22, "root")),
        ("admin@web:2222", Target("web", 2222, "admin")),
        ("web:22", Target("web", 22, "root")),
    ],
)
def test_target_parse(spec: str, expected: Target) -> None:
    assert Target.parse(spec) == expected


@pytest.mark.parametrize("spec", ["", "web:", "web:abc", "u@"])
def test_target_parse_errors(spec: str) -> None:
    with pytest.raises(ValueError, match="bad target"):
        Target.parse(spec)


def test_target_str() -> None:
    assert str(Target("h")) == "h"
    assert str(Target("h", 2222)) == "h:2222"


class FakeConn:
    """Stands in for an asyncssh connection: answers each command from a table."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.commands: list[str] = []

    async def __aenter__(self) -> FakeConn:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def run(self, command: str, check: bool = False) -> SimpleNamespace:
        self.commands.append(command)
        answer = self.answers.get(command, SimpleNamespace(stdout="ok\n", stderr="", exit_status=0))
        if isinstance(answer, Exception):
            raise answer
        return answer  # type: ignore[no-any-return]


def test_scan_host_collects_outputs_and_errors(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake = FakeConn(
        {
            COMMANDS["ss"]: SimpleNamespace(stdout="", stderr="ss: not found", exit_status=127),
            COMMANDS["ps"]: asyncssh.ChannelOpenError(2, "nope"),
        }
    )
    seen: dict[str, Any] = {}

    async def connect(host: str, **kwargs: Any) -> FakeConn:
        seen.update(kwargs, host=host)
        return fake

    monkeypatch.setattr(asyncssh, "connect", connect)
    key = tmp_path / "id"
    (raw,) = asyncio.run(collector.scan_many([Target("h", 2222)], Credentials(key)))
    assert raw.target == "h:2222"
    assert raw.outputs["uname"] == "ok\n"
    assert raw.errors["ss"] == "exit 127: ss: not found"
    assert "ChannelOpenError" in raw.errors["ps"]
    # never touch ~/.ssh: explicit key, no agent, no ssh config
    assert seen["client_keys"] == [str(key)]
    assert seen["agent_path"] is None
    assert seen["config"] is None
    assert len(fake.commands) == len(COMMANDS)


def test_save_and_load_raw(tmp_path: Path) -> None:
    raw = RawScan(target="h:2222", outputs={"uname": "Linux"})
    collector.save_raw([raw], tmp_path)
    assert collector.load_raw(tmp_path / "h_2222.json") == raw


def test_wait_for_ssh_success() -> None:
    async def go() -> list[Target]:
        server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            return await collector.wait_for_ssh([Target("127.0.0.1", port)], timeout=5)

    assert asyncio.run(go()) == []
