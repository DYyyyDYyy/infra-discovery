"""Agentless collector: runs read-only commands over SSH and keeps the raw output."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path

import asyncssh

from .models import RawScan

# source name -> shell command; source names are what rules refer to
COMMANDS: dict[str, str] = {
    "uname": "uname -a",
    "os_release": "cat /etc/os-release",
    "hostname": "cat /proc/sys/kernel/hostname",
    "ip_addr": "ip -o -4 addr show",
    "ps": "ps -eo pid,user,args 2>/dev/null || ps -o pid,user,args",
    "ss": "ss -tanpH",
    "packages": (
        "if command -v dpkg-query >/dev/null; then dpkg-query -W -f='${Package} ${Version}\\n';"
        " elif command -v rpm >/dev/null; then rpm -qa --qf '%{NAME} %{VERSION}\\n';"
        " elif command -v apk >/dev/null; then apk info -v 2>/dev/null; fi"
    ),
}
SOURCES = frozenset(COMMANDS)


@dataclass(frozen=True)
class Target:
    host: str
    port: int = 22
    user: str = "root"

    @classmethod
    def parse(cls, spec: str, default_user: str = "root") -> Target:
        """Parse ``[user@]host[:port]``."""
        user, _, rest = spec.rpartition("@")
        host, sep, port = rest.partition(":")
        if not host or (sep and not port.isdigit()):
            raise ValueError(f"bad target: {spec!r}")
        return cls(host=host, port=int(port) if sep else 22, user=user or default_user)

    def __str__(self) -> str:
        return self.host if self.port == 22 else f"{self.host}:{self.port}"


@dataclass(frozen=True)
class Credentials:
    key_path: Path
    connect_timeout: float = 10.0
    command_timeout: float = 15.0


async def scan_host(target: Target, creds: Credentials) -> RawScan:
    raw = RawScan(target=str(target))
    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(
                target.host,
                port=target.port,
                username=target.user,
                client_keys=[str(creds.key_path)],
                known_hosts=None,  # lab only: host keys are regenerated on every build
                agent_path=None,
                config=None,  # never read ~/.ssh/config
            ),
            creds.connect_timeout,
        )
    except (OSError, ValueError, asyncssh.Error, TimeoutError) as exc:  # ValueError: unreadable key
        raw.errors["connect"] = f"{type(exc).__name__}: {exc}"
        return raw
    async with conn:
        for source, command in COMMANDS.items():
            try:
                res = await asyncio.wait_for(conn.run(command, check=False), creds.command_timeout)
            except (asyncssh.Error, TimeoutError) as exc:
                raw.errors[source] = f"{type(exc).__name__}: {exc}"
                continue
            raw.outputs[source] = str(res.stdout or "")
            if res.exit_status:
                raw.errors[source] = f"exit {res.exit_status}: {str(res.stderr or '').strip()}"
    return raw


async def scan_many(targets: list[Target], creds: Credentials, concurrency: int = 10) -> list[RawScan]:
    sem = asyncio.Semaphore(concurrency)

    async def one(t: Target) -> RawScan:
        async with sem:
            return await scan_host(t, creds)

    return list(await asyncio.gather(*(one(t) for t in targets)))


async def wait_for_ssh(targets: list[Target], timeout: float = 60.0) -> list[Target]:
    """Wait until every target accepts TCP on its SSH port; return the ones that never did."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    pending = list(targets)
    while pending and loop.time() < deadline:
        still = []
        for t in pending:
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(t.host, t.port), 2)
                w.close()
            except (OSError, TimeoutError):
                still.append(t)
        pending = still
        if pending:
            await asyncio.sleep(1)
    return pending


def save_raw(scans: list[RawScan], directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for s in scans:
        name = s.target.replace(":", "_") + ".json"
        (directory / name).write_text(s.model_dump_json(indent=2) + "\n")


def load_raw(path: Path) -> RawScan:
    return RawScan.model_validate(json.loads(path.read_text()))
