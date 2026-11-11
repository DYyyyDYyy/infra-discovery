"""Turn raw command output into typed objects using the rules."""

from __future__ import annotations

import re

from .dsl import Rule
from .models import Connection, Host, Inventory, Listener, Process, RawScan, Software

_USERS = re.compile(r'users:\(\("([^"]+)"')
_INET = re.compile(r"\binet (\d+\.\d+\.\d+\.\d+)/")


def parse_ps(text: str, host: str) -> list[Process]:
    procs = []
    for line in text.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3 or not parts[0].isdigit():
            continue  # header or junk
        pid, user, cmd = parts
        exe = cmd.split()[0].rstrip(":")  # "sshd: /usr/sbin/sshd -D" -> sshd
        # [kworker/0:1] is a kernel thread, {applet} a busybox applet, anything else a path
        name = exe.strip("[]{}").split("/", 1)[0] if exe.startswith(("[", "{")) else exe.rsplit("/", 1)[-1]
        procs.append(Process(host=host, pid=int(pid), user=user, name=name, cmd=cmd))
    return procs


def split_addr(addr: str) -> tuple[str, int] | None:
    ip, _, port = addr.rpartition(":")
    if not port.isdigit():
        return None
    ip = ip.strip("[]").removeprefix("::ffff:")
    ip = ip.split("%", 1)[0]  # drop interface scope, e.g. 127.0.0.53%lo
    return ip, int(port)


def parse_ss(text: str, host: str) -> tuple[list[Listener], list[Connection]]:
    listeners: list[Listener] = []
    conns: list[Connection] = []
    for line in text.splitlines():
        cols = line.split()
        if len(cols) < 5:
            continue
        state, local, peer = cols[0], split_addr(cols[3]), split_addr(cols[4]) if cols[4] != "*" else None
        m = _USERS.search(line)
        proc = m.group(1) if m else None
        if state == "LISTEN" and local:
            listeners.append(Listener(host=host, proto="tcp", address=local[0], port=local[1], process=proc))
        elif state == "ESTAB" and local and peer:
            conns.append(
                Connection(
                    host=host,
                    local_ip=local[0],
                    local_port=local[1],
                    peer_ip=peer[0],
                    peer_port=peer[1],
                    process=proc,
                )
            )
    return listeners, conns


def analyze(raw: RawScan, rules: list[Rule]) -> Inventory:
    out = raw.outputs
    name = out.get("hostname", "").strip() or raw.target
    host = Host(
        name=name, target=raw.target, ips=[ip for ip in _INET.findall(out.get("ip_addr", "")) if ip != "127.0.0.1"]
    )
    inv = Inventory(host=host)
    for rule in rules:
        attrs = rule.evaluate(out)
        if attrs is None:
            continue
        if rule.kind == "host":
            host.attrs.update(attrs)
        else:
            sw_name = attrs.pop("name")
            inv.software.append(
                Software(
                    host=name,
                    name=sw_name,
                    version=attrs.pop("version", None),
                    process=attrs.pop("process", None),
                    attrs=attrs,
                )
            )
    inv.processes = parse_ps(out.get("ps", ""), name)
    inv.listeners, inv.connections = parse_ss(out.get("ss", ""), name)
    return inv
