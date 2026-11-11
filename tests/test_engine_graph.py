from __future__ import annotations

from infra_discovery.dsl import Rule
from infra_discovery.engine import analyze, parse_ps, parse_ss, split_addr
from infra_discovery.graph import build_graph, to_mermaid
from infra_discovery.models import RawScan


def test_parse_ps_procps_and_busybox() -> None:
    procps = (
        "    PID USER     COMMAND\n      1 root     sshd: /usr/sbin/sshd -D\n     11 postgres /usr/bin/postgres -D /d\n"
    )
    busybox = "PID   USER     COMMAND\n    7 root     {app-entrypoint.} /bin/sh /x\n    3 root     [kworker/0:1]\n"
    assert [(p.pid, p.name) for p in parse_ps(procps, "h")] == [(1, "sshd"), (11, "postgres")]
    assert [p.name for p in parse_ps(busybox, "h")] == ["app-entrypoint.", "kworker"]


def test_split_addr() -> None:
    assert split_addr("0.0.0.0:80") == ("0.0.0.0", 80)
    assert split_addr("[::]:22") == ("::", 22)
    assert split_addr("[::ffff:10.0.0.5]:5432") == ("10.0.0.5", 5432)
    assert split_addr("127.0.0.53%lo:53") == ("127.0.0.53", 53)
    assert split_addr("*:*") is None


def test_parse_ss() -> None:
    text = (
        'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=8,fd=5))\n'
        "LISTEN 0 244 [::]:5432 [::]:*\n"
        'ESTAB 0 0 10.0.0.2:4000 10.0.0.3:6379 users:(("redis-cli",pid=9,fd=3))\n'
        "TIME-WAIT 0 0 10.0.0.2:4001 10.0.0.3:6379\n"
        "garbage\n"
    )
    listeners, conns = parse_ss(text, "h")
    assert [(lst.port, lst.process) for lst in listeners] == [(80, "nginx"), (5432, None)]
    assert len(conns) == 1
    assert (conns[0].peer_ip, conns[0].peer_port, conns[0].process) == ("10.0.0.3", 6379, "redis-cli")


def test_analyze_app(rules: list[Rule], raws: dict[str, RawScan]) -> None:
    inv = analyze(raws["app"], rules)
    assert inv.host.ips == ["172.30.250.14"]
    assert sorted(s.name for s in inv.software) == ["openssh-server", "psql", "redis-cli"]
    assert {(c.peer_port, c.process) for c in inv.connections} >= {(6379, "redis-cli"), (5432, "psql")}


def test_hostname_falls_back_to_target(rules: list[Rule]) -> None:
    inv = analyze(RawScan(target="10.1.1.1", outputs={"uname": "Linux x 6.1 #1 x86_64"}), rules)
    assert inv.host.name == "10.1.1.1"


def test_graph_relationships(rules: list[Rule], raws: dict[str, RawScan]) -> None:
    g = build_graph([analyze(r, rules) for r in raws.values()])
    kinds = {n.kind for n in g.nodes.values()}
    assert kinds == {"host", "software", "process", "listener"}
    edges = set(g.edges)
    assert "host:web -runs-> software:web/nginx" in edges
    assert "software:web/nginx -listens_on-> listener:web/tcp/80" in edges
    assert "software:web/nginx -has_process-> process:web/nginx" in edges
    # ss cannot see the postgres socket owner (no CAP_SYS_PTRACE); the rule's well-known port links it
    assert "software:db/postgresql -listens_on-> listener:db/tcp/5432" in edges
    assert "software:app/redis-cli -connects_to-> software:cache/redis" in edges
    assert "software:app/psql -connects_to-> software:db/postgresql" in edges
    # loopback-only listeners (docker's embedded DNS) are not part of the graph
    assert not any(
        k.startswith("listener:") and "127.0.0.11" in n.attrs.get("addresses", "") for k, n in g.nodes.items()
    )
    # the scanner's own SSH session (from an unknown IP) creates no edges
    assert not [e for e in g.edges.values() if e.kind == "connects_to" and "sshd" in e.dst]
    # volatile data never ends up in the graph
    assert all("pid" not in n.attrs for n in g.nodes.values())


def test_unowned_listener_hangs_off_host_and_receives_connections() -> None:
    from infra_discovery.models import Connection, Host, Inventory, Listener

    server = Inventory(host=Host(name="s", target="s", ips=["10.0.0.1"]))
    server.listeners = [Listener(host="s", proto="tcp", address="0.0.0.0", port=9000)]
    client = Inventory(host=Host(name="c", target="c", ips=["10.0.0.2"]))
    client.connections = [
        Connection(host="c", local_ip="10.0.0.2", local_port=5000, peer_ip="10.0.0.1", peer_port=9000),
        Connection(host="c", local_ip="10.0.0.2", local_port=5001, peer_ip="10.0.0.1", peer_port=9999),
    ]
    g = build_graph([server, client])
    assert set(g.edges) == {"host:s -listens_on-> listener:s/tcp/9000", "host:c -connects_to-> listener:s/tcp/9000"}


def test_mermaid(rules: list[Rule], raws: dict[str, RawScan]) -> None:
    g = build_graph([analyze(r, rules) for r in raws.values()])
    text = to_mermaid(list(g.nodes.values()), list(g.edges.values()))
    assert text.startswith("graph LR\n")
    assert '[["web<br/>Debian GNU/Linux 13"]]' in text
    assert '("web/nginx 1.26.3")' in text
    assert "==>|connects_to|" in text
