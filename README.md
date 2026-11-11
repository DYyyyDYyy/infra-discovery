# infra-discovery

[![ci](https://github.com/DYyyyDYyy/infra-discovery/actions/workflows/ci.yml/badge.svg)](https://github.com/DYyyyDYyy/infra-discovery/actions/workflows/ci.yml)

Agentless software discovery in the spirit of BMC Discovery: log in to hosts over SSH, run read-only
commands, identify the OS, software, versions, listening ports and client→server dependencies with
TPL-like rules, and keep the result as a CMDB graph with change history.

```bash
make lab && make scan      # 4 containers (Debian, Rocky, Alpine x2), first scan
make scan-check            # second scan: must report "diff: no changes"
make serve                 # http://127.0.0.1:8000  graph page + REST API
```

Requirements: Docker, [uv](https://docs.astral.sh/uv/), make, `ssh-keygen`. No root, no cloud.

## Architecture

```mermaid
flowchart LR
  T[targets] --> C[collector<br/>asyncssh, N parallel, timeouts]
  C -->|raw output<br/>uname, os-release, ps, ss, dpkg/rpm/apk| E[engine]
  R[rules/*.rule<br/>Lark DSL] --> E
  E -->|Host, Software, Process,<br/>Listener, Connection| G[graph builder]
  G --> DB[(SQLite CMDB<br/>nodes, edges, changes)]
  DB --> CLI[discover CLI]
  DB --> API[FastAPI<br/>/hosts /graph /diff]
  API --> UI[graph.html<br/>cytoscape]
```

## What a lab scan finds

Output of `discover graph` after `make scan` (process nodes hidden), rendered by GitHub.
The same graph is interactive at `make serve`.

```mermaid
graph LR
  n0[["app<br/>Alpine Linux 3.22.8"]]
  n1[["cache<br/>Alpine Linux 3.22.8"]]
  n2[["db<br/>Rocky Linux 9.8"]]
  n3[["web<br/>Debian GNU/Linux 13"]]
  n4>"app/tcp/22"]
  n5>"cache/tcp/22"]
  n6>"cache/tcp/6379"]
  n7>"db/tcp/22"]
  n8>"db/tcp/5432"]
  n9>"web/tcp/22"]
  n10>"web/tcp/80"]
  n11("app/openssh-server 10.0_p1")
  n12("app/psql 17.11")
  n13("app/redis-cli 8.0.4")
  n14("cache/openssh-server 10.0_p1")
  n15("cache/redis 8.0.4")
  n16("db/openssh-server 9.9p1")
  n17("db/postgresql 13.23")
  n18("web/nginx 1.26.3")
  n19("web/openssh-server 10.0p1")
  n0 -->|runs| n11
  n0 -->|runs| n12
  n0 -->|runs| n13
  n1 -->|runs| n14
  n1 -->|runs| n15
  n2 -->|runs| n16
  n2 -->|runs| n17
  n3 -->|runs| n18
  n3 -->|runs| n19
  n11 -->|listens_on| n4
  n12 ==>|connects_to| n17
  n13 ==>|connects_to| n15
  n14 -->|listens_on| n5
  n15 -->|listens_on| n6
  n16 -->|listens_on| n7
  n17 -->|listens_on| n8
  n18 -->|listens_on| n10
  n19 -->|listens_on| n9
```

## Rules

A rule fires when all `when` conditions hold; `extract` takes regex group 1 (repeated extracts are
fallbacks, e.g. one per package format); `set` assigns constants.

```
rule postgresql {
    kind software
    when ps matches /postgres: checkpointer/
    set name = "postgresql"
    set process = "postgres"          # links the software to its process and sockets
    set ports = "5432"                # fallback when ss cannot see the socket owner
    extract version from packages regex /^postgresql\d*-server (\S+)/              # rpm
    extract version from packages regex /^postgresql-\d+ (?:\d+:)?([^-\s+]+)/      # dpkg
    extract version from packages regex /^postgresql\d+-(\d[^-\s]*)-r\d+$/        # apk
}
```

Sources: `uname`, `os_release`, `hostname`, `ip_addr`, `ps`, `ss`, `packages`. Errors point at the
spot: `demo.rule:1:31: unexpected 'maches', expected one of: 'matches', 'not'`.
Rule tests run against real output captured from the lab (`tests/fixtures`, refresh with
`discover scan ... --save-raw tests/fixtures`).

## CLI and API

| | |
|---|---|
| `discover scan HOST... --key K` | scan over SSH, reconcile into the CMDB, print the diff |
| `discover analyze raw/*.json` | same from saved raw output, no SSH |
| `discover diff [--from N --to M]` | changes between scans (default: the last one) |
| `discover graph [--format json]` | current graph as Mermaid or JSON |
| `discover serve` | `GET /hosts`, `/graph`, `/diff?from_scan=&to_scan=`, `/scans`, `/` |

Docker: `docker build -t infra-discovery .` then
`docker run --rm --network idlab -v ./lab/id_ed25519:/k/key:ro -v id-data:/data infra-discovery scan web db cache app --key /k/key`
(the key must be readable by the container user; on SELinux hosts add `,z` to the mount).

## How this maps to BMC Discovery

| BMC Discovery / Helix | here |
|---|---|
| Discovery run over **scan ranges** | `discover scan` targets |
| **Credentials** (SSH key / vault) | `--key`, user per target `user@host:port` |
| Discovery scripts / commands on host | `collector.COMMANDS` (read-only) |
| **DDD** (Directly Discovered Data) | `RawScan` JSON (`--save-raw`) |
| **Patterns** written in **TPL** | `rules/*.rule` in the Lark DSL |
| Host, Software Instance, Process, Listening Port | `host`, `software`, `process`, `listener` nodes |
| Dependency / communication mapping | `connects_to` edges from established `ss` sockets |
| CMDB sync and change history | SQLite `nodes`/`edges` + `changes`, `discover diff` |

Not covered: Windows (WMI/PowerShell), SNMP devices, credential vault, privileged commands, a TPL
`triggers`/`pattern` hierarchy. See [docs/adr](docs/adr) for the design decisions.

## Development

`make test` (pytest + hypothesis, coverage gate 80%), `make lint` (ruff, mypy --strict),
`make lab-down` to remove the lab. CI runs lint, tests, the Docker build and a real lab scan.
