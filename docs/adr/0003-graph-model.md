# 3. Graph model with stable keys and soft deletes

**Status:** accepted

**Context.** Repeated scans must not create duplicates, and the CMDB must answer "what changed and when".

**Decision.** Nodes have deterministic keys (`host:web`, `software:web/nginx`, `listener:web/tcp/80`);
volatile data (pids, ephemeral ports) is kept out of keys and attributes. Each scan is reconciled
against stored state only for the hosts it reached: new keys are `added`, different attributes
`changed`, missing ones `removed` (soft delete, `removed=1`). Every change goes to a `changes` table
tied to a scan (time, actor). SQLite with JSON attributes; edges are `(src, kind, dst)`.

**Consequences.** A rescan of an unchanged estate records nothing (checked in CI). Unreachable hosts
keep their last known state. Scaling out would mean PostgreSQL with the same tables, a queue of scan
jobs per range, and incremental reconciliation per host instead of per scan.
