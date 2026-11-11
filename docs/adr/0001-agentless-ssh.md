# 1. Agentless collection over SSH

**Status:** accepted

**Context.** Discovery has to work on hosts we do not own the build of, without installing anything.

**Decision.** Connect with SSH (asyncssh) using an explicit key and run a fixed list of read-only
commands. Raw output is stored as-is (DDD) and all interpretation happens later, centrally.
`~/.ssh` config and agents are never used; host keys are not checked in the lab (rebuilt every time).

**Consequences.** Zero footprint on targets, rules can be re-run on old raw data, and tests use real
captured output. The view is limited by the account's rights: in containers without `CAP_SYS_PTRACE`,
`ss -p` cannot see sockets of other users' processes (PostgreSQL), so rules declare well-known
`ports` as a fallback. Production use needs host-key checking and a credential store.
