#!/bin/sh
# Long-lived client connections, reconnecting if the server is not up yet.
(while true; do redis-cli -h cache subscribe events >/dev/null 2>&1; sleep 2; done) &
(while true; do psql -h db -U postgres -c 'select pg_sleep(1000000)' >/dev/null 2>&1; sleep 2; done) &
exec /usr/sbin/sshd -D -e
