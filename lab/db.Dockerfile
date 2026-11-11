# db: Rocky Linux + PostgreSQL + sshd
FROM rockylinux/rockylinux:9
RUN dnf install -y openssh-server postgresql-server procps-ng iproute \
 && dnf clean all \
 && ssh-keygen -A \
 && mkdir -p /root/.ssh && chmod 700 /root/.ssh \
 && runuser -u postgres -- initdb -D /var/lib/pgsql/data \
 && echo "listen_addresses = '*'" >> /var/lib/pgsql/data/postgresql.conf \
 && echo "host all all 0.0.0.0/0 trust" >> /var/lib/pgsql/data/pg_hba.conf
COPY id_ed25519.pub /root/.ssh/authorized_keys
RUN chmod 600 /root/.ssh/authorized_keys
CMD ["sh", "-c", "install -d -o postgres -g postgres /run/postgresql && runuser -u postgres -- pg_ctl -D /var/lib/pgsql/data -l /tmp/pg.log start && exec /usr/sbin/sshd -D -e"]
