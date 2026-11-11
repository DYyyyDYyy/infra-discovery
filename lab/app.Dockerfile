# app: Alpine client that keeps connections open to db (PostgreSQL) and cache (Redis)
FROM alpine:3.22
RUN apk add --no-cache openssh redis postgresql-client iproute2 \
 && ssh-keygen -A \
 && echo 'root:*' | chpasswd -e \
 && mkdir -p /root/.ssh && chmod 700 /root/.ssh
COPY id_ed25519.pub /root/.ssh/authorized_keys
COPY app-entrypoint.sh /app-entrypoint.sh
RUN chmod 600 /root/.ssh/authorized_keys && chmod 755 /app-entrypoint.sh
CMD ["/app-entrypoint.sh"]
