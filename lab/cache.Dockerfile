# cache: Alpine + Redis + sshd
FROM alpine:3.22
RUN apk add --no-cache openssh redis iproute2 \
 && ssh-keygen -A \
 && echo 'root:*' | chpasswd -e \
 && mkdir -p /root/.ssh && chmod 700 /root/.ssh
COPY id_ed25519.pub /root/.ssh/authorized_keys
RUN chmod 600 /root/.ssh/authorized_keys
CMD ["sh", "-c", "redis-server --bind 0.0.0.0 --protected-mode no --daemonize yes && exec /usr/sbin/sshd -D -e"]
