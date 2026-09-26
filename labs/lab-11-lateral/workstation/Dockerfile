# Attacker workstation for lab-11. Holds the foothold key for host-a.
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY ws_key /root/.ssh/id_ed25519
RUN chmod 600 /root/.ssh/id_ed25519 && printf 'Host *\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n' > /root/.ssh/config
CMD ["sh","-c","echo 'attacker workstation up. foothold: ssh lab@host-a'; sleep infinity"]
