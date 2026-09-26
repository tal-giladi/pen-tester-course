# Attacker workstation for lab-12. Client tooling baked in; carries the lab throwaway key.
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client curl iproute2 netcat-openbsd proxychains4 nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY lab_ed25519 /root/.ssh/id_ed25519
RUN chmod 600 /root/.ssh/id_ed25519 && printf 'Host *\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n' > /root/.ssh/config
CMD ["sh","-c","echo 'attacker workstation up. foothold: ssh lab@dmz (key or Lab-Passw0rd!)'; sleep infinity"]
