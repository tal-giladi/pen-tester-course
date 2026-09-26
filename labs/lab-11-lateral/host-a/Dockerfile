# host-a — the foothold. LAB ONLY. Authorizes the workstation's foothold key for `lab`,
# and carries a "deploy key" (found_key) that opens host-b as svc — the credential reuse.
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server openssh-client \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd
RUN useradd -m -s /bin/bash lab
COPY authorized_keys /home/lab/.ssh/authorized_keys
COPY found_key /home/lab/.ssh/id_ed25519
COPY notes.txt /home/lab/notes.txt
RUN chown -R lab:lab /home/lab/.ssh /home/lab/notes.txt && chmod 700 /home/lab/.ssh \
    && chmod 600 /home/lab/.ssh/authorized_keys /home/lab/.ssh/id_ed25519 \
    && printf 'Host *\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n' > /home/lab/.ssh/config \
    && chown lab:lab /home/lab/.ssh/config
EXPOSE 22
CMD ["/usr/sbin/sshd","-D","-e"]
