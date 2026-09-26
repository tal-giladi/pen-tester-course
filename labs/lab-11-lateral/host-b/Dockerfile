# host-b — the lateral target. LAB ONLY. The svc account authorizes the "deploy key"
# that lives on host-a; reusing it moves you here. The build flag is in svc's home.
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd
RUN useradd -m -s /bin/bash svc
COPY authorized_keys /home/svc/.ssh/authorized_keys
RUN echo "LAB-FLAG-lateral-credential-reuse" > /home/svc/flag.txt \
    && chown -R svc:svc /home/svc/.ssh /home/svc/flag.txt \
    && chmod 700 /home/svc/.ssh && chmod 600 /home/svc/.ssh/authorized_keys && chmod 600 /home/svc/flag.txt
EXPOSE 22
CMD ["/usr/sbin/sshd","-D","-e"]
