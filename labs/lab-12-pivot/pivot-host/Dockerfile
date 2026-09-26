# A generic SSH pivot host for lab-12. LAB ONLY. Runs sshd; the lab throwaway public key
# is authorized for user `lab`. Multi-homed hosts become the routes between segments.
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server curl iproute2 netcat-openbsd ca-certificates \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd
RUN useradd -m -s /bin/bash lab && echo 'lab:Lab-Passw0rd!' | chpasswd
COPY authorized_keys /home/lab/.ssh/authorized_keys
RUN chown -R lab:lab /home/lab/.ssh && chmod 700 /home/lab/.ssh && chmod 600 /home/lab/.ssh/authorized_keys
# Allow the tunnels/forwards this lab teaches; password auth on too (students use either).
RUN sed -i 's/^#\?AllowTcpForwarding.*/AllowTcpForwarding yes/; s/^#\?GatewayPorts.*/GatewayPorts yes/; s/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
