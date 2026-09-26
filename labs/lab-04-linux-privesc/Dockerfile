# lab-04-linux-privesc — an intentionally MISCONFIGURED Linux host for practicing
# local privilege escalation. LAB TARGET ONLY. Runs on an internal (no-egress) network.
#
# The box gives you a low-privilege shell as user `lab`. Several INDEPENDENT privesc
# paths are planted so you can find more than one (04.2 and 04.3 ask for different ones).
# The goal is to read /root/flag.txt (readable only by root), demonstrating root access.
#
# There is nothing real here: synthetic user, synthetic password, benign flag marker.
FROM debian:12-slim

# --- base tooling a realistic host would have (and that the vectors use) ------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        sudo cron python3 vim-tiny less findutils procps iproute2 libcap2-bin \
        openssh-server ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- accounts -----------------------------------------------------------------------
# Low-priv user you start as. Synthetic credentials.
RUN useradd -m -s /bin/bash lab && echo 'lab:Lab-Passw0rd!' | chpasswd

# The objective: a benign flag readable only by root.
RUN echo "LAB-FLAG-8f14e45f-ceea-467d-93a1-privesc-root" > /root/flag.txt \
    && chmod 600 /root/flag.txt && chown root:root /root/flag.txt

# ============================ PLANTED MISCONFIGURATIONS =============================
# Each is a distinct, classic vector. The lessons explain WHY each works.

# (1) SUID on find — a SUID binary that offers a shell/exec primitive runs it as root.
#     GTFOBins: find . -exec /bin/sh -p \; -quit   (the -p keeps the elevated euid)
RUN chmod u+s /usr/bin/find

# (2) sudo NOPASSWD on less — an interactive pager that can spawn a shell while it runs
#     as root:  sudo less /etc/hostname  then  !/bin/sh
RUN echo 'lab ALL=(root) NOPASSWD: /usr/bin/less' > /etc/sudoers.d/lab-less \
    && chmod 440 /etc/sudoers.d/lab-less

# (3) Writable cron script run by root every minute — inject a command as root.
RUN mkdir -p /opt/backup \
    && printf '#!/bin/sh\n# nightly backup (lab)\n/usr/bin/find /var/log -name "*.log" >/dev/null 2>&1\n' > /opt/backup/run.sh \
    && chmod 777 /opt/backup/run.sh \
    && echo '* * * * * root /opt/backup/run.sh' > /etc/cron.d/lab-backup \
    && chmod 644 /etc/cron.d/lab-backup

# (4) Linux capability cap_setuid on a *copy* of python (doesn't break system python).
#     /opt/pypriv -c 'import os;os.setuid(0);os.system("/bin/sh")'
RUN cp /usr/bin/python3 /opt/pypriv && setcap cap_setuid+ep /opt/pypriv

# (5) PATH-hijack: a root-owned SUID helper calls `id` by RELATIVE name; if the caller's
#     PATH has a writable dir first, they control what `id` resolves to. (04.3)
RUN printf '#include <unistd.h>\nint main(){setuid(0);setgid(0);system("id");return 0;}\n' > /tmp/helper.c \
    && apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && gcc -o /usr/local/bin/statuscheck /tmp/helper.c \
    && chmod u+s /usr/local/bin/statuscheck && rm /tmp/helper.c \
    && apt-get purge -y gcc libc6-dev && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
# NOTE: `system("id")` uses /bin/sh -c which honors PATH; the SUID+setuid(0) makes it root.

# --- sshd for a realistic foothold (ingress only; the network still has no egress) ---
RUN mkdir -p /run/sshd && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
