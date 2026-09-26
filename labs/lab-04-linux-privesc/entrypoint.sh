#!/bin/sh
# Start cron (so the cron-based vector is live) and sshd in the foreground.
set -e
service cron start 2>/dev/null || cron
echo "lab-04-linux-privesc up. Foothold: user 'lab' / 'Lab-Passw0rd!'."
echo "Objective: read /root/flag.txt as root. Multiple paths exist."
exec /usr/sbin/sshd -D -e
