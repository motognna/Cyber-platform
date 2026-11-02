#!/bin/sh
# Porneste serviciile laboratorului: rsyslog -> nginx -> sshd (foreground)
set -e

# rsyslog ruleaza ca utilizatorul 'syslog' (Ubuntu): fisierul trebuie sa ii apartina,
# altfel scrierea esueaza cu "Permission denied" si auth.log ramane gol.
touch /var/log/auth.log
chown syslog:adm /var/log/auth.log
chmod 640 /var/log/auth.log

rsyslogd
nginx
# NU folosi 'sshd -e': ar trimite log-urile la stderr in loc de syslog (auth.log ar ramane gol).
exec /usr/sbin/sshd -D
