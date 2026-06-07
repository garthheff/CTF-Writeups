# 0x41haz

Simple Reversing Challenge

In this challenge, you are asked to solve a simple reversing solution. Download and analyze the binary to discover the password.

There may be anti-reversing measures in place!

Room: https://tryhackme.com/room/0x41haz

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/0x41haz.md

-------------------

## Overview

This challenge looked confusing at first because the binary did not appear to be a normal executable. Running `file` showed an unusual architecture and endian result instead of a clean x86-64 ELF.

The main trick was that the ELF header had been tampered with. Once the header was repaired, the binary could run normally. From there, the password could be recovered either by reading the disassembly or by using GDB to inspect the stack.

This writeup includes both methods because this challenge is less obvious than many beginner reverse engineering crackmes.

## Initial File Check

I started by checking the file type.

```bash
file 0x41haz-1640335532346.0x41haz
```

Output:

```text
0x41haz-1640335532346.0x41haz: ELF 64-bit MSB unknown arch 0x3e00 SYSV
```

This output is suspicious.

For a normal Linux x86-64 ELF, I would expect something closer to:

```text
ELF 64-bit LSB executable, x86-64
```

Instead, the file was reported as:

```text
ELF 64-bit MSB unknown arch 0x3e00
```

The important clues were:

```text
MSB
unknown arch 0x3e00
```

`MSB` means big endian.

However, x86-64 Linux binaries are normally little endian. The architecture value for x86-64 is `0x003e`. Because the file was being interpreted as big endian, it appeared backwards as `0x3e00`.

That suggested the ELF endian byte had been changed.

## Inspecting the ELF Header

I inspected the first 32 bytes of the file.

```bash
xxd -g1 -l 32 0x41haz-1640335532346.0x41haz
```

Output:

```text
00000000: 7f 45 4c 46 02 02 01 00 00 00 00 00 00 00 00 00  .ELF............
00000010: 03 00 3e 00 01 00 00 00 80 10 00 00 00 00 00 00  ..>.............
```

The ELF magic bytes are:

```text
7f 45 4c 46
```

That spells:

```text
.ELF
```

The next bytes describe the ELF format.

```text
02 02 01
```

Breaking that down:

```text
02 = 64-bit ELF
02 = big endian
01 = ELF version
```

The second `02` was the problem. For a normal x86-64 Linux ELF, that byte should be:

```text
01 = little endian
```

So the binary was most likely a normal x86-64 ELF with the endian byte changed from `01` to `02`.

## Fixing the ELF Header

The endian byte is at offset `0x05`.

I copied the file and patched that single byte.

```bash
cp 0x41haz-1640335532346.0x41haz fixed
printf '\x01' | dd of=fixed bs=1 seek=5 count=1 conv=notrunc
file fixed
```

Output:

```text
1+0 records in
1+0 records out
1 byte copied
fixed: ELF 64-bit LSB pie executable, x86-64, version 1 SYSV, dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

Now the file was detected correctly as:

```text
ELF 64-bit LSB pie executable, x86-64
```

This confirmed that only the endian byte needed to be repaired.

## Running the Fixed Binary

After making the file executable, I ran it.

```bash
chmod +x fixed
./fixed
```

Output:

```text
=======================
Hey , Can You Crackme ?
=======================
It's jus a simple binary 

Tell Me the Password :
```

The binary asked for a password.

## First Dynamic Check With ltrace

I used `ltrace` to see if the program called common string comparison functions such as `strcmp`, `strncmp`, or `memcmp`.

```bash
ltrace ./fixed
```

I entered a test password.

```text
aaaa
```

Output:

```text
puts("=======================\nHey , Ca"...)
puts("It's jus a simple binary \n")
puts("Tell Me the Password :")
gets(...)
strlen("aaaa") = 4
puts("Is it correct , I don't think so"...)
exit(0)
```

This showed a few useful things:

1. The program uses `gets` to read input.
2. The program checks the input length using `strlen`.
3. There was no visible call to `strcmp`, `strncmp`, or `memcmp`.

That means the password comparison is probably done manually in the program code.

## Method 1: Solving From objdump

I disassembled the binary.

```bash
objdump -d -M intel fixed > disasm.txt
```

Then I searched for `strlen`, because the password logic should be close to the length check.

```bash
grep -n "strlen" disasm.txt
```

Output:

```text
28:0000000000001040 <strlen@plt>:
129:    11c4: e8 77 fe ff ff        call   1040 <strlen@plt>
```

The call to `strlen` happened around address `0x11c4`.

I inspected the surrounding disassembly.

```bash
sed -n '105,160p' disasm.txt
```

Important section:

```asm
1165: push   rbp
1166: mov    rbp,rsp
1169: sub    rsp,0x40

116d: movabs rax,0x6667243532404032
1177: mov    QWORD PTR [rbp-0x16],rax
117b: mov    DWORD PTR [rbp-0xe],0x40265473
1182: mov    WORD PTR [rbp-0xa],0x4c

11ac: lea    rax,[rbp-0x40]
11b0: mov    rdi,rax
11b8: call   1050 <gets@plt>

11bd: lea    rax,[rbp-0x40]
11c1: mov    rdi,rax
11c4: call   1040 <strlen@plt>
11c9: mov    DWORD PTR [rbp-0x8],eax
11cc: cmp    DWORD PTR [rbp-0x8],0xd
11d0: je     11e8
```

The important part is the length check:

```asm
cmp DWORD PTR [rbp-0x8],0xd
```

`0xd` in decimal is `13`.

So the password must be 13 characters long.

Before the input is read, the program stores values on the stack:

```asm
movabs rax,0x6667243532404032
mov    QWORD PTR [rbp-0x16],rax
mov    DWORD PTR [rbp-0xe],0x40265473
mov    WORD PTR [rbp-0xa],0x4c
```

These bytes form the correct password.

Because the system is little endian, the values are stored in reverse byte order.

### Decoding the First Value

The first value is:

```text
0x6667243532404032
```

Stored little endian, that becomes:

```text
32 40 40 32 35 24 67 66
```

ASCII:

```text
2 @ xxxx g f
```

### Decoding the Second Value

The second value is:

```text
0x40265473
```

Stored little endian, that becomes:

```text
73 54 26 40
```

ASCII:

```text
s T & @
```

### Decoding the Final Value

The final value is:

```text
0x4c
```

ASCII:

```text
L
```

Putting the parts together gives the full password:

```text
2@@xxxsT&@L
```

### Understanding the Compare Loop

The compare loop confirms this.

```asm
11f1: mov    eax,DWORD PTR [rbp-0x4]
11f6: movzx  edx,BYTE PTR [rbp+rax*1-0x16]
1200: movzx  eax,BYTE PTR [rbp+rax*1-0x40]
1205: cmp    dl,al
1207: jne    120f
1209: add    DWORD PTR [rbp-0x4],0x1
1225: cmp    eax,DWORD PTR [rbp-0x8]
122b: jl     11f1
```

This compares:

```text
stored correct password at rbp-0x16
```

against:

```text
user input at rbp-0x40
```

one byte at a time.

If any character is wrong, the program prints:

```text
Nope
```

If all 13 characters match, it prints:

```text
Well Done !!
```

## Method 2: Solving With GDB

The same password can be recovered in GDB by letting the program write the password to the stack, then inspecting that memory.

This is useful because it avoids manually decoding all the little endian values.

Start GDB:

```bash
gdb ./fixed
```

Set Intel syntax:

```gdb
set disassembly-flavor intel
```

Because the binary is PIE, the addresses from `objdump` are not the final runtime addresses.

From `objdump`, the function started at:

```text
0x1165
```

The password setup finished at:

```text
0x1188
```

However, since this is a PIE binary, Linux loads it at a runtime base address.

To find the base address, start the program at the first instruction:

```gdb
starti
```

Then check the memory mappings:

```gdb
info proc mappings
```

Relevant output:

```text
Start Addr           End Addr       Size     Offset  Perms  objfile
0x555555554000     0x555555555000   0x1000   0x0     r--p   /home/pingu/Downloads/fixed
0x555555555000     0x555555556000   0x1000   0x1000  r-xp   /home/pingu/Downloads/fixed
```

The base address is:

```text
0x555555554000
```

Now add the `objdump` offsets to the base address.

Function start:

```text
0x555555554000 + 0x1165 = 0x555555555165
```

Password setup finished:

```text
0x555555554000 + 0x1188 = 0x555555555188
```

Set a breakpoint at the function start:

```gdb
break *0x555555555165
continue
```

Once it breaks, set another breakpoint after the password setup instructions:

```gdb
break *0x555555555188
continue
```

At this point, the program has already executed these instructions:

```asm
movabs rax,0x6667243532404032
mov    QWORD PTR [rbp-0x16],rax
mov    DWORD PTR [rbp-0xe],0x40265473
mov    WORD PTR [rbp-0xa],0x4c
```

Those are not GDB commands. They are assembly instructions from the program.

Now inspect the stack location where the password was stored:

```gdb
x/s $rbp-0x16
```

Output:

```text
0x7fffffffdcaa: "2@@xxxxxT&@L"
```

This directly reveals the password.

To continue execution:

```gdb
continue
```

When prompted, enter the recovered password.

```text
2@@xxxxT&@L
```

Output:

```text
Well Done !!
```

## Why the First GDB Breakpoint Looked Empty

When I first broke at the function start and ran:

```gdb
x/s $rbp-0x16
```

the result was empty.

That happened because the breakpoint was too early.

At the function start, the stack frame had only just been created. The password had not been written yet.

The password only exists after these instructions execute:

```asm
movabs rax,0x6667243532404032
mov    QWORD PTR [rbp-0x16],rax
mov    DWORD PTR [rbp-0xe],0x40265473
mov    WORD PTR [rbp-0xa],0x4c
```

That is why the useful breakpoint was:

```text
base + 0x1188
```

not just:

```text
base + 0x1165
```

## Final Verification

Running the fixed binary with the recovered password:

```bash
./fixed
```

Input:

```text
2@xxxxx&@L
```

Output:

```text
=======================
Hey , Can You Crackme ?
=======================
It's jus a simple binary 

Tell Me the Password :
2@@xxxxx@L
Well Done !!
```

## Summary

This challenge had two main parts.

First, the ELF header was intentionally broken. The binary was marked as big endian even though it was really a little endian x86-64 binary. Patching byte offset `0x05` from `02` to `01` fixed the executable.

Second, the crackme stored the correct password directly on the stack before reading user input. The password was then compared one character at a time against the input buffer.

The password could be recovered either by:

1. Reading and decoding the stack writes in `objdump`.
2. Using GDB to break after the stack writes and dumping the string at `$rbp-0x16`.

Recovered password:

```text
2@xxxxxx&@L
```
