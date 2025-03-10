# **Medium - Use your server exploitation skills to take control of a web app.
https://tryhackme.com/room/billing

This challenge is an initial test to evaluate your capabilities in web pentesting, particularly for server-side attacks. Start the VM by clicking the `Start Machine` button at the top right of the task.

You will find all the necessary tools to complete the challenge, like Nmap, PHP shells, and many more on the AttackBox.  

_"Even if it's not accessible from the browser, can you still find a way to capture the flags and sneak into the secret admin panel?"_

# Reconnaissance
Target: 10.10.41.124

## Open services
```
sudo nmap -sV 10.10.41.124 
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-10 00:00 EDT
Nmap scan report for 10.10.41.124
Host is up (0.28s latency).
Not shown: 992 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
25/tcp    open  smtp     Postfix smtpd
110/tcp   open  pop3     Dovecot pop3d
143/tcp   open  imap     Dovecot imapd (Ubuntu)
993/tcp   open  ssl/imap Dovecot imapd (Ubuntu)
995/tcp   open  ssl/pop3 Dovecot pop3d
4000/tcp  open  http     Node.js (Express middleware)
50000/tcp open  http     Apache httpd 2.4.41 ((Ubuntu))
Service Info: Host:  mail.filepath.lab; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.21 seconds

```

# Findings 

- Mail server? 
- SSH
- http://10.10.41.124:4000/
- http://10.10.41.124:50000/

logging in with guest and guest, opening guest profile page looks like we get the values like isAdmin: false and a area to update settings like favorite book, can we use this call to update the admin?
http://10.10.41.124:4000/friend/1

# Exploiting

Testing finding with isAdmin on guest profile page
![[Pasted image 20250310144326.png]]

Looks like this works, refreshing page now gives a new API menu 
![[Pasted image 20250310144450.png]]




Answer the questions below

What is the flag value after logging in to the SysMon app?


What is the content of the hidden text file in /var/www/html?