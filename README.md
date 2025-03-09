# **Easy - Some mistakes can be costly.**
https://tryhackme.com/room/billing

<details>
  <summary><strong>Reconnaissance</strong></summary>

  - **Nmap** to find services  
  - **Gobuster** to enumerate website root directory and `/mbilling`  

</details>

<details>
  <summary><strong>Reconnaissance example commands</strong></summary>
  
  - sudo nmap -sV 10.10.228.140 
  - gobuster dir -u http://10.10.228.140/mbilling -w /usr/share/wordlists/dirb/common.txt -t 50
  - gobuster dir -u http://10.10.228.140/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,html, md
  - gobuster dir -u http://10.10.228.140/mbilling -w /usr/share/wordlists/dirb/common.txt -x php,txt,html, md   
</details>


<details>
  <summary><strong>Hint for Initial Exploitation</strong></summary>

  - find CVE for framework / CVE in http://*.*.*.*/mbilling/README.md
  - find metasploit for this CVE
</details>


<details>
  <summary><strong>Hint for Locating Privilege Escalation</strong></summary>

  - Once you have a shell, check if you can run any commands as **sudo** without a password.  
  - There is a command that lists available **sudo** privileges for your user.  
  - Pay attention to commands that allow running binaries as root without requiring a password.  

</details>

<details>
  <summary><strong>Hint for Executing Privilege Escalation</strong></summary>

  - Modify an **automated security rule** so that it executes a command when an IP is banned.  
  - There is a **command that lets you set an action** when a rule triggers.  
  - Use this to execute a **reverse shell** or copy the root flag to an accessible location.  
  - Before executing, **test your reverse shell manually/command** in the current shell to ensure it works.  
  - Once set, manually **ban an IP** to trigger your command.  
  - Need ideas? Some system security tools allow modifying their **iptables rules** to run commands.  

</details>
