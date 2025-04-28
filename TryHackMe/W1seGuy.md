# W1seGuy

A w1se guy 0nce said, the answer is usually as plain as day.

## Findings

supplied script, does the following,

1) When you connect to the server, it generates a random key (5 characters long)
2) It XORs a fake flag with that key and sends you the XORed result in hex
3) Then it asks you to guess the encryption key
4) If you guess the correct key, it sends you the real flag (read from flag.txt)
5) If not, it says "Close but no cigar" and disconnects.

The following was used to help reverse engineer, by removing the server side and adding prints. 

```
import random  
import string  
  
flag = open('flag.txt','r').read().strip()  
  
def send_message(message):  
    print(message)  
  
def setup(key):  
    flag = 'THM{thisisafakeflag}'  
    xored = ""  
  
    for i in range(0, len(flag)):  
        xored += chr(ord(flag[i]) ^ ord(key[i % len(key)]))  
  
    hex_encoded = xored.encode().hex()  
    print("(debug) hex_encoded =", hex_encoded)  
    return hex_encoded  
  
def start():  
    res = ''.join(random.choices(string.ascii_letters + string.digits, k=5))  
    key = str(res)  
  
    hex_encoded = setup(key)  
    send_message("This XOR encoded text has flag 1: " + hex_encoded)  
    print("(debug) key =" + key)  
    key_answer = input("What is the encryption key? ").strip()  
    print("(debug) key =" + key_answer + ' ' + key)  
    try:  
        if key_answer == key:  
            send_message("Congrats! That is the correct key! Here is flag 2: " + flag)  
        else:  
            send_message('Close but no cigar')  
    except:  
        send_message("Something went wrong. Please try again. :)")  
  
if __name__ == '__main__':  
    start()
```

This gives us 

```
(debug) hex_encoded = 03390e3f393f18302d3e3617222f28311d222330
This XOR encoded text has flag 1: 03390e3f393f18302d3e3617222f28311d222330
(debug) key =WqCDM
What is the encryption key? WqCDM
(debug) key =WqCDM WqCDM
Congrats! That is the correct key! Here is flag 2: THM{thisisafakeflag}
```

## Exploiting

The key is 5 characters long, which normally would require `62^5 ≈ 916 million` combinations to brute-force.  
However, since we know the flag starts with `THM{`, we can XOR-decrypt and recover 4 key characters immediately.  
Only 1 character remains unknown, which can be brute-forced easily (only 256 possibilities).  
Because we know flags usually end with `}`, we can verify the correct final key almost instantly.

kindly asking ChatGPT to create this python and worked a charm,
```
import itertools  
import string  
import sys  
  
hex_encoded = '152b341118700215041c041b0d2b1c35571a010b000d0b59092d2f00023d3317005a1d331b361815'  
encrypted = bytes.fromhex(hex_encoded)  
  
known_plaintext = 'THM{'  
charset = string.ascii_letters + string.digits  
  
# Step 1: Recover first 4 key bytes  
recovered_key = []  
for i in range(4):  
    key_byte = encrypted[i] ^ ord(known_plaintext[i])  
    recovered_key.append(key_byte)  
  
# Step 2: Try all possibilities for 5th character  
for candidate in charset:  
    key = recovered_key + [ord(candidate)]  
    decrypted = ''  
    for i in range(len(encrypted)):  
        decrypted += chr(encrypted[i] ^ key[i % 5])  
  
    if decrypted.startswith('THM{') and decrypted.endswith('}'):  
        print("[+] Found key:", ''.join(chr(k) for k in key))  
        print("[+] Decrypted flag:", decrypted)  
        break
```

### Confirming working,
```
nc 10.10.177.85 1337
This XOR encoded text has flag 1: 152b341118700215041c041b0d2b1c35571a010b000d0b59092d2f00023d3317005a1d331b361815
What is the encryption key? Acyjh
Congrats! That is the correct key! Here is flag 2: THM{********************************}
```