# Lab 4: Browser Secuirty
## Introduction
- This lab will introduce us to browser-based attacks, as well as to how one might go about preventing them. The lab has several parts:
    - Part 1: cross-site scripting attack
    - Part 2: side channel and phishing attack
    - Part 3: a profile worm
## Network setup
- The Zoobar website will be running on `http://localhost:8080/`
- For VMware, use `ssh`'s port forwarding feature to expose our VM's port 8080 as `http://localhost:8080`
    1. Find the VM IP address: `192.168.200.129`
    2. Configure SSH port forwarding (on host machine): (the forward will remain in effect as long as the SSH connection is open)
        ```
        $ ssh -L localhost:8080:localhost:8080 student@192.168.200.129
        student@192.168.200.129's password:
        Last login: Mon Mar 25 03:25:28 2024
        student@6858-v22:~$
        ```
## Web browser
- Use [Mozilla Firefox](https://www.mozilla.com/firefox/) for developing our attacks. There are subtle (and not-so-subtle) differences in the way HTML, JavaScript, and cookies are handled by different browsers
## Setting up the web server
- Run the server
    ```
    $ git checkout -b lab4 origin/lab4
    Branch 'lab4' set up to track remote branch 'lab4' from 'origin'.
    Switched to a new branch 'lab4'
    $ make
    cc -m64 -g -std=c99 -Wall -Wno-format-overflow -D_GNU_SOURCE -static   -c -o zookd.o zookd.c
    cc -m64 -g -std=c99 -Wall -Wno-format-overflow -D_GNU_SOURCE -static   -c -o http.o http.c
    cc -m64  zookd.o http.o   -o zookd
    $ ./zookd 8080
    ```
- Test: open the browser and go to the URL `http://localhost:8080/`, we should see the `zoobar` web application
## Crafting attacks
- No action needed
## Part 1: A cross-site scripting (XSS) attack
- The zoobar users page has a flaw that allows theft of a logged-in user's cookie from the user's browser, if an attacker can trick the user into clicking a special-crafted URL constructed by the attacker. Our job is to construct such a URL
- *Exercise 1*: Print cookie
- *Exercise 2*: Log the cookie
- *Exercise 3*: Remote execution
- *Exercise 4*: Steal cookies
- *Exercise 5*: Hiding our tracks
## Part 2: Fake login page
## Part 3: Profile worm
