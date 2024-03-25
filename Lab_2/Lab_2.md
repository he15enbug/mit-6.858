# Lab 2: Privilege Separation and Server-side Sandboxing
- This lab will introduce us to privilege separation and server-side sandboxing, in the context of a simple Python web application called `zoobar`, where users transfer "zoobars" (credits) between each other. The main goal of privilege separation is to ensure that if an adversary compromises one part of an application, the adversary doesn't compromise the other parts too
- We will set up a privilege-separated web server, examine possible vulnerabilities, and break up the application code into less-privileged components to minimize the effects of any single vulnerability. The lab will use modern support for privilege separation: [Linux containers](https://linuxcontainers.org/)
- We will also extend the `zoobar` web application to support *executable profiles*, which allow users to use Python code as their profiles. To make a profile, a user saves a Python program in their profile on their home page. (To indicate that the profile contains Python code, the first line must be `#!python`). Whenever another user views the user's Python profile, the server will execute the Python code in that user's profile to generate the resulting profile output
- Supporting this safely requires sandboxing the profile code on the server, so that it cannot perform arbitrary operations or access arbitrary files. On the other hand, this code may need to keep track of persistent data in some files, or to access existing zoobar databases, to function properly. We will use the remote procedure call library and some shim code that are provided to securely sandbox executable profiles.
- Setup
    ```
    $ git checkout -b lab2 origin/lab2
    Branch lab2 set up to track remote branch lab2 from origin.
    Switched to a new branch 'lab2'
    $ make
    cc -m64 -g -std=c99 -Wall -Wno-format-overflow -D_GNU_SOURCE -static   -c -o zookfs.o zookfs.c
    cc -m64 -g -std=c99 -Wall -Wno-format-overflow -D_GNU_SOURCE -static   -c -o http2.o http2.c
    cc -m64  zookfs.o http2.o   -o zookfs
    cc -m64 -g -std=c99 -Wall -Wno-format-overflow -D_GNU_SOURCE -static   -c -o zookd2.o zookd2.c
    cc -m64  zookd2.o http2.o   -o zookd2
    ```
## Prelude: What's a zoobar
## Privilege separation
### Part 1: Privilege-separate the web server setup using containers
### Interlude: RPC library
### Part 2: Privilege-separating the login service in Zoobar
### Part 3: Privilege-separating the bank in Zoobar
### Part 4: Server-side sandboxing for executable profiles