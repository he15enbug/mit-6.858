# Lab 1: Buffer Overflows
- we will exploit the buffer overflow vulnerabilities in the context of a web server called `zookws`, which runs a simple python web application `zoobar`
- *Lab infrastructure*:
    - for convenience, use the provided Ubuntu 21.10 Linux virtual machine
    - username: `student`, password: `6858`
    - `ssh -p 2222 student@<IP_ADDRESS>`
    - I used VSCode to ssh login to the VM, we need the following configuration in `~/.ssh/config`
        ```
        Host 858vm
            User student
            HostName <IP_ADDRESS>
            Port 2222
            IdentityFile ~/.ssh/858ssh
        ```
