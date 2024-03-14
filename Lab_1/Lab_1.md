# Lab 1: Buffer Overflows
- We will exploit the buffer overflow vulnerabilities in the context of a web server called `zookws`, which runs a simple python web application `zoobar`
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
- *Preparation*:
    - Get and compile the lab code
        ```
        $ git clone https://web.mit.edu/6858/2022/lab.git
        $ make
        ```
    - There are 2 versions of `zookd`
        - `zookd-exstack`: runs with an executable stack
        - `zookd-nxstack`: runs with a non-executable stack
    - To run the web server in a predictable fashion, i.e., each time the stack and memory layout is the same, use `clean-env.sh`
    - Run `$ ./clean-env.sh ./zookd 8080`, the `clean-env.sh` commands starts `zookd` on port 8080, then we can visit `http://<VM_IP>:8080/` in our browser

## Part 1: Finding buffer overflows
- Study the server's C code (`zookd.c` and `http.c`) to find one example of code that allows the attacker to overwrite the return address of a function
- `zookd.c`
    1. `main()`, `run_server`, and `start_server` basically create a socket listening to all network interfaces (`0.0.0.0`) and the port specified in the first argument. When a new connection request comes, `run_server` will create a child process, which will run `process_client(cltfd)`, where `cltfd` is the file descriptor of the client socket
    2. `process_client()`
        1. Declares a static buffer `env[8192]` (not on the stack)
        2. Declares a buffer `reqpath[4096]` on the stack
        3. Invokes `http_request_line(fd, reqpath, env, &env_len)`, it reads the first line of the request, like `GET /tmp HTTP/1.0`, and parses it
        4. Invokes `env_deserialize(env, sizeof(env))`
        5. Invokes `http_request_headers(fd)`, it reads the rest of the request and parse the HTTP headers
- `http.c`
    1. `int http_read_line(int fd, char *buf, size_t size)`
        - Reads the HTTTP request from the client FD byte by byte, until it sees the first `\n` or `\r`, i.e., it reads one line of the request
    2. `const char *http_request_line(int fd, char *reqpath, char *env, size_t *env_len)`
        - Invokes the previous `http_read_line()`, but converts the returned integer to error information if there is an error
        - Parses request like `GET /foo.html?a=1 HTTP/1.0` (only support `GET` and `POST`)
        - Finally stores the URL decoded request path (e.g., `/foo.html`) in `reqpath`, store some environment variables (e.g., `REQUEST_METHOD=GET\0SERVER_PROTOCOL=HTTP/1.0\0QUERY_STRING=a=1\0REQUEST_URI=/foo.html\0SERVER_NAME=zoobar.org`) in `env`
    2. `const char *http_request_headers(int fd)`
        - Parses the rest of the request, each line is like `XXX: ...`, e.g., `Cookie: foo bar`
        - Converts the header name (e.g., `Cookie`, `Content-Type`) to uppercase, replaces all hyphens with underscores, and add these header names to `envvar`, notice that all header names will be added a prefix `HTTP_` except `CONTENT_TYPE` and `CONTENT_LENGTH`
        - Uses `setenv` to set the header names and corresponding values (URL decoded) as environment variables
    3. `env_deserialize(const char *env, size_t len)`
        - Parses the content in `env`, which is like `REQUEST_METHOD=GET\0SERVER_PROTOCOL=HTTP/1.0\0QUERY_STRING=a=1\0REQUEST_URI=/foo.html\0SERVER_NAME=zoobar.org`, set them as environment variables
        - For example, by processing `REQUEST_METHOD=GET\0`, it invokes `setenv('REQUEST_METHOD', 'GET')`
    4. `url_decode(char *dst, char *src)`
        - URL decodes the content in `src` and store the result in `dst`

- *vulnerability*: a buffer overflow can happen when the request path (after URL decoded ) is longer than the length of `regpath` (4096 bytes), this is possible because the maximum length of each line can get to 8192 bytes (the size of `env`), and there isn't any size check when invoking `url_decode(reqpath, sq1)` inside `http_request_line(fd, reqpath, env, &env_len)`
    - the chain of function calls: `process_client()`, `http_request_line()`, `url_decode()`

- Now we can start developing exploits. The provided `~/lab/exploit-template.py` issues an HTTP request, it takes 2 arguments, the server name and port number, we can run it in this way: 
    ```
    $ ./clean-env.sh ./zookd-exstack 8080 & <-- starts the server in the backgroud
    $ ./exploit-template.py localhost 8080
    ```
- `gdb` is useful in building our exploits, we can attach it to an already-running process with `gdb -p $(pgrep zookd-)`. By default, `gdb` continues to debug parent process and does not attach to the child when the process forks. We can using the command `set follow-fork-mode child` to attach `gdb` to the child process, we can add it to `~/lab/.gdbinit`
