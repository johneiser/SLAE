---
title:  Assignment 4
description: Create a Custom Encoder
order: 4
---

[&lt;&lt; Go Back]({{ site.baseurl }})


# {{ page.title }}
### {{ page.description }}
___
<div style="text-align:right;direction:ltr;margin-left:1em;"><h6>{{ page.date }}</h6></div>

For this challenge we will be creating a custom shellcode encoder, specifically what I am calling a 'Flip-XOR' encoder.  This encoder will reverse the order of the shellcode, XOR each byte with a key, then prepend a decoder stub.  Let's get started!

The first challenge is decoding such a shellcode.  The following assembly file shows how we could accomplish this:

```nasm
; decoder.nasm
;  - Decode shellcode, then pass over execution

global _start

section .text
_start:

        jmp short call_decoder

decoder:
        pop esi                 ; Shellcode location
        xor ecx, ecx            ; Length of shellcode
        mov cl, 7               ; ...
        mov edi, esi            ; Decode location
        add edi, ecx            ; ...
        add edi, ecx            ; ...
        dec edi                 ; ...

decode:
        xor ebx, ebx            ; Clear carry register
        mov bl, byte [esi]      ; Decode
        xor bl, 0xAA            ; ...
        mov byte [edi], bl      ; Move
        mov byte [esi], 0x90    ; Replace with nop
        inc esi                 ; Loop
        dec edi                 ; ...
        loop decode             ; ...
        jmp short Shellcode     ; Pass over execution


call_decoder:
        call decoder
        Shellcode: db 0x2a, 0x67, 0xea, 0x69, 0x23, 0x6a, 0x9b
```

As you can see, we start with a *jmp call pop* method of retrieving the address of our shellcode, then we set up our decode function with that address and the length of the shellcode.  In addition to storing the shellcode address, we also store an address to the *end* of a duplicate range *after* the shellcode, where we'll store our decoded shellcode.

The decode function takes the byte at *esi*, XORs it with the key (0xAA), moves the result to *edi*, then replaces *esi* with a NOP (0x90).  The function then loops after incrementing *esi* and decrementing *edi*.  In graphical form, we transformed this...

```
                 ESI                                           EDI
|--decoder-stub--|---encoded-shellcode---|-----------?-----------|
EIP
```
... into this ...
```
                                      ESI EDI
|--decoder-stub--|-------nop-sled--------|---decoded-shellcode---|
                 EIP
```

<br>
{% include preamble.md %}

[&lt;&lt; Go Back]({{ site.baseurl }})
