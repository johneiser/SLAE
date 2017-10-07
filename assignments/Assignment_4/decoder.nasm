; decoder.nasm
;  - Decode shellcode, then pass over execution

global _start

section .text
_start:

	jmp short call_decoder

decoder:
	pop esi			; Shellcode location
	xor ecx, ecx		; Length of shellcode
	mov cl, 7		; ...
	mov edi, esi		; Decode location
	add edi, ecx		; ...
	add edi, ecx		; ...
	dec edi			; ...

decode:
	xor ebx, ebx		; Clear carry register
	mov bl, byte [esi]	; Decode
	xor bl, 0xAA		; ...
	mov byte [edi], bl	; Move
	mov byte [esi], 0x90	; Replace with nop
	inc esi			; Loop
	dec edi			; ...
	loop decode		; ...
	jmp short Shellcode	; Pass over execution


call_decoder:
	call decoder
	Shellcode: db 0x2a, 0x67, 0xea, 0x69, 0x23, 0x6a, 0x9b
