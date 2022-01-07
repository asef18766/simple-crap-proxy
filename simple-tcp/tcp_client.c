#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
int main(int argc, char const *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s (server ip) (server port)\n", argv[0]);
        return -1;
    }

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1)
	{
		perror("[socket error]");
		return -1;
	}
	struct sockaddr_in server;
	memset(&server, 0, sizeof(server));

    server.sin_family = PF_INET;
    server.sin_addr.s_addr = inet_addr(argv[1]);
    server.sin_port = htons(atoi(argv[2]));

	if (connect(sockfd, (struct sockaddr *)&server, sizeof(server)) == -1)
	{
		perror("[connect failed]");
        return -1;
	}

	char msg[] = "hello from client";
	if (write(sockfd, msg, sizeof(msg)) < 0)
		perror("[client write error]");
	close(sockfd);
	return 0;
}