#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
void printhex(const char *bin, size_t len)
{
    for (size_t i =0; i != len; ++i)
        printf("%02x", bin[i]);
}
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

	if (bind(sockfd, (struct sockaddr *)&server, sizeof(server)) == -1)
	{
		perror("[bind error]");
		return -1;
	}
	listen(sockfd, 5);

	char buf[48763];
	while (1)
	{
		struct sockaddr_in src_addr;
		socklen_t addr_len = sizeof(src_addr);
		int msgsock = accept(sockfd, (struct sockaddr *)&src_addr, &addr_len);
		if (msgsock == -1)
		{
			perror("[accept error]");
			return -1;
		}
		if (recv(msgsock, buf, 1024, 0) == -1)
		{
			perror("[recv error]");
			return -1;
		}
		printf("server recv from %s:[%s]\n", inet_ntoa(src_addr.sin_addr), buf);
		close(msgsock);
	}
}