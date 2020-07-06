
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "serve.h"

int inet_aton(const char *cp, struct in_addr *inp);

int protoverse_serve(const char *bind_addr_str, int port)
{
	int fd;
	struct in_addr my_addr;
	struct sockaddr_in bind_addr;
	struct sockaddr addr;
	socklen_t addrlen;
	ssize_t recv_len;
	static char buf[1024];
	int err;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		printf("socket creation failed: %s\n", strerror(errno));
		return 0;
	}

	if (inet_aton(bind_addr_str, &my_addr) == 0) {
		printf("inet_aton failed: %s\n", strerror(errno));
		return 0;
	}

	bind_addr.sin_family = AF_INET;
	bind_addr.sin_port = port == 0 || port == -1 ? 1988 : port;
	bind_addr.sin_addr = my_addr;

	err = bind(fd, (struct sockaddr*)&bind_addr,
		   sizeof(bind_addr)) == -1;

	if (err) {
		printf("bind failed: %s\n", strerror(errno));
		return 0;
	}

	while (1) {
		recv_len = recvfrom(fd, buf, sizeof(buf), 0, &addr,
				    &addrlen);

		printf("got '%.*s'\n", (int)recv_len, buf);
	}
}


