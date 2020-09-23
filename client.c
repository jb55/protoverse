
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "client.h"
#include "cursor.h"
#include "net.h"

int inet_aton(const char *cp, struct in_addr *inp);

int protoverse_connect(const char *server_ip_str, int port)
{
	static unsigned char buf[0xFFFF];

	int sockfd;
	struct in_addr server_in_addr;
	struct sockaddr_in server_addr;
	struct cursor cursor;
	struct packet packet;

	make_cursor(buf, buf + sizeof(buf), &cursor);

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		printf("socket creation failed: %s\n", strerror(errno));
		return 0;
	}

	if (inet_aton(server_ip_str, &server_in_addr) == 0) {
		printf("could not parse server ip: %s\n", strerror(errno));
		return 0;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = port == 0 || port == -1 ? 1988 : port;
	server_addr.sin_addr = server_in_addr;

	packet.type = PKT_CHAT;
	packet.data.chat.message = "hello, world";
	packet.data.chat.sender = 0xFFFFFF;

	send_packet(sockfd, &server_addr, &packet);
	recv_packet(sockfd, &cursor, &server_addr, &packet);
	print_packet(&packet);

	packet.type = PKT_FETCH_DATA;
	packet.data.fetch.path = "TAGS";

	send_packet(sockfd, &server_addr, &packet);
	recv_packet(sockfd, &cursor, &server_addr, &packet);

	print_packet(&packet);

	return 1;
}
