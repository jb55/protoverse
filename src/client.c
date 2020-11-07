
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
#include "describe.h"
#include "net.h"

int inet_aton(const char *cp, struct in_addr *inp);

static int handle_data_response(struct parser *parser, const char *expected_path,
				struct packet *packet)
{
	struct fetch_response_packet *resp = &packet->data.fetch_response;
	u16 root;
	int ok;

	if (packet->type == PKT_FETCH_DATA_RESPONSE &&
	    !strcmp(expected_path, resp->path))
	{
		ok = parse_buffer(parser, resp->data, resp->data_len, &root);
		if (!ok) {
			printf("could not parse space\n");
			return 0;
		}
		describe(parser, root);
	}

	return 1;
}

int protoverse_connect(const char *server_ip_str, int port)
{
	static unsigned char buf[0xFFFF];

	int sockfd;
	struct in_addr server_in_addr;
	struct sockaddr_in server_addr;
	struct cursor cursor;
	struct packet packet;
	const char *expected_path;
	struct parser parser;

	init_parser(&parser);
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

	expected_path = "index.space";
	packet.type = PKT_FETCH_DATA;
	packet.data.fetch.path = expected_path;

	send_packet(sockfd, &server_addr, &packet);
	recv_packet(sockfd, &cursor, &server_addr, &packet);

	handle_data_response(&parser, expected_path, &packet);

	free_parser(&parser);

	return 1;
}
