
#ifndef PROTOVERSE_NET_H
#define PROTOVERSE_NET_H

#include <sys/socket.h>
#include <arpa/inet.h>
#include "cursor.h"

enum packet_type {
	PKT_FETCH_DATA,
	PKT_FETCH_DATA_RESPONSE,
	PKT_CHAT,
	PKT_NUM_TYPES,
};

struct fetch_packet {
	const char *path;
};

struct fetch_response_packet {
	const char *path;
	int data_len;
	const unsigned char *data;
};

struct chat_packet {
	int sender;
	const char *message;
};

union packet_data {
	struct fetch_packet fetch;
	struct fetch_response_packet fetch_response;
	struct chat_packet chat;
};

struct packet {
	enum packet_type type;
	union packet_data data;
};

int send_packet(int fd, struct sockaddr_in *to_addr, struct packet *packet);
int recv_packet(int sockfd, struct cursor *buf, struct sockaddr_in *from, struct packet *packet);

int push_packet(unsigned char *buf, int bufsize, struct packet *packet);
int pull_packet(struct cursor *c, struct cursor *buf, struct packet *packet);

int packet_eq(struct packet *a, struct packet *b);
void print_packet(struct packet *packet);

#endif /* PROTOVERSE_NET_H */
