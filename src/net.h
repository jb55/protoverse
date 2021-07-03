
#ifndef PROTOVERSE_NET_H
#define PROTOVERSE_NET_H

#include <sys/socket.h>
#include <arpa/inet.h>

#include "cursor.h"
#include "env.h"

enum packet_type {
	PKT_FETCH_DATA,
	PKT_FETCH_DATA_RESPONSE,
	PKT_MESSAGE,
	PKT_NUM_TYPES,
};

enum message_type {
	MSG_CHAT,
	MSG_INTERACT,
};

struct fetch_packet {
	const char *path;
};

struct fetch_response_packet {
	const char *path;
	int data_len;
	unsigned char *data;
};

struct message_packet {
	int receiver;
	int type;
	const char *message;
};

union packet_data {
	struct fetch_packet fetch;
	struct fetch_response_packet fetch_response;
	struct message_packet message;
};

struct packet {
	enum packet_type type;
	union packet_data data;
};

int send_packet(int fd, struct sockaddr_in *to_addr, struct packet *packet);
int recv_packet(int sockfd, struct cursor *buf, struct sockaddr_in *from, struct packet *packet);

int push_packet(unsigned char *buf, int bufsize, struct packet *packet);
int pull_packet(struct cursor *c, struct cursor *buf, struct packet *packet, int received_bytes);

int packet_eq(struct packet *a, struct packet *b);
void print_packet(struct env *env, struct packet *packet);

#endif /* PROTOVERSE_NET_H */
