
#ifndef PROTOVERSE_SERVE_H
#define PROTOVERSE_SERVE_H

/*typedef int (*handle_packet_fn)(void *closure,
				int sockfd,
				struct sockaddr_in *from,
				struct packet *packet);
				*/
#include "env.h"
#include "net.h"

struct protoverse_server;

typedef int (*packet_handler_fn)(struct protoverse_server *server, int sockfd,
			         struct sockaddr_in *from,
				 struct packet *packet);


struct protoverse_server {
	const char *bind;
	void *data;
	int port;
	struct env env;
	packet_handler_fn handle_packet;

	/*
	void *closure;
	handle_packet_fn handle_packet;*/
};

enum event_type {
	PROTO_EVENT_MESSAGE = 1,
};

struct protoverse_event {
	enum event_type type;
	union {
		struct message_packet msg;
	};
};

void protoverse_server_init(struct protoverse_server *server);
int protoverse_serve(struct protoverse_server *server);

#endif
