
#ifndef PROTOVERSE_SERVE_H
#define PROTOVERSE_SERVE_H

/*typedef int (*handle_packet_fn)(void *closure,
				int sockfd,
				struct sockaddr_in *from,
				struct packet *packet);
				*/

struct protoverse_server {
	const char *bind;
	int port;

	/*
	void *closure;
	handle_packet_fn handle_packet;*/
};



int protoverse_serve(struct protoverse_server *server);

#endif
