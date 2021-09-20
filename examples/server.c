
#include "serve.h"

static int handle_packet(struct protoverse_server *server, int sockfd,
			 struct sockaddr_in *from,
			 struct packet *packet)
{
	(void)sockfd;
	(void)from;

	print_packet(&server->env, packet);
	return 1;
}

int main(int argc, const char *argv[]) 
{
	struct protoverse_server server;

	(void)argc;
	(void)argv;

	protoverse_server_init(&server);

	server.port = 1988;
	server.bind = "127.0.0.1";
	server.handle_packet = handle_packet;

	protoverse_serve(&server);

	return 1;
}
