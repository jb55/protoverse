
#ifndef PROTOVERSE_SERVE_H
#define PROTOVERSE_SERVE_H

struct protoverse_server {
	const char *bind;
	int port;

	const char *path;
};



int protoverse_serve(struct protoverse_server *server);

#endif
