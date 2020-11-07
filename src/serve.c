
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>

#include "serve.h"
#include "net.h"
#include "io.h"

#define MAX_CACHED_FILES 12

int inet_aton(const char *cp, struct in_addr *inp);

struct file_cache {
	const char *path;
	int data_len;
	unsigned char *dat;
};

static int load_data(struct cursor *buf, const char *path,
		     int *data_len, unsigned char **data)
{
	int ok;

	ok = read_file(path, buf->p, buf->end - buf->p, data_len);
	if (!ok) return 0;

	assert(*data_len <= buf->end - buf->p);

	*data = buf->p;

	buf->p += *data_len;

	return 1;
}

static int make_fetch_response(struct cursor *buf,
			       struct packet *response,
			       const char *path)
{
	int data_len, ok;
	data_len = 0;

	ok = load_data(buf, path, &data_len,
		       &response->data.fetch_response.data);

	/* printf("load_data %d ok %d\n", data_len, ok); */

	if (!ok) return 0;

	response->type = PKT_FETCH_DATA_RESPONSE;
	response->data.fetch_response.path = path;
	response->data.fetch_response.data_len = data_len;

	return 1;
}

static int handle_packet(int sockfd,
			 struct cursor *buf,
			 struct sockaddr_in *from,
			 struct packet *packet)
{
	struct packet response;
	int ok;

	print_packet(packet);
	switch (packet->type) {
	case PKT_CHAT:
		return send_packet(sockfd, from, packet);
	case PKT_FETCH_DATA:
		ok = make_fetch_response(buf, &response,
					 packet->data.fetch.path);
		if (!ok) return 0;
		return send_packet(sockfd, from, &response);
	case PKT_FETCH_DATA_RESPONSE:
		printf("todo: handle fetch response\n");
		return 0;
	case PKT_NUM_TYPES:
		return 0;
	}

	return 0;
}

int protoverse_serve(struct protoverse_server *server)
{
        #define FILEBUF_SIZE 31457280
	static unsigned char *buf_;

	struct in_addr my_addr;
	struct sockaddr_in bind_addr;
	struct sockaddr_in from;
	struct packet packet;
	struct cursor buf;
	/* socklen_t from_addr_len; */

	int err, ok, fd;

	buf_ = malloc(FILEBUF_SIZE);
	make_cursor(buf_, buf_ + FILEBUF_SIZE, &buf);

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		printf("socket creation failed: %s\n", strerror(errno));
		return 0;
	}

	if (inet_aton(server->bind, &my_addr) == 0) {
		printf("inet_aton failed: %s\n", strerror(errno));
		return 0;
	}

	bind_addr.sin_family = AF_INET;
	bind_addr.sin_port = server->port == 0 || server->port == -1 ? 1988 : server->port;
	bind_addr.sin_addr = my_addr;

	err = bind(fd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) == -1;

	if (err) {
		printf("bind failed: %s\n", strerror(errno));
		return 0;
	}

	while (1) {
		ok = recv_packet(fd, &buf, &from, &packet);
		if (!ok) {
			printf("malformed packet\n");
			continue;
		}

		ok = handle_packet(fd, &buf, &from, &packet);
		if (!ok) {
			printf("handle packet failed for ");
			print_packet(&packet);
		}

		buf.p = buf.start;
	}

	free(buf_);
}
