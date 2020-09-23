
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

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
	/* TODO: better file cache */
	static struct file_cache file_cache[MAX_CACHED_FILES] = {0};
	static int cached_files = 0;
	struct file_cache *cached_file;
	int i, ok;
	size_t written;

	for (i = 0; i < cached_files; i++) {
		if (!strcmp(path, file_cache[i].path)) {
			*data_len = file_cache[i].data_len;
			*data = file_cache[i].dat;
			return 1;
		}
	}

	ok = read_file(path, buf->p, buf->end - buf->p, &written);
	if (!ok) return 0;

	assert(written <= (size_t)(buf->end - buf->p));

	*data = buf->p;

	buf->p += written;

	if (cached_files + 1 > MAX_CACHED_FILES)
		return 1;
	
	cached_file = &file_cache[cached_files++];
	cached_file->path = path;
	cached_file->data_len = written;
	cached_file->dat = buf->p - written;

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
		return 0;
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
	static unsigned char buf_[0xFFFF];

	struct in_addr my_addr;
	struct sockaddr_in bind_addr;
	struct sockaddr_in from;
	struct packet packet;
	struct cursor buf;
	socklen_t from_addr_len;

	int err, ok, fd;

	make_cursor(buf_, buf_ + sizeof(buf_), &buf);

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

	err = bind(fd, (struct sockaddr*)&bind_addr,
		   sizeof(bind_addr)) == -1;

	if (err) {
		printf("bind failed: %s\n", strerror(errno));
		return 0;
	}

	while (1) {
		ok = recv_packet(fd, &buf, &from, &packet);
		assert(sizeof(from) == from_addr_len);
		if (!ok) {
			printf("malformed packet\n");
			continue;
		}

		handle_packet(fd, &buf, &from, &packet);
	}
}


