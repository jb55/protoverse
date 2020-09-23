
#include "net.h"
#include "cursor.h"
#include "util.h"
#include "varint.h"

#include <sys/types.h>
#include <assert.h>
#include <error.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

static int push_fetch_response_packet(struct cursor *c, struct fetch_response_packet *resp)
{
	int ok;
	ok = push_prefixed_str(c, resp->path);
	if (!ok) return 0;
	ok = push_varint(c, resp->data_len);
	if (!ok) return 0;
	return push_data(c, resp->data, resp->data_len);
}

static int pull_fetch_response_packet(struct cursor *c, struct cursor *buf,
				      struct fetch_response_packet *resp)
{
	int ok;
	ok = pull_prefixed_str(c, buf, &resp->path);
	if (!ok) return 0;
	ok = pull_varint(c, &resp->data_len);
	if (!ok) return 0;
	return pull_data_into_cursor(c, buf, &resp->data, resp->data_len);
}

static int push_fetch_packet(struct cursor *c, struct fetch_packet *fetch)
{
	return push_prefixed_str(c, fetch->path);
}

/* TODO: CPU-independent encoding */
static int push_chat_packet(struct cursor *c, struct chat_packet *chat)
{
	int ok;
	ok = push_varint(c, chat->sender);
	if (!ok) return 0;

	return push_prefixed_str(c, chat->message);
}

static int pull_chat_packet(struct cursor *c, struct cursor *buf, struct chat_packet *chat)
{
	int ok;

	ok = pull_varint(c, &chat->sender);
	if (!ok) return 0;

	return pull_prefixed_str(c, buf, &chat->message);
}

static int pull_fetch_packet(struct cursor *c, struct cursor *buf, struct fetch_packet *fetch)
{
	return pull_prefixed_str(c, buf, &fetch->path);
}


int send_packet(int sockfd, struct sockaddr_in *to_addr, struct packet *packet)
{
	static unsigned char buf[0xFFFF];
	int ok, len;

	len = push_packet(buf, sizeof(buf), packet);
	if (!len) return 0;

	ok = sendto(sockfd, buf, len, 0, (struct sockaddr*)to_addr, sizeof(*to_addr));

	if (ok != len) {
		printf("sendto: sent %d != packet_len %d - %s\n", ok, len, strerror(errno));
		return 0;
	}

	return ok;
}

int recv_packet(int sockfd, struct cursor *buf, struct sockaddr_in *from, struct packet *packet)
{
	static unsigned char tmp[0xFFFF];
	struct cursor tmp_cursor;
	socklen_t size = sizeof(*from);
	int bytes;

	bytes = recvfrom(sockfd, tmp, sizeof(tmp), 0, (struct sockaddr*)from, &size);
	assert(size == sizeof(*from));
	make_cursor(tmp, tmp + sizeof(tmp), &tmp_cursor);

	return pull_packet(&tmp_cursor, buf, packet, bytes);
}

static int push_envelope(struct cursor *cursor, enum packet_type type, int len)
{
	int ok;
	int env_len;

	ok = push_varint(cursor, (int)type);
	if (!ok) return 0;

	env_len = ok;

	ok = push_varint(cursor, len);

	env_len += ok;

	return env_len;
}

static int pull_envelope(struct cursor *cursor, enum packet_type *type, int *len)
{
	int ok, env_len;
	ok = pull_varint(cursor, (int*)type);
	if (!ok) return 0;

	if (*type >= PKT_NUM_TYPES)
		return 0;

	env_len = ok;

	ok = pull_varint(cursor, len);
	if (!ok) return 0;

	env_len += ok;

	return env_len;
}

static int push_packet_data(struct cursor *c, struct packet *packet)
{
	switch (packet->type) {
	case PKT_FETCH_DATA:
		return push_fetch_packet(c, &packet->data.fetch);
	case PKT_FETCH_DATA_RESPONSE:
		return push_fetch_response_packet(c, &packet->data.fetch_response);
	case PKT_CHAT:
		return push_chat_packet(c, &packet->data.chat);
	case PKT_NUM_TYPES:
		return 0;
	}

	return 0;
}

int push_packet(unsigned char *buf, int bufsize, struct packet *packet)
{
	struct cursor cursor;
	struct cursor envelope_cursor;
	int len, ok, envelope_size;
	envelope_size = VARINT_MAX_LEN * 2;

	make_cursor(buf, buf + envelope_size, &envelope_cursor);
	make_cursor(buf + envelope_size, buf + bufsize, &cursor);

	ok = push_packet_data(&cursor, packet);
	if (!ok) return 0;

	len = cursor.p - cursor.start;

	ok = push_envelope(&envelope_cursor, packet->type, len);
	if (!ok) return 0;

	memmove(buf + ok, cursor.start, len);

	return len + ok;
}


static int pull_packet_data(struct cursor *c, struct cursor *buf,
			    struct packet *packet, int len)
{
	(void)c;
	(void)len;
	switch (packet->type) {
	case PKT_FETCH_DATA:
		return pull_fetch_packet(c, buf, &packet->data.fetch);
	case PKT_FETCH_DATA_RESPONSE:
		return pull_fetch_response_packet(c, buf,
						  &packet->data.fetch_response);
	case PKT_CHAT:
		return pull_chat_packet(c, buf, &packet->data.chat);
	case PKT_NUM_TYPES:
		break;
	}

	return 0;
}

int pull_packet(struct cursor *c, struct cursor *buf, struct packet *packet,
		int received_bytes)
{
	int ok, env_size, len, capacity_left;

	env_size = pull_envelope(c, &packet->type, &len);
	if (!env_size) return 0;

	if (len + env_size != received_bytes) {
		printf("invalid packet size. expected %d, got %d\n", len+env_size,
		       received_bytes);
		return 0;
	}

	capacity_left = cursor_remaining_capacity(c) - 1;
	if (len > capacity_left) {
		printf("sanity: packet larger (%d) than remaining buffer size: %d", len, capacity_left);
		return 0;
	}

	ok = pull_packet_data(c, buf, packet, len);
	if (!ok) return 0;

	return len + env_size;
}

static int packet_chat_eq(struct chat_packet *a, struct chat_packet *b)
{
	/* fail if either is 0 but not both 0 or both not 0 */
	if (!a->message ^ !b->message)
		return 0;

	return a->sender == b->sender && !strcmp(a->message, b->message);
}

static int packet_fetch_eq(struct fetch_packet *a, struct fetch_packet *b)
{
	if (!a->path ^ !b->path)
		return 0;

	return !strcmp(a->path, b->path);
}

static int packet_fetch_resp_eq(struct fetch_response_packet *a,
				struct fetch_response_packet *b)
{
	if (!a->path ^ !b->path)
		return 0;

	return memeq(a->data, a->data_len, b->data, b->data_len);
}

int packet_eq(struct packet *a, struct packet *b)
{
	if (a->type != b->type)
		return 0;

	switch (a->type) {
	case PKT_CHAT:
		return packet_chat_eq(&a->data.chat, &b->data.chat);
	case PKT_FETCH_DATA:
		return packet_fetch_eq(&a->data.fetch, &b->data.fetch);
	case PKT_FETCH_DATA_RESPONSE:
		return packet_fetch_resp_eq(&a->data.fetch_response,
					    &b->data.fetch_response);
	case PKT_NUM_TYPES:
		return 0;
	}

	return 0;
}


void print_packet(struct packet *packet)
{
	switch (packet->type) {
	case PKT_CHAT:
		printf("(chat (sender %d) (message \"%s\"))\n",
		       packet->data.chat.sender,
		       packet->data.chat.message);
		return;
	case PKT_FETCH_DATA_RESPONSE:
		printf("(fetch-resp (path \"%s\") (data %d))\n",
			packet->data.fetch_response.path,
			packet->data.fetch_response.data_len);
		return;
	case PKT_FETCH_DATA:
		printf("(fetch (path \"%s\"))\n",
		       packet->data.fetch.path);
		return;
	case PKT_NUM_TYPES:
		break;
	}

	printf("(unknown)\n");
}
