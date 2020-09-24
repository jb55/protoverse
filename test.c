
#include "net.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned char bufs[3][1024];
static struct cursor cursors[3];


static void print_mem(unsigned char *a, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		printf("%02x ", a[i]);
	}
	printf("\n");

}

static void test_packet_serialization(struct packet packet)
{
	struct packet packet_out;
	int pushed[2], pulled;

	int i;
	for (i = 0; i < 3; i++) {
		make_cursor(bufs[i], bufs[i] + sizeof(bufs[i]), &cursors[i]);
	}

	pushed[0] = push_packet(bufs[0], sizeof(bufs[0]), &packet);
	assert(pushed[0]);

	pulled = pull_packet(&cursors[0], &cursors[1], &packet_out, pushed[0]);
	assert(pulled);

	pushed[1] = push_packet(bufs[2], sizeof(bufs[2]), &packet_out);
	assert(pushed[1]);

	print_mem(bufs[0], pushed[0]);

	/* printf("pushed %d,%d pulled %d\n", pushed[0], pushed[1], pulled); */
	assert(pushed[0] == pulled && pushed[1] == pushed[0]);

	assert(!memcmp(bufs[0], bufs[2], pulled));
	assert(packet_eq(&packet, &packet_out));

	print_packet(&packet);
}

static void test_chat_packet_serialization(void)
{
	struct packet packet;
	packet.type = PKT_CHAT;
	packet.data.chat.sender = 0xFFFF;
	packet.data.chat.message = "hello there";

	printf("chat packet\n");
	test_packet_serialization(packet);
}

static void test_fetch_packet_serialization(void)
{
	struct packet packet;
	packet.type = PKT_FETCH_DATA;
	packet.data.fetch.path = "derp";

	printf("fetch packet\n");
	test_packet_serialization(packet);
}


static void test_fetch_response_packet_serialization(void)
{
	struct packet packet;
	packet.type = PKT_FETCH_DATA_RESPONSE;
	packet.data.fetch_response.path = "derp";
	packet.data.fetch_response.data = (unsigned char[]){0xDE,0xEA,0xDB,0xEE,0xFF};
	packet.data.fetch_response.data_len = 5;

	printf("fetch_response packet\n");
	test_packet_serialization(packet);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	test_chat_packet_serialization();
	test_fetch_packet_serialization();
	test_fetch_response_packet_serialization();

	return 0;
}
