
#include "net.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>


static void print_mem(unsigned char *a, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		printf("%02x ", a[i]);
	}
	printf("\n");

}

int main(int argc, char *argv[])
{
	static unsigned char bufs[3][1024];

	struct cursor cursors[3];
	struct packet packet;
	struct packet packet_out;

	int pushed[2], pulled, i;

	(void)argc;
	(void)argv;

	for (i = 0; i < 3; i++) {
		make_cursor(bufs[i], bufs[i] + sizeof(bufs[i]), &cursors[i]);
	}

	packet.type = PKT_CHAT;
	packet.data.chat.sender = 1;
	packet.data.chat.message = "hello there";

	pushed[0] = push_packet(bufs[0], sizeof(bufs[0]), &packet);
	assert(pushed[0]);

	pulled = pull_packet(&cursors[0], &cursors[1], &packet_out);
	assert(pulled);

	pushed[1] = push_packet(bufs[2], sizeof(bufs[2]), &packet_out);
	assert(pushed[1]);

	printf("chat packet\n");
	print_mem(bufs[0], pushed[0]);

	/* printf("pushed %d,%d pulled %d\n", pushed[0], pushed[1], pulled); */
	assert(pushed[0] == pulled && pushed[1] == pushed[0]);


	assert(!memcmp(bufs[0], bufs[2], pulled));
	assert(packet_eq(&packet, &packet_out));

	print_packet(&packet);

	return 0;
}
