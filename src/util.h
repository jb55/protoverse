
#ifndef PROTOVERSE_UTIL_H
#define PROTOVERSE_UTIL_H

#include <string.h>

static inline int memeq(void *buf, int buf_len, void *buf2, int buf2_len)
{
	if (buf_len != buf2_len)
		return 0;

	return memcmp(buf, buf2, buf_len) == 0;
}

#endif /* PROTOVERSE_UTIL_H */
