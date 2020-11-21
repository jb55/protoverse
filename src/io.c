
#include "io.h"

#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

int read_fd(FILE *fd, unsigned char *buf, int buflen, int *written)
{
	unsigned char *p = buf;
	int len = 0;
	*written = 0;

	do {
		len = fread(p, 1, 4096, fd);
		*written += len;
		p += len;
		if (p > buf + buflen)
			return 0;
	} while (len == 4096);

	return 1;
}

int map_file(const char *filename, unsigned char **p, size_t *flen)
{
	struct stat st;
	int des;
	stat(filename, &st);
	*flen = st.st_size;

	des = open(filename, O_RDONLY);

	*p = mmap(NULL, *flen, PROT_READ, MAP_PRIVATE, des, 0);
	close(des);

	return *p != MAP_FAILED;
}

int read_file(const char *filename, unsigned char *buf, int buflen, int *written)
{
	FILE *file = NULL;
	int ok;

	file = fopen(filename, "rb");
	if (file == NULL) {
		*written = strlen(filename) + 1;
		strncpy((char*)buf, filename, buflen);
		return 1;
	}

	ok = read_fd(file, buf, buflen, written);
	fclose(file);
	return ok;
}


int read_file_or_stdin(const char *filename, unsigned char *buf, int buflen,
		       int *written)
{
	if (filename == NULL) {
		return read_fd(stdin, buf, buflen, written);
	}

	return read_file(filename, buf, buflen, written);
}
