
#ifndef PROTOVERSE_IO_H
#define PROTOVERSE_IO_H

#include <stdio.h>

int read_fd(FILE *fd, unsigned char *buf, int buflen, int *written);
int read_file(const char *filename, unsigned char *buf, int buflen, int *written);
int read_file_or_stdin(const char *filename, unsigned char *buf, int buflen, int *written);
int map_file(const char *filename, unsigned char **p, size_t *flen);


#endif /* PROTOVERSE_IO_H */
