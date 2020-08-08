
#ifndef PROTOVERSE_IO_H
#define PROTOVERSE_IO_H

#include <stdio.h>

int read_fd(FILE *fd, unsigned char *buf, size_t buflen, size_t *written);
int read_file(const char *filename, unsigned char *buf, size_t buflen, size_t *written);
int read_file_or_stdin(const char *filename, unsigned char *buf,
                       size_t buflen, size_t *written);


#endif /* PROTOVERSE_IO_H */
