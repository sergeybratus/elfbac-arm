#ifndef LIBC_H_
#define LIBC_H_

long read(int fd, void *buf, unsigned long count);
long write(int fd, const void *buf, unsigned long count);
void _exit(int status);

#endif /* LIBC_H_ */

