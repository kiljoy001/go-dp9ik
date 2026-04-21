// Minimal stubs for kernel functions needed by drawterm libraries
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sched.h>

char *argv0 = "go-9front-auth";

// Memory tagging (debugging) - no-op
void setmalloctag(void *v, unsigned long pc) {
    (void)v; (void)pc;
}

// System calls - use POSIX equivalents
int sysopen(const char *path, int mode) {
    return open(path, mode);
}

int sysclose(int fd) {
    return close(fd);
}

long sysread(int fd, void *buf, long n) {
    return read(fd, buf, n);
}

long syswrite(int fd, const void *buf, long n) {
    return write(fd, buf, n);
}

int sysgetpid(void) {
    return getpid();
}

// Sleep functions
void osyield(void) {
    sched_yield();
}

void osmsleep(unsigned long ms) {
    usleep(ms * 1000);
}

// Print functions
void iprint(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

// Error formatting
int __errfmt(void *f, void *a) {
    (void)f; (void)a;
    return 0;
}

// QLock stubs - genrandom needs these
void qlock(void *l) {
    (void)l; // No-op for now
}

void qunlock(void *l) {
    (void)l; // No-op for now
}
