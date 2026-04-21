# Makefile for building C libraries needed by go-dp9ik
# Build order is critical: libc -> libmp -> libsec -> libauthsrv

CC = gcc
AR = ar
CFLAGS = -I./drawterm/include -I./drawterm -fPIC -O2 -Wall

# Library directories
LIBC_DIR = drawterm/libc
LIBMP_DIR = drawterm/libmp
LIBSEC_DIR = drawterm/libsec
LIBAUTHSRV_DIR = drawterm/libauthsrv

# Output libraries
LIBC = $(LIBC_DIR)/libc.a
LIBMP = $(LIBMP_DIR)/libmp.a
LIBSEC = $(LIBSEC_DIR)/libsec.a
LIBAUTHSRV = $(LIBAUTHSRV_DIR)/libauthsrv.a
LIBSTUBS = libstubs.a
LIBMACHDEP = libmachdep.a

# Source files
LIBC_SRCS = $(wildcard $(LIBC_DIR)/*.c)
LIBMP_SRCS = $(wildcard $(LIBMP_DIR)/*.c)
LIBSEC_SRCS = $(wildcard $(LIBSEC_DIR)/*.c)
LIBAUTHSRV_SRCS = $(wildcard $(LIBAUTHSRV_DIR)/*.c)

# Object files
LIBC_OBJS = $(LIBC_SRCS:.c=.o)
LIBMP_OBJS = $(LIBMP_SRCS:.c=.o)
LIBSEC_OBJS = $(LIBSEC_SRCS:.c=.o)
LIBAUTHSRV_OBJS = $(LIBAUTHSRV_SRCS:.c=.o)

.PHONY: all clean

all: $(LIBSTUBS) $(LIBMACHDEP) $(LIBC) $(LIBMP) $(LIBSEC) $(LIBAUTHSRV)
	@echo "All libraries built successfully"

# Stubs library (POSIX compatibility layer)
$(LIBSTUBS): stubs.c
	$(CC) $(CFLAGS) -c stubs.c -o stubs.o
	$(AR) rcs $@ stubs.o

# Placeholder for libmachdep (arch-specific, just create empty archive)
$(LIBMACHDEP):
	$(AR) rcs $@

# Build order: libc first (no dependencies)
$(LIBC): $(LIBC_OBJS)
	$(AR) rcs $@ $^

# libmp depends on libc
$(LIBMP): $(LIBMP_OBJS) | $(LIBC)
	$(AR) rcs $@ $(LIBMP_OBJS)

# libsec depends on libc and libmp
$(LIBSEC): $(LIBSEC_OBJS) | $(LIBC) $(LIBMP)
	$(AR) rcs $@ $(LIBSEC_OBJS)

# libauthsrv depends on libc, libmp, and libsec
$(LIBAUTHSRV): $(LIBAUTHSRV_OBJS) | $(LIBC) $(LIBMP) $(LIBSEC)
	$(AR) rcs $@ $(LIBAUTHSRV_OBJS)

# Pattern rules for compilation
$(LIBC_DIR)/%.o: $(LIBC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(LIBMP_DIR)/%.o: $(LIBMP_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(LIBSEC_DIR)/%.o: $(LIBSEC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(LIBAUTHSRV_DIR)/%.o: $(LIBAUTHSRV_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(LIBC_OBJS) $(LIBMP_OBJS) $(LIBSEC_OBJS) $(LIBAUTHSRV_OBJS)
	rm -f $(LIBC) $(LIBMP) $(LIBSEC) $(LIBAUTHSRV)
	rm -f $(LIBSTUBS) $(LIBMACHDEP) stubs.o
	@echo "Cleaned all build artifacts"

# Convenience targets
libc: $(LIBC)
libmp: $(LIBMP)
libsec: $(LIBSEC)
libauthsrv: $(LIBAUTHSRV)

.DEFAULT_GOAL := all
