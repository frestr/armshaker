CC=gcc
CFLAGS=-march=armv8-a -std=gnu11 -Iinclude -Wall -Wextra -Og -g
LDLIBS=-lopcodes
DEFINES=-D_FILE_OFFSET_BITS=64

ifeq ($(USE_CAPSTONE),TRUE)
LDLIBS+=-lcapstone
DEFINES+=-DUSE_CAPSTONE
endif

SRCS=$(wildcard src/*.c)
OBJS=$(notdir $(SRCS:.c=.o))

all: fuzzer

fuzzer: $(OBJS)
	$(CC) -o $@ $(LDLIBS) $(OBJS)

%.o: src/%.c
	$(CC) $(CFLAGS) $(DEFINES) -c $<

clean:
	$(RM) $(OBJS) fuzzer
