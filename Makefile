CC=gcc
CFLAGS=-march=armv8-a -std=gnu11 -D_FILE_OFFSET_BITS=64 -Iinclude -Wall -Wextra -Og -g
LDLIBS=-lcapstone -lopcodes

SRCS=$(wildcard src/*.c)
OBJS=$(notdir $(SRCS:.c=.o))

all: fuzzer

fuzzer: $(OBJS)
	$(CC) -o $@ $(LDLIBS) $(OBJS)

%.o: src/%.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) $(OBJS) fuzzer
