CC=gcc
CFLAGS=-std=gnu11 -Wall -Wextra -O3
LDLIBS=-lcapstone -lopcodes

SRCS=$(wildcard src/*.c)
OBJS=$(notdir $(SRCS:.c=.o))

all: fuzzer

fuzzer: $(OBJS)
	$(CC) -o $@ $< $(LDLIBS)

%.o: src/%.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) $(OBJS) fuzzer
