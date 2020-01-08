CC=gcc
CFLAGS=-Wall -Wextra -O3 -g
LDLIBS=-lcapstone

SRCS=$(wildcard *.c)
OBJS=$(notdir $(SRCS:.c=.o))

all: fuzzer

fuzzer: $(OBJS)
	$(CC) -o $@ $< $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) $(OBJS)
