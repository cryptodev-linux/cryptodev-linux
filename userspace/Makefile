CC = gcc
CFLAGS = -Wall -g -O2

progs := ncr-setkey

all: $(progs)

ncr-setkey: setkey.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *.o *~ ncr-setkey
