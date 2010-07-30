CC = gcc
CFLAGS = -Wall -g -O2

progs := ncr pk speed

all: $(progs)

speed: speed.c
	$(CC) $(CFLAGS) $< -o $@

ncr: ncr.c
	$(CC) $(CFLAGS) $< -o $@

pk: pk.c
	$(CC) $(CFLAGS) $< -o $@ -L/usr/local/lib -lgnutls

check: $(progs)
	./ncr
	./pk
	./speed

clean:
	rm -f *.o *~ ncr pk speed
