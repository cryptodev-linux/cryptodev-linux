CC = gcc
CFLAGS = -Wall -g -O2

progs := aes rsa

all: $(progs)

aes: aes.c
	$(CC) $(CFLAGS) $< -o $@

rsa: rsa.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *.o *~ $(progs)
