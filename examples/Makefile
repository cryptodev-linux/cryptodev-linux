CC = gcc
CFLAGS = -Wall -g -O2

progs := cipher hmac ncr pk speed ncr-direct

all: $(progs)

cipher: cipher.c
	$(CC) $(CFLAGS) $< -o $@

speed: speed.c
	$(CC) $(CFLAGS) $< -o $@

hmac: hmac.c
	$(CC) $(CFLAGS) $< -o $@

ncr: ncr.c
	$(CC) $(CFLAGS) $< -o $@

pk: pk.c
	$(CC) $(CFLAGS) $< -o $@ -L/usr/local/lib -lgnutls

check: $(progs)
	./ncr
	./ncr-direct
	./pk
	./cipher
	./hmac
	./speed

clean:
	rm -f *.o *~ hmac cipher ncr pk speed ncr-direct
