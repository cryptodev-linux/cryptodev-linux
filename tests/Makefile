CC = gcc
CFLAGS = -Wall -g -O2

progs := ncr pk speed uspeed u2speed

all: $(progs)

speed: speed.c
	$(CC) $(CFLAGS) $< -o $@

ncr: ncr.c
	$(CC) $(CFLAGS) $< -o $@

pk: pk.c
	$(CC) $(CFLAGS) $< -o $@ -L/usr/local/lib -lgnutls

uspeed: shm/aes_cbc.c shm/shm.c shm/aes.h
	$(CC) $(CFLAGS) shm/aes_cbc.c shm/shm.c -o $@ -Ishm -lpthread

u2speed: shm/aes_cbc.c shm/plain.c shm/aes.h
	$(CC) $(CFLAGS) shm/aes_cbc.c shm/plain.c -o $@ -Ishm

check: $(progs)
	./ncr
	./pk
	./speed

clean:
	rm -f *.o *~ $(progs)
