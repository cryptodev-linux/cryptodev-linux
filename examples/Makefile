KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build

hostprogs := cipher hmac new new-key
example-cipher-objs := cipher.o
example-hmac-objs := hmac.o
new-objs := new.o
new-key-objs := new-key.c

check: $(hostprogs)
	./new-key
	./new
	./cipher
	./hmac

clean:
	rm -f *.o *~ hmac cipher new new-key
