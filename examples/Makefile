KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build

hostprogs := cipher hmac new
example-cipher-objs := cipher.o
example-hmac-objs := hmac.o
new-objs := new.o

check: $(hostprogs)
	./new
	./cipher
	./hmac

clean:
	rm -f *.o *~ hmac cipher new
