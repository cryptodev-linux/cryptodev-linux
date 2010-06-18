KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build

hostprogs := setkey
setkey-objs := setkey.o

all: $(hostprogs)

clean:
	rm -f *.o *~ setkey
