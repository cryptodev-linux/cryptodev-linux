/*
 * Demo on how to use /dev/crypto device for HMAC.
 *
 * Placed under public domain.
 *
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "../ncr.h"
#include <stdlib.h>



int main(int argc, char** argv)
{
	int fd = -1;
	FILE* fp;
	struct ncr_master_key_st key;
	int size;
	
	if (argc != 2) {
		fprintf(stderr, "Usage: setkey [filename]\n");
		exit(1);
	}
	
	memset(&key, 0, sizeof(key));
	fp = fopen(argv[1], "r");
	size = fread(key.key, 1, sizeof(key.key), fp);
	if (size < 16) {
		fprintf(stderr, "Illegal key!\n");
		exit(1);
	}
	fclose(fp);
	key.key_size = size;

	/* Open the crypto device */
	fd = open("/dev/crypto", O_RDWR, 0);
	if (fd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}

	/* encrypt */
	
	if (ioctl(fd, NCRIO_MASTER_KEY_SET, &key)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_MASTER_KEY_SET)");
		return 1;
	}
	/* Close the original descriptor */
	if (close(fd)) {
		perror("close(fd)");
		return 1;
	}

	return 0;
}
