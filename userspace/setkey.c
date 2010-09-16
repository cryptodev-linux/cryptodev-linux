/*
 * Demo on how to use /dev/crypto device for HMAC.
 *
 * Placed under public domain.
 *
 */
#include <stdint.h>
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char** argv)
{
	int fd = -1;
	FILE* fp;
	struct ncr_master_key_set key;
	int size, ret;
	struct stat st;
	uint8_t rawkey[32];
	
	if (argc != 2) {
		fprintf(stderr, "Usage: setkey [filename]\n");
		exit(1);
	}
	
	/* check permissions */
	ret = stat(argv[1], &st);
	if (ret < 0) {
		fprintf(stderr, "Cannot find key: %s\n", argv[1]);
		exit(1);
	}
	
	if (st.st_mode & S_IROTH || st.st_mode & S_IRGRP || st.st_uid != 0) {
		fprintf(stderr, "Key file must belong to root and must be readable by him only.\n");
		exit(1);
	}
	
	/* read key */
	
	memset(&key, 0, sizeof(key));
	fp = fopen(argv[1], "r");
	if (fp == NULL) {
		fprintf(stderr, "Cannot read %s\n", argv[1]);
		exit(1);
	}

	size = fread(rawkey, 1, sizeof(rawkey), fp);
	if (size < 16) {
		fprintf(stderr, "Illegal key!\n");
		exit(1);
	}
	fclose(fp);
	key.key = rawkey;
	key.key_size = size;

	/* Open the crypto device */
	fd = open("/dev/ncr", O_RDWR, 0);
	if (fd < 0) {
		perror("open(/dev/ncr)");
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
