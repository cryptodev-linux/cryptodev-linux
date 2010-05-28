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

#include <sys/ioctl.h>
#include "../ncr.h"
#include <stdlib.h>

#define DATA_SIZE 4096

static void randomize_data(uint8_t * data, size_t data_size)
{
int i;
	
	srand(time(0)*getpid());
	for (i=0;i<data_size;i++) {
		data[i] = rand() & 0xff;
	}
}

static int
test_ncr_data(int cfd)
{
	struct ncr_data_init_st init;
	struct ncr_data_st kdata;
	uint8_t data[DATA_SIZE];
	uint8_t data_bak[DATA_SIZE];
	int i;

	randomize_data(data, sizeof(data));
	memcpy(data_bak, data, sizeof(data));

	init.max_object_size = DATA_SIZE;
	init.flags = NCR_DATA_FLAG_EXPORTABLE;
	init.initial_data = data;
	init.initial_data_size = sizeof(data);

	if (ioctl(cfd, NCRIO_DATA_INIT, &init)) {
		perror("ioctl(NCRIO_DATA_INIT)");
		return 1;
	}
	
	fprintf(stderr, "Imported data\n");

	memset(data, 0, sizeof(data));

	kdata.desc = init.desc;
	kdata.data = data;
	kdata.data_size = sizeof(data);
	kdata.append_flag = 0;

	if (ioctl(cfd, NCRIO_DATA_GET, &kdata)) {
		perror("ioctl(NCRIO_DATA_GET)");
		return 1;
	}

	if (memcmp(data, data_bak, sizeof(data))!=0) {
		fprintf(stderr, "data returned but differ!\n");
		return 1;
	}

	fprintf(stderr, "Verified imported data integrity\n");

	/* test set */
	memset(data, 0xf1, sizeof(data));

	kdata.desc = init.desc;
	kdata.data = data;
	kdata.data_size = sizeof(data);
	kdata.append_flag = 0;

	if (ioctl(cfd, NCRIO_DATA_SET, &kdata)) {
		perror("ioctl(NCRIO_DATA_SET)");
		return 1;
	}

	fprintf(stderr, "Imported new data\n");

	/* test get after set */
	memset(data, 0, sizeof(data));

	kdata.desc = init.desc;
	kdata.data = data;
	kdata.data_size = sizeof(data);
	kdata.append_flag = 0;

	if (ioctl(cfd, NCRIO_DATA_GET, &kdata)) {
		perror("ioctl(NCRIO_DATA_GET)");
		return 1;
	}

	for(i=0;i<kdata.data_size;i++) {
		if (((uint8_t*)kdata.data)[i] != 0xf1) {
			fprintf(stderr, "data returned but differ!\n");
			return 1;
		}
	}
	fprintf(stderr, "Verified new data\n");

	if (ioctl(cfd, NCRIO_DATA_DEINIT, &kdata.desc)) {
		perror("ioctl(NCRIO_DATA_DEINIT)");
		return 1;
	}

	fprintf(stderr, "Initializing unexportable data\n");
	randomize_data(data, sizeof(data));

	init.max_object_size = DATA_SIZE;
	init.flags = 0;
	init.initial_data = data;
	init.initial_data_size = sizeof(data);

	if (ioctl(cfd, NCRIO_DATA_INIT, &init)) {
		perror("ioctl(NCRIO_DATA_INIT)");
		return 1;
	}

	kdata.desc = init.desc;
	kdata.data = data;
	kdata.data_size = sizeof(data);
	kdata.append_flag = 0;

	if (ioctl(cfd, NCRIO_DATA_GET, &kdata)) {
		perror("ioctl");
		fprintf(stderr, "Verified that unexportable data cannot be exported\n");
	} else {
		fprintf(stderr, "Unexportable data were exported!?\n");
		return 1; /* ok */
	}

	for (i=0;i<512;i++ ) {
		init.max_object_size = DATA_SIZE;
		init.flags = 0;
		init.initial_data = data;
		init.initial_data_size = sizeof(data);

		if (ioctl(cfd, NCRIO_DATA_INIT, &init)) {
			perror("ioctl(NCRIO_DATA_INIT)");
			fprintf(stderr, "Reached maximum limit at: %d data\n", i);
		}
	}

	return 0;
}

int
main()
{
	int fd = -1;

	/* Open the crypto device */
	fd = open("/dev/crypto", O_RDWR, 0);
	if (fd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}

	/* Run the test itself */
	if (test_ncr_data(fd))
		return 1;

	/* Close the original descriptor */
	if (close(fd)) {
		perror("close(fd)");
		return 1;
	}

	return 0;
}
