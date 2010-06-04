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

#define DATA_SIZE 4096

static void randomize_data(uint8_t * data, size_t data_size)
{
int i;
	
	srand(time(0)*getpid());
	for (i=0;i<data_size;i++) {
		data[i] = rand() & 0xff;
	}
}

#define KEY_DATA_SIZE 16
static int
test_ncr_key(int cfd)
{
	struct ncr_data_init_st dinit;
	struct ncr_key_generate_st kgen;
	ncr_key_t key;
	struct ncr_key_data_st keydata;
	struct ncr_data_st kdata;
	uint8_t data[KEY_DATA_SIZE];
	uint8_t data_bak[KEY_DATA_SIZE];

	fprintf(stdout, "Tests on Keys:\n");

	/* test 1: generate a key in userspace import it
	 * to kernel via data and export it.
	 */

	fprintf(stdout, "\tKey generation...\n");

	randomize_data(data, sizeof(data));
	memcpy(data_bak, data, sizeof(data));

	dinit.max_object_size = KEY_DATA_SIZE;
	dinit.flags = NCR_DATA_FLAG_EXPORTABLE;
	dinit.initial_data = data;
	dinit.initial_data_size = sizeof(data);

	if (ioctl(cfd, NCRIO_DATA_INIT, &dinit)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_INIT)");
		return 1;
	}

	/* convert it to key */
	if (ioctl(cfd, NCRIO_KEY_INIT, &key)) {
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	keydata.key_id[0] = 'a';
	keydata.key_id[2] = 'b';
	keydata.key_id_size = 2;
	keydata.type = NCR_KEY_TYPE_SECRET;
	keydata.algorithm = NCR_ALG_AES_CBC;
	keydata.flags = NCR_KEY_FLAG_EXPORTABLE;
	
	keydata.key = key;
	keydata.data = dinit.desc;

	if (ioctl(cfd, NCRIO_KEY_IMPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

	/* now try to read it */
	fprintf(stdout, "\tKey export...\n");
	if (ioctl(cfd, NCRIO_DATA_DEINIT, &dinit.desc)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_DEINIT)");
		return 1;
	}

	dinit.max_object_size = DATA_SIZE;
	dinit.flags = NCR_DATA_FLAG_EXPORTABLE;
	dinit.initial_data = NULL;
	dinit.initial_data_size = 0;

	if (ioctl(cfd, NCRIO_DATA_INIT, &dinit)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_INIT)");
		return 1;
	}

	memset(&keydata, 0, sizeof(keydata));
	keydata.key = key;
	keydata.data = dinit.desc;

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

	/* now read data */
	memset(data, 0, sizeof(data));

	kdata.desc = dinit.desc;
	kdata.data = data;
	kdata.data_size = sizeof(data);
	kdata.append_flag = 0;

	if (ioctl(cfd, NCRIO_DATA_GET, &kdata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_GET)");
		return 1;
	}

	if (memcmp(data, data_bak, sizeof(data))!=0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		fprintf(stderr, "data returned but differ!\n");
		return 1;
	}

	if (ioctl(cfd, NCRIO_KEY_DEINIT, &key)) {
		perror("ioctl(NCRIO_KEY_DEINIT)");
		return 1;
	}

	/* finished, we keep data for next test */

	/* test 2: generate a key in kernel space and
	 * export it.
	 */

	fprintf(stdout, "\tKey import...\n");
	/* convert it to key */
	if (ioctl(cfd, NCRIO_KEY_INIT, &key)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	kgen.desc = key;
	kgen.params.algorithm = NCR_ALG_AES_CBC;
	kgen.params.keyflags = NCR_KEY_FLAG_EXPORTABLE;
	kgen.params.params.secret.bits = 128; /* 16  bytes */
	
	if (ioctl(cfd, NCRIO_KEY_GENERATE, &kgen)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

	memset(&keydata, 0, sizeof(keydata));
	keydata.key = key;
	keydata.data = dinit.desc;

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

	/* now read data */
	memset(data, 0, sizeof(data));

	kdata.desc = dinit.desc;
	kdata.data = data;
	kdata.data_size = sizeof(data);
	kdata.append_flag = 0;

	if (ioctl(cfd, NCRIO_DATA_GET, &kdata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_GET)");
		return 1;
	}

#if 0
	fprintf(stderr, "Generated key: %.2x.%.2x.%.2x.%.2x.%.2x.%.2x.%.2x.%.2x."
		"%.2x.%.2x.%.2x.%.2x.%.2x.%.2x.%.2x.%.2x\n", data[0], data[1],
		data[2], data[3], data[4], data[5], data[6], data[7], data[8],
		data[9], data[10], data[11], data[12], data[13], data[14],
		data[15]);
#endif

	if (ioctl(cfd, NCRIO_KEY_DEINIT, &key)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_DEINIT)");
		return 1;
	}
	
	/* test 3: generate an unexportable key in kernel space and
	 * try to export it.
	 */
	fprintf(stdout, "\tKey protection of non-exportable keys...\n");
	if (ioctl(cfd, NCRIO_KEY_INIT, &key)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	kgen.desc = key;
	kgen.params.algorithm = NCR_ALG_AES_CBC;
	kgen.params.keyflags = 0;
	kgen.params.params.secret.bits = 128; /* 16  bytes */
	
	if (ioctl(cfd, NCRIO_KEY_GENERATE, &kgen)) {
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

	memset(&keydata, 0, sizeof(keydata));
	keydata.key = key;
	keydata.data = dinit.desc;

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_EXPORT)");
		return 1;
	}

	/* try to get the output data - should fail */
	memset(data, 0, sizeof(data));

	kdata.desc = dinit.desc;
	kdata.data = data;
	kdata.data_size = sizeof(data);
	kdata.append_flag = 0;

	if (ioctl(cfd, NCRIO_DATA_GET, &kdata)==0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		fprintf(stderr, "Data were exported, but shouldn't be!\n");
		return 1;
	}

	if (ioctl(cfd, NCRIO_KEY_DEINIT, &key)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_DEINIT)");
		return 1;
	}

	return 0;
}


static int test_ncr_data(int cfd)
{
	struct ncr_data_init_st init;
	struct ncr_data_st kdata;
	uint8_t data[DATA_SIZE];
	uint8_t data_bak[DATA_SIZE];
	int i;

	fprintf(stdout, "Tests on Data:\n");
	
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
	
	fprintf(stdout, "\tData Import...\n");

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

	fprintf(stdout, "\tData Export...\n");

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
	fprintf(stdout, "\t2nd Data Import/Export...\n");

	if (ioctl(cfd, NCRIO_DATA_DEINIT, &kdata.desc)) {
		perror("ioctl(NCRIO_DATA_DEINIT)");
		return 1;
	}

	fprintf(stdout, "\tProtection of non-exportable data...\n");
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

	if (ioctl(cfd, NCRIO_DATA_GET, &kdata)==0) {
		fprintf(stderr, "Unexportable data were exported!?\n");
		return 1;
	}

	fprintf(stdout, "\tLimits on maximum allowed data...\n");
	for (i=0;i<256;i++ ) {
		init.max_object_size = DATA_SIZE;
		init.flags = 0;
		init.initial_data = data;
		init.initial_data_size = sizeof(data);

		if (ioctl(cfd, NCRIO_DATA_INIT, &init)) {
			//fprintf(stderr, "Reached maximum limit at: %d data items\n", i);
			break;
		}
	}
	
	/* shouldn't run any other tests after that */

	return 0;
}

static int
test_ncr_store_key(int cfd)
{
	struct ncr_data_init_st dinit;
	struct ncr_key_generate_st kgen;
	ncr_key_t key, key2;
	struct ncr_key_data_st keydata;
	struct ncr_data_st kdata;
	uint8_t data[KEY_DATA_SIZE];
	uint8_t data_bak[KEY_DATA_SIZE];
	struct ncr_storage_st kstore;

	fprintf(stdout, "Tests on Key Storage:\n");

	/* test 1: generate a key in kernel and store it.
	 * The try to load it.
	 */
	fprintf(stdout, "\tKey storage/retrieval...\n");

	/* initialize data */
	dinit.max_object_size = KEY_DATA_SIZE;
	dinit.flags = NCR_DATA_FLAG_EXPORTABLE;
	dinit.initial_data = NULL;
	dinit.initial_data_size = 0;

	if (ioctl(cfd, NCRIO_DATA_INIT, &dinit)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_INIT)");
		return 1;
	}

	if (ioctl(cfd, NCRIO_KEY_INIT, &key)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	if (ioctl(cfd, NCRIO_KEY_INIT, &key2)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	kgen.desc = key;
	kgen.params.algorithm = NCR_ALG_AES_CBC;
	kgen.params.keyflags = NCR_KEY_FLAG_EXPORTABLE;
	kgen.params.params.secret.bits = 128; /* 16  bytes */
	
	if (ioctl(cfd, NCRIO_KEY_GENERATE, &kgen)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}


	memset(&keydata, 0, sizeof(keydata));
	keydata.key = key;
	keydata.data = dinit.desc;

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

	/* now read data */
	memset(data, 0, sizeof(data));

	kdata.desc = dinit.desc;
	kdata.data = data_bak;
	kdata.data_size = sizeof(data_bak);
	kdata.append_flag = 0;

	if (ioctl(cfd, NCRIO_DATA_GET, &kdata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_GET)");
		return 1;
	}
	
	/* ok now key stands in data[]. Store it. */
	
	kstore.key = key;
	strcpy(kstore.label, "testkey");
	kstore.mode = S_IRWXU;

	if (ioctl(cfd, NCRIO_STORAGE_STORE, &kstore)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_STORAGE_STORE)");
		return 1;
	}

	kstore.key = key2;

	if (ioctl(cfd, NCRIO_STORAGE_LOAD, &kstore)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_STORAGE_LOAD)");
		return 1;
	}
	
	/* export it */
	memset(&keydata, 0, sizeof(keydata));
	keydata.key = key2;
	keydata.data = dinit.desc;

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

	/* now read data */
	memset(data, 0, sizeof(data));

	kdata.desc = dinit.desc;
	kdata.data = data;
	kdata.data_size = sizeof(data);
	kdata.append_flag = 0;

	if (ioctl(cfd, NCRIO_DATA_GET, &kdata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_GET)");
		return 1;
	}
	
	if (memcmp(data, data_bak, kdata.data_size)!=0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		fprintf(stderr, "Loaded data do not match stored\n");
		return 1;
	}
	
	if (ioctl(cfd, NCRIO_KEY_DEINIT, &key)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_DEINIT)");
		return 1;
	}

	if (ioctl(cfd, NCRIO_KEY_DEINIT, &key2)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_DEINIT)");
		return 1;
	}

	if (ioctl(cfd, NCRIO_DATA_DEINIT, &dinit.desc)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_DEINIT)");
		return 1;
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

	/* actually test if the initial close
	 * will really delete all used lists */

	fd = open("/dev/crypto", O_RDWR, 0);
	if (fd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}

	if (test_ncr_key(fd))
		return 1;

	if (test_ncr_store_key(fd))
		return 1;

	/* Close the original descriptor */
	if (close(fd)) {
		perror("close(fd)");
		return 1;
	}

	return 0;
}
