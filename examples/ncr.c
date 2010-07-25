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
#define WRAPPED_KEY_DATA_SIZE 32
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
	memset(&kdata, 0, sizeof(kdata));

	kdata.desc = dinit.desc;
	kdata.data = data;
	kdata.data_size = sizeof(data);

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

	if (ioctl(cfd, NCRIO_DATA_SET, &kdata)) {
		perror("ioctl(NCRIO_DATA_SET)");
		return 1;
	}

	/* test get after set */
	memset(data, 0, sizeof(data));

	kdata.desc = init.desc;
	kdata.data = data;
	kdata.data_size = sizeof(data);

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

/* Key wrapping */
static int
test_ncr_wrap_key(int cfd)
{
	int i;
	struct ncr_data_init_st dinit;
	ncr_key_t key, key2;
	struct ncr_key_data_st keydata;
	struct ncr_data_st kdata;
	struct ncr_key_wrap_st kwrap;
	uint8_t data[WRAPPED_KEY_DATA_SIZE];
	int data_size;

	fprintf(stdout, "Tests on Keys:\n");

	/* test 1: generate a key in userspace import it
	 * to kernel via data and export it.
	 */

	fprintf(stdout, "\tKey Wrap test...\n");

	dinit.max_object_size = WRAPPED_KEY_DATA_SIZE;
	dinit.flags = NCR_DATA_FLAG_EXPORTABLE;
	dinit.initial_data = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
	dinit.initial_data_size = 16;

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
	keydata.flags = NCR_KEY_FLAG_EXPORTABLE|NCR_KEY_FLAG_WRAPPABLE;
	
	keydata.key = key;
	keydata.data = dinit.desc;

	if (ioctl(cfd, NCRIO_KEY_IMPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

#define DKEY "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"
	/* now key data */
	kdata.data = DKEY;
	kdata.data_size = 16;
	kdata.desc = dinit.desc;

	if (ioctl(cfd, NCRIO_DATA_SET, &kdata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_SET)");
		return 1;
	}

	/* convert it to key */
	if (ioctl(cfd, NCRIO_KEY_INIT, &key2)) {
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	keydata.key_id[0] = 'b';
	keydata.key_id[2] = 'a';
	keydata.key_id_size = 2;
	keydata.type = NCR_KEY_TYPE_SECRET;
	keydata.algorithm = NCR_ALG_AES_CBC;
	keydata.flags = NCR_KEY_FLAG_EXPORTABLE|NCR_KEY_FLAG_WRAPPABLE;
	
	keydata.key = key2;
	keydata.data = kdata.desc;

	if (ioctl(cfd, NCRIO_KEY_IMPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

	/* now try wrapping key2 using key */
	memset(&kwrap, 0, sizeof(kwrap));
	kwrap.algorithm = NCR_WALG_AES_RFC3394;
	kwrap.keytowrap = key2;
	kwrap.key = key;
	kwrap.io = data;
	kwrap.io_size = sizeof(data);

	if (ioctl(cfd, NCRIO_KEY_WRAP, &kwrap)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_WRAP)");
		return 1;
	}
	
	data_size = kwrap.io_size;

	if (kwrap.io_size != 24 || memcmp(data,
		"\x1F\xA6\x8B\x0A\x81\x12\xB4\x47\xAE\xF3\x4B\xD8\xFB\x5A\x7B\x82\x9D\x3E\x86\x23\x71\xD2\xCF\xE5", 24) != 0) {
		fprintf(stderr, "Wrapped data do not match.\n");

		fprintf(stderr, "Data[%d]: ",(int) kwrap.io_size);
		for(i=0;i<kwrap.io_size;i++)
			fprintf(stderr, "%.2x:", data[i]);
		fprintf(stderr, "\n");
		return 1;
	}




	/* test unwrapping */
	fprintf(stdout, "\tKey Unwrap test...\n");

	/* reset key2 */
	if (ioctl(cfd, NCRIO_KEY_DEINIT, &key2)) {
		perror("ioctl(NCRIO_KEY_DEINIT)");
		return 1;
	}

	if (ioctl(cfd, NCRIO_KEY_INIT, &key2)) {
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	memset(&kwrap, 0, sizeof(kwrap));
	kwrap.algorithm = NCR_WALG_AES_RFC3394;
	kwrap.keytowrap = key2;
	kwrap.key = key;
	kwrap.io = data;
	kwrap.io_size = data_size;

	if (ioctl(cfd, NCRIO_KEY_UNWRAP, &kwrap)) {
		perror("ioctl(NCRIO_KEY_UNWRAP)");
		return 1;
	}

	/* now export the unwrapped */
#if 0
	/* this cannot be performed like that, because unwrap
	 * always sets keys as unexportable. Maybe we can implement
	 * a data comparison ioctl().
	 */
	memset(&keydata, 0, sizeof(keydata));
	keydata.key = key2;
	keydata.data = kdata.desc;

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

	if (ioctl(cfd, NCRIO_DATA_GET, &kdata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_GET)");
		return 1;
	}

	if (kdata.data_size != 16 || memcmp(kdata.data, DKEY, 16) != 0) {
		fprintf(stderr, "Unwrapped data do not match.\n");
		fprintf(stderr, "Data[%d]: ", (int) kdata.data_size);
		for(i=0;i<kdata.data_size;i++)
			fprintf(stderr, "%.2x:", data[i]);
		fprintf(stderr, "\n");
		return 1;
	}
#endif

	return 0;

}

static int
test_ncr_store_wrap_key(int cfd)
{
	int i;
	struct ncr_data_init_st dinit;
	ncr_key_t key2;
	struct ncr_key_data_st keydata;
	struct ncr_data_st kdata;
	struct ncr_key_storage_wrap_st kwrap;
	uint8_t data[DATA_SIZE];
	int dd;
	int data_size;

	fprintf(stdout, "Tests on Key storage:\n");

	/* test 1: generate a key in userspace import it
	 * to kernel via data and export it.
	 */

	fprintf(stdout, "\tKey Storage wrap test...\n");

	memset(&dinit, 0, sizeof(dinit));
	dinit.max_object_size = DATA_SIZE;
	dinit.flags = NCR_DATA_FLAG_EXPORTABLE;

	if (ioctl(cfd, NCRIO_DATA_INIT, &dinit)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_INIT)");
		return 1;
	}

	dd = dinit.desc;

#define DKEY "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"
	/* now key data */
	kdata.data = DKEY;
	kdata.data_size = 16;
	kdata.desc = dd;

	if (ioctl(cfd, NCRIO_DATA_SET, &kdata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_SET)");
		return 1;
	}

	/* convert it to key */
	if (ioctl(cfd, NCRIO_KEY_INIT, &key2)) {
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	keydata.key_id[0] = 'b';
	keydata.key_id[2] = 'a';
	keydata.key_id_size = 2;
	keydata.type = NCR_KEY_TYPE_SECRET;
	keydata.algorithm = NCR_ALG_AES_CBC;
	keydata.flags = NCR_KEY_FLAG_EXPORTABLE|NCR_KEY_FLAG_WRAPPABLE;
	
	keydata.key = key2;
	keydata.data = dd;

	if (ioctl(cfd, NCRIO_KEY_IMPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

	/* now try wrapping key2 using key */
	memset(&kwrap, 0, sizeof(kwrap));
	kwrap.keytowrap = key2;
	kwrap.io = data;
	kwrap.io_size = sizeof(data);

	if (ioctl(cfd, NCRIO_KEY_STORAGE_WRAP, &kwrap)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_STORAGE_WRAP)");
		return 1;
	}

	/* test unwrapping */
	data_size = kwrap.io_size;
	fprintf(stdout, "\tKey Storage Unwrap test...\n");

	/* reset key2 */
	if (ioctl(cfd, NCRIO_KEY_DEINIT, &key2)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_DEINIT)");
		return 1;
	}

	if (ioctl(cfd, NCRIO_KEY_INIT, &key2)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	memset(&kwrap, 0, sizeof(kwrap));
	kwrap.keytowrap = key2;
	kwrap.io = data;
	kwrap.io_size = data_size;

	if (ioctl(cfd, NCRIO_KEY_STORAGE_UNWRAP, &kwrap)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_STORAGE_UNWRAP)");
		return 1;
	}

	/* now export the unwrapped */
	memset(&keydata, 0, sizeof(keydata));
	keydata.key = key2;
	keydata.data = dd;

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

	kdata.data = data;
	if (ioctl(cfd, NCRIO_DATA_GET, &kdata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_GET)");
		return 1;
	}

	if (kdata.data_size != 16 || memcmp(kdata.data, DKEY, 16) != 0) {
		fprintf(stderr, "Unwrapped data do not match.\n");
		fprintf(stderr, "Data[%d]: ", (int) kdata.data_size);
		for(i=0;i<kdata.data_size;i++)
			fprintf(stderr, "%.2x:", data[i]);
		fprintf(stderr, "\n");
		return 1;
	}

	return 0;

}

struct aes_vectors_st {
	const uint8_t* key;
	const uint8_t* plaintext;
	const uint8_t* ciphertext;
} aes_vectors[] = {
	{
		.key = (uint8_t*)"\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.plaintext = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.ciphertext = (uint8_t*)"\x4b\xc3\xf8\x83\x45\x0c\x11\x3c\x64\xca\x42\xe1\x11\x2a\x9e\x87",
	},
	{
		.key = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.plaintext = (uint8_t*)"\xf3\x44\x81\xec\x3c\xc6\x27\xba\xcd\x5d\xc3\xfb\x08\xf2\x73\xe6",
		.ciphertext = (uint8_t*)"\x03\x36\x76\x3e\x96\x6d\x92\x59\x5a\x56\x7c\xc9\xce\x53\x7f\x5e",
	},
	{
		.key = (uint8_t*)"\x10\xa5\x88\x69\xd7\x4b\xe5\xa3\x74\xcf\x86\x7c\xfb\x47\x38\x59",
		.plaintext = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.ciphertext = (uint8_t*)"\x6d\x25\x1e\x69\x44\xb0\x51\xe0\x4e\xaa\x6f\xb4\xdb\xf7\x84\x65",
	},
	{
		.key = (uint8_t*)"\xca\xea\x65\xcd\xbb\x75\xe9\x16\x9e\xcd\x22\xeb\xe6\xe5\x46\x75",
		.plaintext = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.ciphertext = (uint8_t*)"\x6e\x29\x20\x11\x90\x15\x2d\xf4\xee\x05\x81\x39\xde\xf6\x10\xbb",
	},
	{
		.key = (uint8_t*)"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe",
		.plaintext = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		.ciphertext = (uint8_t*)"\x9b\xa4\xa9\x14\x3f\x4e\x5d\x40\x48\x52\x1c\x4f\x88\x77\xd8\x8e",
	},
};

/* AES cipher */
static int
test_ncr_aes(int cfd)
{
	struct ncr_data_init_st dinit;
	ncr_key_t key;
	struct ncr_key_data_st keydata;
	struct ncr_data_st kdata;
	ncr_data_t dd, dd2;
	uint8_t data[KEY_DATA_SIZE];
	int i, j;
	struct ncr_session_once_op_st nop;

	dinit.max_object_size = KEY_DATA_SIZE;
	dinit.flags = NCR_DATA_FLAG_EXPORTABLE;
	dinit.initial_data = NULL;
	dinit.initial_data_size = 0;

	if (ioctl(cfd, NCRIO_DATA_INIT, &dinit)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_INIT)");
		return 1;
	}

	dd = dinit.desc;

	if (ioctl(cfd, NCRIO_DATA_INIT, &dinit)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_INIT)");
		return 1;
	}

	dd2 = dinit.desc;

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
	

	fprintf(stdout, "Tests on AES Encryption\n");
	for (i=0;i<sizeof(aes_vectors)/sizeof(aes_vectors[0]);i++) {

		/* import key */
		kdata.data = (void*)aes_vectors[i].key;
		kdata.data_size = 16;
		kdata.desc = dd;

		if (ioctl(cfd, NCRIO_DATA_SET, &kdata)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_DATA_SET)");
			return 1;
		}

		keydata.key = key;
		keydata.data = dd;
		if (ioctl(cfd, NCRIO_KEY_IMPORT, &keydata)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_KEY_IMPORT)");
			return 1;
		}
		/* import data */

		kdata.data = (void*)aes_vectors[i].plaintext;
		kdata.data_size = 16;
		kdata.desc = dd;

		if (ioctl(cfd, NCRIO_DATA_SET, &kdata)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_DATA_SET)");
			return 1;
		}

		/* encrypt */
		memset(&nop, 0, sizeof(nop));
		nop.init.algorithm = NCR_ALG_AES_ECB;
		nop.init.key = key;
		nop.init.op = NCR_OP_ENCRYPT;
		nop.op.data.ndata.input = dd;
		nop.op.data.ndata.output = dd2;
		nop.op.type = NCR_DATA;

		if (ioctl(cfd, NCRIO_SESSION_ONCE, &nop)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_SESSION_ONCE)");
			return 1;
		}

		/* verify */
		kdata.desc = dd2;
		kdata.data = data;
		kdata.data_size = sizeof(data);

		if (ioctl(cfd, NCRIO_DATA_GET, &kdata)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_DATA_GET)");
			return 1;
		}

		if (kdata.data_size != 16 || memcmp(kdata.data, aes_vectors[i].ciphertext, 16) != 0) {
			fprintf(stderr, "AES test vector %d failed!\n", i);

			fprintf(stderr, "Cipher[%d]: ", (int)kdata.data_size);
			for(j=0;j<kdata.data_size;j++)
			  fprintf(stderr, "%.2x:", (int)data[j]);
			fprintf(stderr, "\n");

			fprintf(stderr, "Expected[%d]: ", 16);
			for(j=0;j<16;j++)
			  fprintf(stderr, "%.2x:", (int)aes_vectors[i].ciphertext[j]);
			fprintf(stderr, "\n");
			return 1;
		}
	}

	fprintf(stdout, "Tests on AES Decryption\n");
	for (i=0;i<sizeof(aes_vectors)/sizeof(aes_vectors[0]);i++) {

		/* import key */
		kdata.data = (void*)aes_vectors[i].key;
		kdata.data_size = 16;
		kdata.desc = dd;

		if (ioctl(cfd, NCRIO_DATA_SET, &kdata)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_DATA_SET)");
			return 1;
		}

		keydata.key = key;
		keydata.data = dd;
		if (ioctl(cfd, NCRIO_KEY_IMPORT, &keydata)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_KEY_IMPORT)");
			return 1;
		}

		/* import ciphertext */

		kdata.data = (void*)aes_vectors[i].ciphertext;
		kdata.data_size = 16;
		kdata.desc = dd;

		if (ioctl(cfd, NCRIO_DATA_SET, &kdata)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_DATA_SET)");
			return 1;
		}

		/* decrypt */
		memset(&nop, 0, sizeof(nop));
		nop.init.algorithm = NCR_ALG_AES_ECB;
		nop.init.key = key;
		nop.init.op = NCR_OP_DECRYPT;
		nop.op.data.ndata.input = dd;
		nop.op.data.ndata.output = dd2;
		nop.op.type = NCR_DATA;

		if (ioctl(cfd, NCRIO_SESSION_ONCE, &nop)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_SESSION_ONCE)");
			return 1;
		}

		/* verify */
		kdata.desc = dd2;
		kdata.data = data;
		kdata.data_size = sizeof(data);

		if (ioctl(cfd, NCRIO_DATA_GET, &kdata)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_DATA_GET)");
			return 1;
		}

		if (kdata.data_size != 16 || memcmp(kdata.data, aes_vectors[i].plaintext, 16) != 0) {
			fprintf(stderr, "AES test vector %d failed!\n", i);

			fprintf(stderr, "Plain[%d]: ", (int)kdata.data_size);
			for(j=0;j<kdata.data_size;j++)
			  fprintf(stderr, "%.2x:", (int)data[j]);
			fprintf(stderr, "\n");

			fprintf(stderr, "Expected[%d]: ", 16);
			for(j=0;j<16;j++)
			  fprintf(stderr, "%.2x:", (int)aes_vectors[i].plaintext[j]);
			fprintf(stderr, "\n");
			return 1;
		}
	}


	fprintf(stdout, "\n");

	return 0;

}

struct hash_vectors_st {
	const char* name;
	ncr_algorithm_t algorithm;
	const uint8_t* key; /* if hmac */
	int key_size;
	const uint8_t* plaintext;
	int plaintext_size;
	const uint8_t* output;
	int output_size;
	ncr_crypto_op_t op;
} hash_vectors[] = {
	{
		.name = "SHA1",
		.algorithm = NCR_ALG_SHA1,
		.key = NULL,
		.plaintext = (uint8_t*)"what do ya want for nothing?",
		.plaintext_size = sizeof("what do ya want for nothing?")-1,
		.output = (uint8_t*)"\x8f\x82\x03\x94\xf9\x53\x35\x18\x20\x45\xda\x24\xf3\x4d\xe5\x2b\xf8\xbc\x34\x32",
		.output_size = 20,
		.op = NCR_OP_SIGN,
	},
	{
		.name = "HMAC-MD5",
		.algorithm = NCR_ALG_HMAC_MD5,
		.key = (uint8_t*)"Jefe",
		.key_size = 4,
		.plaintext = (uint8_t*)"what do ya want for nothing?",
		.plaintext_size = sizeof("what do ya want for nothing?")-1,
		.output = (uint8_t*)"\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38",
		.output_size = 16,
		.op = NCR_OP_SIGN,
	},
	/* from rfc4231 */
	{
		.name = "HMAC-SHA224",
		.algorithm = NCR_ALG_HMAC_SHA2_224,
		.key = (uint8_t*)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
		.key_size = 20,
		.plaintext = (uint8_t*)"Hi There",
		.plaintext_size = sizeof("Hi There")-1,
		.output = (uint8_t*)"\x89\x6f\xb1\x12\x8a\xbb\xdf\x19\x68\x32\x10\x7c\xd4\x9d\xf3\x3f\x47\xb4\xb1\x16\x99\x12\xba\x4f\x53\x68\x4b\x22",
		.output_size = 28,
		.op = NCR_OP_SIGN,
	},
	{
		.name = "HMAC-SHA256",
		.algorithm = NCR_ALG_HMAC_SHA2_256,
		.key = (uint8_t*)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
		.key_size = 20,
		.plaintext = (uint8_t*)"Hi There",
		.plaintext_size = sizeof("Hi There")-1,
		.output = (uint8_t*)"\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7",
		.output_size = 32,
		.op = NCR_OP_SIGN,
	},
	{
		.name = "HMAC-SHA384",
		.algorithm = NCR_ALG_HMAC_SHA2_384,
		.key = (uint8_t*)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
		.key_size = 20,
		.plaintext = (uint8_t*)"Hi There",
		.plaintext_size = sizeof("Hi There")-1,
		.output = (uint8_t*)"\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90\x7f\x15\xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c\xfa\xea\x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2\xfa\x9c\xb6",
		.output_size = 48,
		.op = NCR_OP_SIGN,
	},
	{
		.name = "HMAC-SHA512",
		.algorithm = NCR_ALG_HMAC_SHA2_512,
		.key = (uint8_t*)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
		.key_size = 20,
		.plaintext = (uint8_t*)"Hi There",
		.plaintext_size = sizeof("Hi There")-1,
		.output = (uint8_t*)"\x87\xaa\x7c\xde\xa5\xef\x61\x9d\x4f\xf0\xb4\x24\x1a\x1d\x6c\xb0\x23\x79\xf4\xe2\xce\x4e\xc2\x78\x7a\xd0\xb3\x05\x45\xe1\x7c\xde\xda\xa8\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\xae\xa3\xf4\xe4\xbe\x9d\x91\x4e\xeb\x61\xf1\x70\x2e\x69\x6c\x20\x3a\x12\x68\x54",
		.output_size = 64,
		.op = NCR_OP_SIGN,
	},
};

#define HASH_DATA_SIZE 64

/* SHA1 and other hashes */
static int
test_ncr_hash(int cfd)
{
	struct ncr_data_init_st dinit;
	ncr_key_t key;
	struct ncr_key_data_st keydata;
	struct ncr_data_st kdata;
	ncr_data_t dd, dd2;
	uint8_t data[HASH_DATA_SIZE];
	int i, j;
	struct ncr_session_once_op_st nop;

	dinit.max_object_size = HASH_DATA_SIZE;
	dinit.flags = NCR_DATA_FLAG_EXPORTABLE;
	dinit.initial_data = NULL;
	dinit.initial_data_size = 0;

	if (ioctl(cfd, NCRIO_DATA_INIT, &dinit)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_INIT)");
		return 1;
	}

	dd = dinit.desc;

	if (ioctl(cfd, NCRIO_DATA_INIT, &dinit)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_INIT)");
		return 1;
	}

	dd2 = dinit.desc;

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
	

	fprintf(stdout, "Tests on Hashes\n");
	for (i=0;i<sizeof(hash_vectors)/sizeof(hash_vectors[0]);i++) {

		fprintf(stdout, "\t%s:\n", hash_vectors[i].name);
		/* import key */
		if (hash_vectors[i].key != NULL) {
			kdata.data = (void*)hash_vectors[i].key;
			kdata.data_size = hash_vectors[i].key_size;
			kdata.desc = dd;

			if (ioctl(cfd, NCRIO_DATA_SET, &kdata)) {
				fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
				perror("ioctl(NCRIO_DATA_SET)");
				return 1;
			}

			keydata.key = key;
			keydata.data = dd;
			if (ioctl(cfd, NCRIO_KEY_IMPORT, &keydata)) {
				fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
				perror("ioctl(NCRIO_KEY_IMPORT)");
				return 1;
			}
		}
		/* import data */

		kdata.data = (void*)hash_vectors[i].plaintext;
		kdata.data_size = hash_vectors[i].plaintext_size;
		kdata.desc = dd;

		if (ioctl(cfd, NCRIO_DATA_SET, &kdata)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_DATA_SET)");
			return 1;
		}

		/* encrypt */
		memset(&nop, 0, sizeof(nop));
		nop.init.algorithm = hash_vectors[i].algorithm;
		if (hash_vectors[i].key != NULL)
			nop.init.key = key;
		nop.init.op = hash_vectors[i].op;
		nop.op.data.ndata.input = dd;
		nop.op.data.ndata.output = dd2;
		nop.op.type = NCR_DATA;

		if (ioctl(cfd, NCRIO_SESSION_ONCE, &nop)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_SESSION_ONCE)");
			return 1;
		}

		/* verify */
		memset(&kdata, 0, sizeof(kdata));
		kdata.desc = dd2;
		kdata.data = data;
		kdata.data_size = sizeof(data);

		if (ioctl(cfd, NCRIO_DATA_GET, &kdata)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_DATA_GET)");
			return 1;
		}

		if (kdata.data_size != hash_vectors[i].output_size ||
			memcmp(kdata.data, hash_vectors[i].output, hash_vectors[i].output_size) != 0) {
			fprintf(stderr, "HASH test vector %d failed!\n", i);

			fprintf(stderr, "Output[%d]: ", (int)kdata.data_size);
			for(j=0;j<kdata.data_size;j++)
			  fprintf(stderr, "%.2x:", (int)data[j]);
			fprintf(stderr, "\n");

			fprintf(stderr, "Expected[%d]: ", hash_vectors[i].output_size);
			for(j=0;j<hash_vectors[i].output_size;j++)
			  fprintf(stderr, "%.2x:", (int)hash_vectors[i].output[j]);
			fprintf(stderr, "\n");
			return 1;
		}
	}

	fprintf(stdout, "\n");

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

	if (test_ncr_aes(fd))
		return 1;

	if (test_ncr_hash(fd))
		return 1;

	if (test_ncr_wrap_key(fd))
		return 1;

	if (test_ncr_store_wrap_key(fd))
		return 1;

	/* Close the original descriptor */
	if (close(fd)) {
		perror("close(fd)");
		return 1;
	}

	return 0;
}
