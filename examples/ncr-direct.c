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
#define KEY_DATA_SIZE 16


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

		/* encrypt */
		memset(&nop, 0, sizeof(nop));
		nop.init.algorithm = NCR_ALG_AES_ECB;
		nop.init.key = key;
		nop.init.op = NCR_OP_ENCRYPT;
		nop.op.data.udata.input = (void*)aes_vectors[i].plaintext;
		nop.op.data.udata.input_size = 16;
		nop.op.data.udata.output = data;
		nop.op.data.udata.output_size = sizeof(data);
		nop.op.type = NCR_DIRECT_DATA;

		if (ioctl(cfd, NCRIO_SESSION_ONCE, &nop)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_SESSION_ONCE)");
			return 1;
		}

		/* verify */

		if (nop.op.data.udata.output_size != 16 || memcmp(data, aes_vectors[i].ciphertext, 16) != 0) {
			fprintf(stderr, "AES test vector %d failed!\n", i);

			fprintf(stderr, "Cipher[%d]: ", (int)nop.op.data.udata.output_size);
			for(j=0;j<nop.op.data.udata.output_size;j++)
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


		/* decrypt */
		memset(&nop, 0, sizeof(nop));
		nop.init.algorithm = NCR_ALG_AES_ECB;
		nop.init.key = key;
		nop.init.op = NCR_OP_DECRYPT;
		nop.op.data.udata.input = (void*)aes_vectors[i].ciphertext;
		nop.op.data.udata.input_size = 16;
		nop.op.data.udata.output = data;
		nop.op.data.udata.output_size = sizeof(data);
		nop.op.type = NCR_DIRECT_DATA;

		if (ioctl(cfd, NCRIO_SESSION_ONCE, &nop)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_SESSION_ONCE)");
			return 1;
		}

		if (nop.op.data.udata.output_size != 16 || memcmp(data, aes_vectors[i].plaintext, 16) != 0) {
			fprintf(stderr, "AES test vector %d failed!\n", i);

			fprintf(stderr, "Plain[%d]: ", (int)nop.op.data.udata.output_size);
			for(j=0;j<nop.op.data.udata.output_size;j++)
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

		/* encrypt */
		memset(&nop, 0, sizeof(nop));
		nop.init.algorithm = hash_vectors[i].algorithm;
		if (hash_vectors[i].key != NULL)
			nop.init.key = key;
		nop.init.op = hash_vectors[i].op;
		nop.op.data.udata.input =  (void*)hash_vectors[i].plaintext;
		nop.op.data.udata.input_size = hash_vectors[i].plaintext_size;
		nop.op.data.udata.output = data;
		nop.op.data.udata.output_size = sizeof(data);
		nop.op.type = NCR_DIRECT_DATA;

		if (ioctl(cfd, NCRIO_SESSION_ONCE, &nop)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_SESSION_ONCE)");
			return 1;
		}

		if (nop.op.data.udata.output_size != hash_vectors[i].output_size ||
			memcmp(data, hash_vectors[i].output, hash_vectors[i].output_size) != 0) {
			fprintf(stderr, "HASH test vector %d failed!\n", i);

			fprintf(stderr, "Output[%d]: ", (int)nop.op.data.udata.output_size);
			for(j=0;j<nop.op.data.udata.output_size;j++)
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

	if (test_ncr_aes(fd))
		return 1;

	if (test_ncr_hash(fd))
		return 1;

	/* Close the original descriptor */
	if (close(fd)) {
		perror("close(fd)");
		return 1;
	}

	return 0;
}
