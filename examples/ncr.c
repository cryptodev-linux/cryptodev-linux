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
#include <sys/socket.h>
#include <linux/netlink.h>
#include "../ncr.h"
#include <stdlib.h>

#define DATA_SIZE 4096

#define ALIGN_NL __attribute__((aligned(NLA_ALIGNTO)))

#define ALG_AES_CBC "cbc(aes)"
#define ALG_AES_ECB "ecb(aes)"

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
	struct __attribute__((packed)) {
		struct ncr_key_generate f;
		struct nlattr algo_head ALIGN_NL;
		char algo[sizeof(ALG_AES_CBC)] ALIGN_NL;
		struct nlattr flags_head ALIGN_NL;
		uint32_t flags ALIGN_NL;
		struct nlattr bits_head ALIGN_NL;
		uint32_t bits ALIGN_NL;
	} kgen;
	struct __attribute__((packed)) {
		struct ncr_key_get_info f;
		/* This union is only here to stop gcc from complaining about
		   aliasing. */
		union {
			unsigned char __reserve[DATA_SIZE];
			struct nlattr first_header;
		} u ALIGN_NL;
	} kinfo;
	struct nlattr *nla;
	ncr_key_t key;
	struct __attribute__((packed)) {
		struct ncr_key_import f;
		struct nlattr id_head ALIGN_NL;
		uint8_t id[2] ALIGN_NL;
		struct nlattr type_head ALIGN_NL;
		uint32_t type ALIGN_NL;
		struct nlattr algo_head ALIGN_NL;
		char algo[sizeof(ALG_AES_CBC)] ALIGN_NL;
		struct nlattr flags_head ALIGN_NL;
		uint32_t flags ALIGN_NL;
	} kimport;
	struct ncr_key_export kexport;
	uint8_t data[KEY_DATA_SIZE];
	uint8_t data_bak[KEY_DATA_SIZE];
	uint16_t *attr_p;
	int got_algo, got_flags, got_type;

	fprintf(stdout, "Tests on Keys:\n");

	/* test 1: generate a key in userspace import it
	 * to kernel via data and export it.
	 */

	fprintf(stdout, "\tKey generation...\n");

	randomize_data(data, sizeof(data));
	memcpy(data_bak, data, sizeof(data));

	/* convert it to key */
	key = ioctl(cfd, NCRIO_KEY_INIT);
	if (key == -1) {
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	memset(&kimport.f, 0, sizeof(kimport.f));
	kimport.f.input_size = sizeof(kimport);
	kimport.f.key = key;
	kimport.f.data = data;
	kimport.f.data_size = sizeof(data);
	kimport.id_head.nla_len = NLA_HDRLEN + sizeof(kimport.id);
	kimport.id_head.nla_type = NCR_ATTR_KEY_ID;
	kimport.id[0] = 'a';
	kimport.id[1] = 'b';
	kimport.type_head.nla_len = NLA_HDRLEN + sizeof(kimport.type);
	kimport.type_head.nla_type = NCR_ATTR_KEY_TYPE;
	kimport.type = NCR_KEY_TYPE_SECRET;
	kimport.algo_head.nla_len = NLA_HDRLEN + sizeof(kimport.algo);
	kimport.algo_head.nla_type = NCR_ATTR_ALGORITHM;
	strcpy(kimport.algo, ALG_AES_CBC);
	kimport.flags_head.nla_len = NLA_HDRLEN + sizeof(kimport.flags);
	kimport.flags_head.nla_type = NCR_ATTR_KEY_FLAGS;
	kimport.flags = NCR_KEY_FLAG_EXPORTABLE;

	if (ioctl(cfd, NCRIO_KEY_IMPORT, &kimport)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

	/* now try to read it */
	fprintf(stdout, "\tKey export...\n");

	memset(&kexport, 0, sizeof(kexport));
	kexport.key = key;
	kexport.buffer = data;
	kexport.buffer_size = sizeof(data);

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &kexport) != sizeof(data)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_EXPORT)");
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
	key = ioctl(cfd, NCRIO_KEY_INIT);
	if (key == -1) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	memset(&kgen.f, 0, sizeof(kgen.f));
	kgen.f.input_size = sizeof(kgen);
	kgen.f.key = key;
	kgen.algo_head.nla_len = NLA_HDRLEN + sizeof(kgen.algo);
	kgen.algo_head.nla_type = NCR_ATTR_ALGORITHM;
	strcpy(kgen.algo, ALG_AES_CBC);
	kgen.flags_head.nla_len = NLA_HDRLEN + sizeof(kgen.flags);
	kgen.flags_head.nla_type = NCR_ATTR_KEY_FLAGS;
	kgen.flags = NCR_KEY_FLAG_EXPORTABLE;
	kgen.bits_head.nla_len = NLA_HDRLEN + sizeof(kgen.bits);
	kgen.bits_head.nla_type = NCR_ATTR_SECRET_KEY_BITS;
	kgen.bits = 128; /* 16 bytes */

	if (ioctl(cfd, NCRIO_KEY_GENERATE, &kgen)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_GENERATE)");
		return 1;
	}

	memset(data, 0, sizeof(data));

	memset(&kexport, 0, sizeof(kexport));
	kexport.key = key;
	kexport.buffer = data;
	kexport.buffer_size = sizeof(data);

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &kexport) != sizeof(data)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_EXPORT)");
		return 1;
	}

	if (data[0] == 0 && data[1] == 0 && data[2] == 0 && data[4] == 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		fprintf(stderr, "Generated key: %.2x.%.2x.%.2x.%.2x.%.2x.%.2x.%.2x.%.2x."
			"%.2x.%.2x.%.2x.%.2x.%.2x.%.2x.%.2x.%.2x\n", data[0], data[1],
			data[2], data[3], data[4], data[5], data[6], data[7], data[8],
			data[9], data[10], data[11], data[12], data[13], data[14],
			data[15]);
		return 1;
	}

	memset(&kinfo.f, 0, sizeof(kinfo.f));
	kinfo.f.output_size = sizeof(kinfo);
	kinfo.f.key = key;
	nla = &kinfo.u.first_header;
	nla->nla_type = NCR_ATTR_WANTED_ATTRS;
	attr_p = (uint16_t *)((char *)nla + NLA_HDRLEN);
	*attr_p++ = NCR_ATTR_ALGORITHM;
	*attr_p++ = NCR_ATTR_KEY_FLAGS;
	*attr_p++ = NCR_ATTR_KEY_TYPE;
	nla->nla_len = (char *)attr_p - (char *)nla;
	kinfo.f.input_size = (char *)attr_p - (char *)&kinfo;

	if (ioctl(cfd, NCRIO_KEY_GET_INFO, &kinfo)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_GET_INFO)");
		return 1;
	}

	got_algo = got_flags = got_type = 0;
	if (kinfo.f.output_size <
	    (char *)&kinfo.u.first_header - (char *)&kinfo) {
		fprintf(stderr, "No nlattr returned\n");
		return 1;
	}
	nla = &kinfo.u.first_header;
	for (;;) {
		void *data;

		if (nla->nla_len >
		    kinfo.f.output_size - ((char *)nla - (char *)&kinfo)) {
			fprintf(stderr, "Attributes overflow\n");
			return 1;
		}
		data = (char *)nla + NLA_HDRLEN;
		switch (nla->nla_type) {
		case NCR_ATTR_ALGORITHM:
			if (nla->nla_len < NLA_HDRLEN + 1) {
				fprintf(stderr, "Attribute too small\n");
				return 1;
			}
			if (((char *)data)[nla->nla_len - NLA_HDRLEN - 1]
			    != 0) {
				fprintf(stderr, "NUL missing\n");
				return 1;
			}
			if (strcmp(data, ALG_AES_CBC) != 0) {
				fprintf(stderr, "Unexpected algorithm\n");
				return 1;
			}
			got_algo++;
			break;
		case NCR_ATTR_KEY_FLAGS:
			if (nla->nla_len < NLA_HDRLEN + sizeof(uint32_t)) {
				fprintf(stderr, "Attribute too small\n");
				return 1;
			}
			if (*(uint32_t *)data != NCR_KEY_FLAG_EXPORTABLE) {
				fprintf(stderr, "Unexpected key flags\n");
				return 1;
			}
			got_flags++;
			break;
		case NCR_ATTR_KEY_TYPE:
			if (nla->nla_len < NLA_HDRLEN + sizeof(uint32_t)) {
				fprintf(stderr, "Attribute too small\n");
				return 1;
			}
			if (*(uint32_t *)data != NCR_KEY_TYPE_SECRET) {
				fprintf(stderr, "Unexpected key type\n");
				return 1;
			}
			got_type++;
			break;
		}

		if (NLA_ALIGN(nla->nla_len) + NLA_HDRLEN >
		    kinfo.f.output_size - ((char *)nla - (char *)&kinfo))
			break;
		nla = (struct nlattr *)((char *)nla + NLA_ALIGN(nla->nla_len));
	}
	if (got_algo != 1 || got_flags != 1 || got_type != 1) {
		fprintf(stderr, "Unexpected attrs - %d, %d, %d\n", got_algo,
			got_flags, got_type);
		return 1;
	}

	if (ioctl(cfd, NCRIO_KEY_DEINIT, &key)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_DEINIT)");
		return 1;
	}
	
	/* test 3: generate an unexportable key in kernel space and
	 * try to export it.
	 */
	fprintf(stdout, "\tKey protection of non-exportable keys...\n");
	key = ioctl(cfd, NCRIO_KEY_INIT);
	if (key == -1) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	memset(&kgen.f, 0, sizeof(kgen.f));
	kgen.f.input_size = sizeof(kgen);
	kgen.f.key = key;
	kgen.algo_head.nla_len = NLA_HDRLEN + sizeof(kgen.algo);
	kgen.algo_head.nla_type = NCR_ATTR_ALGORITHM;
	strcpy(kgen.algo, ALG_AES_CBC);
	kgen.flags_head.nla_len = NLA_HDRLEN + sizeof(kgen.flags);
	kgen.flags_head.nla_type = NCR_ATTR_KEY_FLAGS;
	kgen.flags = 0;
	kgen.bits_head.nla_len = NLA_HDRLEN + sizeof(kgen.flags);
	kgen.bits_head.nla_type = NCR_ATTR_SECRET_KEY_BITS;
	kgen.bits = 128; /* 16 bytes */

	if (ioctl(cfd, NCRIO_KEY_GENERATE, &kgen)) {
		perror("ioctl(NCRIO_KEY_GENERATE)");
		return 1;
	}

	memset(data, 0, sizeof(data));

	memset(&kexport, 0, sizeof(kexport));
	kexport.key = key;
	kexport.buffer = data;
	kexport.buffer_size = sizeof(data);

	/* try to get the output data - should fail */

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &kexport) >= 0) {
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



/* Key wrapping */
static int
test_ncr_wrap_key(int cfd)
{
	int i, ret;
	ncr_key_t key, key2;
	struct __attribute__((packed)) {
		struct ncr_key_import f;
		struct nlattr id_head ALIGN_NL;
		uint8_t id[2] ALIGN_NL;
		struct nlattr type_head ALIGN_NL;
		uint32_t type ALIGN_NL;
		struct nlattr algo_head ALIGN_NL;
		char algo[sizeof(ALG_AES_CBC)] ALIGN_NL;
		struct nlattr flags_head ALIGN_NL;
		uint32_t flags ALIGN_NL;
	} kimport;
	struct __attribute__((packed)) {
		struct ncr_key_wrap f;
		struct nlattr algo_head ALIGN_NL;
		char algo[sizeof(NCR_WALG_AES_RFC3394)] ALIGN_NL;
	} kwrap;
	struct __attribute__((packed)) {
		struct ncr_key_unwrap f;
		struct nlattr wrap_algo_head ALIGN_NL;
		char wrap_algo[sizeof(NCR_WALG_AES_RFC3394)] ALIGN_NL;
		struct nlattr flags_head ALIGN_NL;
		uint32_t flags ALIGN_NL;
	} kunwrap;
	uint8_t data[WRAPPED_KEY_DATA_SIZE];
	int data_size;

	fprintf(stdout, "Tests on Keys:\n");

	/* test 1: generate a key in userspace import it
	 * to kernel via data and export it.
	 */

	fprintf(stdout, "\tKey Wrap test...\n");

	/* convert it to key */
	key = ioctl(cfd, NCRIO_KEY_INIT);
	if (key == -1) {
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	memset(&kimport.f, 0, sizeof(kimport.f));
	kimport.f.input_size = sizeof(kimport);
	kimport.f.key = key;
	kimport.f.data = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
	kimport.f.data_size = 16;
	kimport.id_head.nla_len = NLA_HDRLEN + sizeof(kimport.id);
	kimport.id_head.nla_type = NCR_ATTR_KEY_ID;
	kimport.id[0] = 'a';
	kimport.id[1] = 'b';
	kimport.type_head.nla_len = NLA_HDRLEN + sizeof(kimport.type);
	kimport.type_head.nla_type = NCR_ATTR_KEY_TYPE;
	kimport.type = NCR_KEY_TYPE_SECRET;
	kimport.algo_head.nla_len = NLA_HDRLEN + sizeof(kimport.algo);
	kimport.algo_head.nla_type = NCR_ATTR_ALGORITHM;
	strcpy(kimport.algo, ALG_AES_CBC);
	kimport.flags_head.nla_len = NLA_HDRLEN + sizeof(kimport.flags);
	kimport.flags_head.nla_type = NCR_ATTR_KEY_FLAGS;
	kimport.flags = NCR_KEY_FLAG_EXPORTABLE|NCR_KEY_FLAG_WRAPPING|NCR_KEY_FLAG_UNWRAPPING;

	ret = ioctl(cfd, NCRIO_KEY_IMPORT, &kimport);
	if (geteuid() == 0 && ret) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

	if (geteuid() != 0) {
		/* cannot test further */
		fprintf(stdout, "\t(Wrapping test not completed. Run as root)\n");
		return 0;
	}

	/* convert it to key */
	key2 = ioctl(cfd, NCRIO_KEY_INIT);
	if (key2 == -1) {
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	memset(&kimport.f, 0, sizeof(kimport.f));
	kimport.f.input_size = sizeof(kimport);
	kimport.f.key = key2;
#define DKEY "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"
	kimport.f.data = DKEY;
	kimport.f.data_size = 16;
	kimport.id_head.nla_len = NLA_HDRLEN + sizeof(kimport.id);
	kimport.id_head.nla_type = NCR_ATTR_KEY_ID;
	kimport.id[0] = 'b';
	kimport.id[1] = 'a';
	kimport.type_head.nla_len = NLA_HDRLEN + sizeof(kimport.type);
	kimport.type_head.nla_type = NCR_ATTR_KEY_TYPE;
	kimport.type = NCR_KEY_TYPE_SECRET;
	kimport.algo_head.nla_len = NLA_HDRLEN + sizeof(kimport.algo);
	kimport.algo_head.nla_type = NCR_ATTR_ALGORITHM;
	strcpy(kimport.algo, ALG_AES_CBC);
	kimport.flags_head.nla_len = NLA_HDRLEN + sizeof(kimport.flags);
	kimport.flags_head.nla_type = NCR_ATTR_KEY_FLAGS;
	kimport.flags = NCR_KEY_FLAG_EXPORTABLE|NCR_KEY_FLAG_WRAPPABLE;

	if (ioctl(cfd, NCRIO_KEY_IMPORT, &kimport)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

	/* now try wrapping key2 using key */
	memset(&kwrap.f, 0, sizeof(kwrap.f));
	kwrap.f.input_size = sizeof(kwrap);
	kwrap.f.wrapping_key = key;
	kwrap.f.source_key = key2;
	kwrap.f.buffer = data;
	kwrap.f.buffer_size = sizeof(data);
	kwrap.algo_head.nla_len = NLA_HDRLEN + sizeof(kwrap.algo);
	kwrap.algo_head.nla_type = NCR_ATTR_WRAPPING_ALGORITHM;
	strcpy(kwrap.algo, NCR_WALG_AES_RFC3394);

	data_size = ioctl(cfd, NCRIO_KEY_WRAP, &kwrap);
	if (data_size < 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_WRAP)");
		return 1;
	}

	if (data_size != 24 || memcmp(data,
		"\x1F\xA6\x8B\x0A\x81\x12\xB4\x47\xAE\xF3\x4B\xD8\xFB\x5A\x7B\x82\x9D\x3E\x86\x23\x71\xD2\xCF\xE5", 24) != 0) {
		fprintf(stderr, "Wrapped data do not match.\n");

		fprintf(stderr, "Data[%d]: ",(int) data_size);
		for(i=0;i<data_size;i++)
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

	key2 = ioctl(cfd, NCRIO_KEY_INIT);
	if (key2 == -1) {
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	memset(&kunwrap.f, 0, sizeof(kunwrap.f));
	kunwrap.f.input_size = sizeof(kunwrap);
	kunwrap.f.wrapping_key = key;
	kunwrap.f.dest_key = key2;
	kunwrap.f.data = data;
	kunwrap.f.data_size = data_size;
	kunwrap.wrap_algo_head.nla_len = NLA_HDRLEN + sizeof(kunwrap.wrap_algo);
	kunwrap.wrap_algo_head.nla_type = NCR_ATTR_WRAPPING_ALGORITHM;
	strcpy(kunwrap.wrap_algo, NCR_WALG_AES_RFC3394);
	kunwrap.flags_head.nla_len = NLA_HDRLEN + sizeof(kunwrap.flags);
	kunwrap.flags_head.nla_type = NCR_ATTR_KEY_FLAGS;
	kunwrap.flags = NCR_KEY_FLAG_EXPORTABLE|NCR_KEY_FLAG_WRAPPABLE;

	if (ioctl(cfd, NCRIO_KEY_UNWRAP, &kunwrap)) {
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

/* check whether wrapping of long keys is not allowed with
 * shorted wrapping keys */
static int
test_ncr_wrap_key2(int cfd)
{
	int ret;
	ncr_key_t key, key2;
	struct __attribute__((packed)) {
		struct ncr_key_import f;
		struct nlattr id_head ALIGN_NL;
		uint8_t id[2] ALIGN_NL;
		struct nlattr type_head ALIGN_NL;
		uint32_t type ALIGN_NL;
		struct nlattr algo_head ALIGN_NL;
		char algo[sizeof(ALG_AES_CBC)] ALIGN_NL;
		struct nlattr flags_head ALIGN_NL;
		uint32_t flags ALIGN_NL;
	} kimport;
	struct __attribute__((packed)) {
		struct ncr_key_wrap f;
		struct nlattr algo_head ALIGN_NL;
		char algo[sizeof(NCR_WALG_AES_RFC3394)] ALIGN_NL;
	} kwrap;
	uint8_t data[WRAPPED_KEY_DATA_SIZE];

	/* test 1: generate a key in userspace import it
	 * to kernel via data and export it.
	 */

	fprintf(stdout, "\tKey Wrap test II...\n");

	if (geteuid() != 0) {
		/* cannot test further */
		fprintf(stdout, "\t(Wrapping test not completed. Run as root)\n");
		return 0;
	}

	/* convert it to key */
	key = ioctl(cfd, NCRIO_KEY_INIT);
	if (key == -1) {
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	memset(&kimport.f, 0, sizeof(kimport.f));
	kimport.f.input_size = sizeof(kimport);
	kimport.f.key = key;
	kimport.f.data = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
	kimport.f.data_size = 16;
	kimport.id_head.nla_len = NLA_HDRLEN + sizeof(kimport.id);
	kimport.id_head.nla_type = NCR_ATTR_KEY_ID;
	kimport.id[0] = 'a';
	kimport.id[1] = 'b';
	kimport.type_head.nla_len = NLA_HDRLEN + sizeof(kimport.type);
	kimport.type_head.nla_type = NCR_ATTR_KEY_TYPE;
	kimport.type = NCR_KEY_TYPE_SECRET;
	kimport.algo_head.nla_len = NLA_HDRLEN + sizeof(kimport.algo);
	kimport.algo_head.nla_type = NCR_ATTR_ALGORITHM;
	strcpy(kimport.algo, ALG_AES_CBC);
	kimport.flags_head.nla_len = NLA_HDRLEN + sizeof(kimport.flags);
	kimport.flags_head.nla_type = NCR_ATTR_KEY_FLAGS;
	kimport.flags = NCR_KEY_FLAG_EXPORTABLE|NCR_KEY_FLAG_WRAPPING|NCR_KEY_FLAG_UNWRAPPING;

	if (ioctl(cfd, NCRIO_KEY_IMPORT, &kimport)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}


	/* convert it to key */
	key2 = ioctl(cfd, NCRIO_KEY_INIT);
	if (key2 == -1) {
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	memset(&kimport.f, 0, sizeof(kimport.f));
	kimport.f.input_size = sizeof(kimport);
	kimport.f.key = key2;
	kimport.f.data = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF";
	kimport.f.data_size = 32;
	kimport.id_head.nla_len = NLA_HDRLEN + sizeof(kimport.id);
	kimport.id_head.nla_type = NCR_ATTR_KEY_ID;
	kimport.id[0] = 'b';
	kimport.id[1] = 'a';
	kimport.type_head.nla_len = NLA_HDRLEN + sizeof(kimport.type);
	kimport.type_head.nla_type = NCR_ATTR_KEY_TYPE;
	kimport.type = NCR_KEY_TYPE_SECRET;
	kimport.algo_head.nla_len = NLA_HDRLEN + sizeof(kimport.algo);
	kimport.algo_head.nla_type = NCR_ATTR_ALGORITHM;
	strcpy(kimport.algo, ALG_AES_CBC);
	kimport.flags_head.nla_len = NLA_HDRLEN + sizeof(kimport.flags);
	kimport.flags_head.nla_type = NCR_ATTR_KEY_FLAGS;
	kimport.flags = NCR_KEY_FLAG_EXPORTABLE|NCR_KEY_FLAG_WRAPPABLE;

	if (ioctl(cfd, NCRIO_KEY_IMPORT, &kimport)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

	/* now try wrapping key2 using key */
	memset(&kwrap.f, 0, sizeof(kwrap.f));
	kwrap.f.input_size = sizeof(kwrap);
	kwrap.f.wrapping_key = key;
	kwrap.f.source_key = key2;
	kwrap.f.buffer = data;
	kwrap.f.buffer_size = sizeof(data);
	kwrap.algo_head.nla_len = NLA_HDRLEN + sizeof(kwrap.algo);
	kwrap.algo_head.nla_type = NCR_ATTR_WRAPPING_ALGORITHM;
	strcpy(kwrap.algo, NCR_WALG_AES_RFC3394);

	ret = ioctl(cfd, NCRIO_KEY_WRAP, &kwrap);
	if (ret >= 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		/* wrapping shouldn't have been allowed */
		return 1;
	}
	
	return 0;
}

static int
test_ncr_store_wrap_key(int cfd)
{
	int i;
	ncr_key_t key2;
	struct __attribute__((packed)) {
		struct ncr_key_import f;
		struct nlattr id_head ALIGN_NL;
		uint8_t id[2] ALIGN_NL;
		struct nlattr type_head ALIGN_NL;
		uint32_t type ALIGN_NL;
		struct nlattr algo_head ALIGN_NL;
		char algo[sizeof(ALG_AES_CBC)] ALIGN_NL;
		struct nlattr flags_head ALIGN_NL;
		uint32_t flags ALIGN_NL;
	} kimport;
	struct ncr_key_export kexport;
	struct ncr_key_storage_wrap kwrap;
	struct ncr_key_storage_unwrap kunwrap;
	uint8_t data[DATA_SIZE];
	int data_size;

	fprintf(stdout, "Tests on Key storage:\n");

	/* test 1: generate a key in userspace import it
	 * to kernel via data and export it.
	 */

	fprintf(stdout, "\tKey Storage wrap test...\n");

	/* convert it to key */
	key2 = ioctl(cfd, NCRIO_KEY_INIT);
	if (key2 == -1) {
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	memset(&kimport.f, 0, sizeof(kimport.f));
	kimport.f.input_size = sizeof(kimport);
	kimport.f.key = key2;
#define DKEY "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"
	kimport.f.data = DKEY;
	kimport.f.data_size = 16;
	kimport.id_head.nla_len = NLA_HDRLEN + sizeof(kimport.id);
	kimport.id_head.nla_type = NCR_ATTR_KEY_ID;
	kimport.id[0] = 'b';
	kimport.id[1] = 'a';
	kimport.type_head.nla_len = NLA_HDRLEN + sizeof(kimport.type);
	kimport.type_head.nla_type = NCR_ATTR_KEY_TYPE;
	kimport.type = NCR_KEY_TYPE_SECRET;
	kimport.algo_head.nla_len = NLA_HDRLEN + sizeof(kimport.algo);
	kimport.algo_head.nla_type = NCR_ATTR_ALGORITHM;
	strcpy(kimport.algo, ALG_AES_CBC);
	kimport.flags_head.nla_len = NLA_HDRLEN + sizeof(kimport.flags);
	kimport.flags_head.nla_type = NCR_ATTR_KEY_FLAGS;
	kimport.flags = NCR_KEY_FLAG_EXPORTABLE|NCR_KEY_FLAG_WRAPPABLE;

	if (ioctl(cfd, NCRIO_KEY_IMPORT, &kimport)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

	/* now try wrapping key2 using key */
	memset(&kwrap, 0, sizeof(kwrap));
	kwrap.key = key2;
	kwrap.buffer = data;
	kwrap.buffer_size = sizeof(data);

	data_size = ioctl(cfd, NCRIO_KEY_STORAGE_WRAP, &kwrap);
	if (data_size < 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_STORAGE_WRAP)");
		return 1;
	}

	/* test unwrapping */
	fprintf(stdout, "\tKey Storage Unwrap test...\n");

	/* reset key2 */
	if (ioctl(cfd, NCRIO_KEY_DEINIT, &key2)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_DEINIT)");
		return 1;
	}

	key2 = ioctl(cfd, NCRIO_KEY_INIT);
	if (key2 == -1) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	memset(&kunwrap, 0, sizeof(kunwrap));
	kunwrap.key = key2;
	kunwrap.data = data;
	kunwrap.data_size = data_size;

	if (ioctl(cfd, NCRIO_KEY_STORAGE_UNWRAP, &kunwrap)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_STORAGE_UNWRAP)");
		return 1;
	}

	/* now export the unwrapped */
	memset(&kexport, 0, sizeof(kexport));
	kexport.key = key2;
	kexport.buffer = data;
	kexport.buffer_size = sizeof(data);

	data_size = ioctl(cfd, NCRIO_KEY_EXPORT, &kexport);
	if (data_size != 16) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_EXPORT)");
		return 1;
	}

	if (memcmp(data, DKEY, 16) != 0) {
		fprintf(stderr, "Unwrapped data do not match.\n");
		fprintf(stderr, "Data[%d]: ", (int) data_size);
		for(i=0;i<data_size;i++)
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
	ncr_key_t key;
	struct __attribute__((packed)) {
		struct ncr_key_import f;
		struct nlattr id_head ALIGN_NL;
		uint8_t id[2] ALIGN_NL;
		struct nlattr type_head ALIGN_NL;
		uint32_t type ALIGN_NL;
		struct nlattr algo_head ALIGN_NL;
		char algo[sizeof(ALG_AES_ECB)] ALIGN_NL;
		struct nlattr flags_head ALIGN_NL;
		uint32_t flags ALIGN_NL;
	} kimport;
	uint8_t data[KEY_DATA_SIZE];
	int i, j;
	struct __attribute__((packed)) {
		struct ncr_session_once f;
		struct nlattr algo_head ALIGN_NL;
		char algo[sizeof(ALG_AES_ECB)] ALIGN_NL;
		struct nlattr key_head ALIGN_NL;
		uint32_t key ALIGN_NL;
		struct nlattr input_head ALIGN_NL;
		struct ncr_session_input_data input ALIGN_NL;
		struct nlattr output_head ALIGN_NL;
		struct ncr_session_output_buffer output ALIGN_NL;
	} op;
	size_t data_size;

	/* convert it to key */
	key = ioctl(cfd, NCRIO_KEY_INIT);
	if (key == -1) {
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	fprintf(stdout, "Tests on AES Encryption\n");
	for (i=0;i<sizeof(aes_vectors)/sizeof(aes_vectors[0]);i++) {

		memset(&kimport.f, 0, sizeof(kimport.f));
		kimport.f.input_size = sizeof(kimport);
		kimport.f.key = key;
		kimport.f.data = aes_vectors[i].key;
		kimport.f.data_size = 16;
		kimport.id_head.nla_len = NLA_HDRLEN + sizeof(kimport.id);
		kimport.id_head.nla_type = NCR_ATTR_KEY_ID;
		kimport.id[0] = 'a';
		kimport.id[1] = 'b';
		kimport.type_head.nla_len = NLA_HDRLEN + sizeof(kimport.type);
		kimport.type_head.nla_type = NCR_ATTR_KEY_TYPE;
		kimport.type = NCR_KEY_TYPE_SECRET;
		kimport.algo_head.nla_len = NLA_HDRLEN + sizeof(kimport.algo);
		kimport.algo_head.nla_type = NCR_ATTR_ALGORITHM;
		strcpy(kimport.algo, ALG_AES_ECB);
		kimport.flags_head.nla_len = NLA_HDRLEN + sizeof(kimport.flags);
		kimport.flags_head.nla_type = NCR_ATTR_KEY_FLAGS;
		kimport.flags = NCR_KEY_FLAG_EXPORTABLE;
		if (ioctl(cfd, NCRIO_KEY_IMPORT, &kimport)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_KEY_IMPORT)");
			return 1;
		}

		/* encrypt */
		memset(&op.f, 0, sizeof(op.f));
		op.f.input_size = sizeof(op);
		op.f.op = NCR_OP_ENCRYPT;
		op.algo_head.nla_len = NLA_HDRLEN + sizeof(op.algo);
		op.algo_head.nla_type = NCR_ATTR_ALGORITHM;
		strcpy(op.algo, ALG_AES_ECB);
		op.key_head.nla_len = NLA_HDRLEN + sizeof(op.key);
		op.key_head.nla_type = NCR_ATTR_KEY;
		op.key = key;
		op.input_head.nla_len = NLA_HDRLEN + sizeof(op.input);
		op.input_head.nla_type = NCR_ATTR_UPDATE_INPUT_DATA;
		op.input.data = aes_vectors[i].plaintext;
		op.input.data_size = 16;
		op.output_head.nla_len = NLA_HDRLEN + sizeof(op.output);
		op.output_head.nla_type = NCR_ATTR_UPDATE_OUTPUT_BUFFER;
		op.output.buffer = data;
		op.output.buffer_size = sizeof(data);
		op.output.result_size_ptr = &data_size;

		if (ioctl(cfd, NCRIO_SESSION_ONCE, &op)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_SESSION_ONCE)");
			return 1;
		}
		/* verify */

		if (data_size != 16 || memcmp(data, aes_vectors[i].ciphertext, 16) != 0) {
			fprintf(stderr, "AES test vector %d failed!\n", i);

			fprintf(stderr, "Cipher[%d]: ", (int)data_size);
			for(j=0;j<data_size;j++)
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

		memset(&kimport.f, 0, sizeof(kimport.f));
		kimport.f.input_size = sizeof(kimport);
		kimport.f.key = key;
		kimport.f.data = aes_vectors[i].key;
		kimport.f.data_size = 16;
		kimport.id_head.nla_len = NLA_HDRLEN + sizeof(kimport.id);
		kimport.id_head.nla_type = NCR_ATTR_KEY_ID;
		kimport.id[0] = 'a';
		kimport.id[1] = 'b';
		kimport.type_head.nla_len = NLA_HDRLEN + sizeof(kimport.type);
		kimport.type_head.nla_type = NCR_ATTR_KEY_TYPE;
		kimport.type = NCR_KEY_TYPE_SECRET;
		kimport.algo_head.nla_len = NLA_HDRLEN + sizeof(kimport.algo);
		kimport.algo_head.nla_type = NCR_ATTR_ALGORITHM;
		strcpy(kimport.algo, ALG_AES_CBC);
		kimport.flags_head.nla_len = NLA_HDRLEN + sizeof(kimport.flags);
		kimport.flags_head.nla_type = NCR_ATTR_KEY_FLAGS;
		kimport.flags = NCR_KEY_FLAG_EXPORTABLE;
		if (ioctl(cfd, NCRIO_KEY_IMPORT, &kimport)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_KEY_IMPORT)");
			return 1;
		}

		/* decrypt */
		memset(&op.f, 0, sizeof(op.f));
		op.f.input_size = sizeof(op);
		op.f.op = NCR_OP_DECRYPT;
		op.algo_head.nla_len = NLA_HDRLEN + sizeof(op.algo);
		op.algo_head.nla_type = NCR_ATTR_ALGORITHM;
		strcpy(op.algo, ALG_AES_ECB);
		op.key_head.nla_len = NLA_HDRLEN + sizeof(op.key);
		op.key_head.nla_type = NCR_ATTR_KEY;
		op.key = key;
		op.input_head.nla_len = NLA_HDRLEN + sizeof(op.input);
		op.input_head.nla_type = NCR_ATTR_UPDATE_INPUT_DATA;
		op.input.data = aes_vectors[i].ciphertext;
		op.input.data_size = 16;
		op.output_head.nla_len = NLA_HDRLEN + sizeof(op.output);
		op.output_head.nla_type = NCR_ATTR_UPDATE_OUTPUT_BUFFER;
		op.output.buffer = data;
		op.output.buffer_size = sizeof(data);
		op.output.result_size_ptr = &data_size;

		if (ioctl(cfd, NCRIO_SESSION_ONCE, &op)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_SESSION_ONCE)");
			return 1;
		}

		if (data_size != 16 || memcmp(data, aes_vectors[i].plaintext, 16) != 0) {
			fprintf(stderr, "AES test vector %d failed!\n", i);

			fprintf(stderr, "Plain[%d]: ", (int)data_size);
			for(j=0;j<data_size;j++)
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
	const char* algorithm;
	const uint8_t* key; /* if hmac */
	int key_size;
	const uint8_t* plaintext;
	int plaintext_size;
	const uint8_t* output;
	int output_size;
	ncr_crypto_op_t op;
} hash_vectors[] = {
	{
		.algorithm = "sha1",
		.key = NULL,
		.plaintext = (uint8_t*)"what do ya want for nothing?",
		.plaintext_size = sizeof("what do ya want for nothing?")-1,
		.output = (uint8_t*)"\x8f\x82\x03\x94\xf9\x53\x35\x18\x20\x45\xda\x24\xf3\x4d\xe5\x2b\xf8\xbc\x34\x32",
		.output_size = 20,
		.op = NCR_OP_SIGN,
	},
	{
		.algorithm = "hmac(md5)",
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
		.algorithm = "hmac(sha224)",
		.key = (uint8_t*)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
		.key_size = 20,
		.plaintext = (uint8_t*)"Hi There",
		.plaintext_size = sizeof("Hi There")-1,
		.output = (uint8_t*)"\x89\x6f\xb1\x12\x8a\xbb\xdf\x19\x68\x32\x10\x7c\xd4\x9d\xf3\x3f\x47\xb4\xb1\x16\x99\x12\xba\x4f\x53\x68\x4b\x22",
		.output_size = 28,
		.op = NCR_OP_SIGN,
	},
	{
		.algorithm = "hmac(sha256)",
		.key = (uint8_t*)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
		.key_size = 20,
		.plaintext = (uint8_t*)"Hi There",
		.plaintext_size = sizeof("Hi There")-1,
		.output = (uint8_t*)"\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7",
		.output_size = 32,
		.op = NCR_OP_SIGN,
	},
	{
		.algorithm = "hmac(sha384)",
		.key = (uint8_t*)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
		.key_size = 20,
		.plaintext = (uint8_t*)"Hi There",
		.plaintext_size = sizeof("Hi There")-1,
		.output = (uint8_t*)"\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90\x7f\x15\xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c\xfa\xea\x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2\xfa\x9c\xb6",
		.output_size = 48,
		.op = NCR_OP_SIGN,
	},
	{
		.algorithm = "hmac(sha512)",
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
	ncr_key_t key;
	struct __attribute__((packed)) {
		struct ncr_key_import f;
		struct nlattr id_head ALIGN_NL;
		uint8_t id[2] ALIGN_NL;
		struct nlattr type_head ALIGN_NL;
		uint32_t type ALIGN_NL;
		struct nlattr flags_head ALIGN_NL;
		uint32_t flags ALIGN_NL;
		struct nlattr algo_head ALIGN_NL;
		char algo[128] ALIGN_NL;
	} kimport;
	uint8_t data[HASH_DATA_SIZE];
	int i, j;
	size_t data_size;
	struct __attribute__((packed)) {
		struct ncr_session_once f;
		struct nlattr key_head ALIGN_NL;
		uint32_t key ALIGN_NL;
		struct nlattr input_head ALIGN_NL;
		struct ncr_session_input_data input ALIGN_NL;
		struct nlattr output_head ALIGN_NL;
		struct ncr_session_output_buffer output ALIGN_NL;
		struct nlattr algo_head ALIGN_NL;
		char algo[128] ALIGN_NL;
	} op;

	/* convert it to key */
	key = ioctl(cfd, NCRIO_KEY_INIT);
	if (key == -1) {
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	fprintf(stdout, "Tests on Hashes\n");
	for (i=0;i<sizeof(hash_vectors)/sizeof(hash_vectors[0]);i++) {
		size_t algo_size;

		algo_size = strlen(hash_vectors[i].algorithm) + 1;
		fprintf(stdout, "\t%s:\n", hash_vectors[i].algorithm);
		/* import key */
		if (hash_vectors[i].key != NULL) {

			memset(&kimport.f, 0, sizeof(kimport.f));
			kimport.f.key = key;
			kimport.f.data = hash_vectors[i].key;
			kimport.f.data_size = hash_vectors[i].key_size;
			kimport.id_head.nla_len
				= NLA_HDRLEN + sizeof(kimport.id);
			kimport.id_head.nla_type = NCR_ATTR_KEY_ID;
			kimport.id[0] = 'a';
			kimport.id[1] = 'b';
			kimport.type_head.nla_len
				= NLA_HDRLEN + sizeof(kimport.type);
			kimport.type_head.nla_type = NCR_ATTR_KEY_TYPE;
			kimport.type = NCR_KEY_TYPE_SECRET;
			kimport.flags_head.nla_len
				= NLA_HDRLEN + sizeof(kimport.flags);
			kimport.flags_head.nla_type = NCR_ATTR_KEY_FLAGS;
			kimport.flags = NCR_KEY_FLAG_EXPORTABLE;
			kimport.algo_head.nla_len = NLA_HDRLEN + algo_size;
			kimport.algo_head.nla_type = NCR_ATTR_ALGORITHM;
			memcpy(kimport.algo, hash_vectors[i].algorithm,
			       algo_size);
			kimport.f.input_size
				= kimport.algo + algo_size - (char *)&kimport;
			if (ioctl(cfd, NCRIO_KEY_IMPORT, &kimport)) {
				fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
				perror("ioctl(NCRIO_KEY_IMPORT)");
				return 1;
			}
		}

		memset(&op.f, 0, sizeof(op.f));
		op.f.op = hash_vectors[i].op;
		op.key_head.nla_len = NLA_HDRLEN + sizeof(op.key);
		op.key_head.nla_type = NCR_ATTR_KEY;
		op.key = hash_vectors[i].key != NULL ? key : NCR_KEY_INVALID;
		op.input_head.nla_len = NLA_HDRLEN + sizeof(op.input);
		op.input_head.nla_type = NCR_ATTR_UPDATE_INPUT_DATA;
		op.input.data = hash_vectors[i].plaintext;
		op.input.data_size = hash_vectors[i].plaintext_size;
		op.output_head.nla_len = NLA_HDRLEN + sizeof(op.output);
		op.output_head.nla_type = NCR_ATTR_FINAL_OUTPUT_BUFFER;
		op.output.buffer = data;
		op.output.buffer_size = sizeof(data);
		op.output.result_size_ptr = &data_size;
		op.algo_head.nla_len = NLA_HDRLEN + algo_size;
		op.algo_head.nla_type = NCR_ATTR_ALGORITHM;
		memcpy(op.algo, hash_vectors[i].algorithm, algo_size);
		op.f.input_size = op.algo + algo_size - (char *)&op;

		if (ioctl(cfd, NCRIO_SESSION_ONCE, &op)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_SESSION_ONCE)");
			return 1;
		}

		if (data_size != hash_vectors[i].output_size ||
			memcmp(data, hash_vectors[i].output, hash_vectors[i].output_size) != 0) {
			fprintf(stderr, "HASH test vector %d failed!\n", i);

			fprintf(stderr, "Output[%d]: ", (int)data_size);
			for(j=0;j<data_size;j++)
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

static int
test_ncr_hash_clone(int cfd)
{
	ncr_key_t key;
	struct __attribute__((packed)) {
		struct ncr_key_import f;
		struct nlattr id_head ALIGN_NL;
		uint8_t id[2] ALIGN_NL;
		struct nlattr type_head ALIGN_NL;
		uint32_t type ALIGN_NL;
		struct nlattr flags_head ALIGN_NL;
		uint32_t flags ALIGN_NL;
		struct nlattr algo_head ALIGN_NL;
		char algo[128] ALIGN_NL;
	} kimport;
	uint8_t data[HASH_DATA_SIZE];
	const struct hash_vectors_st *hv;
	int j;
	size_t data_size;
	struct __attribute__((packed)) {
		struct ncr_session_init f;
		struct nlattr key_head ALIGN_NL;
		uint32_t key ALIGN_NL;
		struct nlattr algo_head ALIGN_NL;
		char algo[128] ALIGN_NL;
	} kinit;
	struct __attribute__((packed)) {
		struct ncr_session_update f;
		struct nlattr input_head ALIGN_NL;
		struct ncr_session_input_data input ALIGN_NL;
	} kupdate;
	struct __attribute__((packed)) {
		struct ncr_session_final f;
		struct nlattr input_head ALIGN_NL;
		struct ncr_session_input_data input ALIGN_NL;
		struct nlattr output_head ALIGN_NL;
		struct ncr_session_output_buffer output ALIGN_NL;
	} kfinal;
	struct __attribute__((packed)) {
		struct ncr_session_once f;
		struct nlattr clone_head ALIGN_NL;
		uint32_t clone ALIGN_NL;
		struct nlattr input_head ALIGN_NL;
		struct ncr_session_input_data input ALIGN_NL;
		struct nlattr output_head ALIGN_NL;
		struct ncr_session_output_buffer output ALIGN_NL;
	} kclone;
	ncr_session_t ses;

	/* convert it to key */
	key = ioctl(cfd, NCRIO_KEY_INIT);
	if (key == -1) {
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	fprintf(stdout, "Tests of hash cloning\n");
	for (hv = hash_vectors;
	     hv < hash_vectors + sizeof(hash_vectors) / sizeof(hash_vectors[0]);
	     hv++) {
		size_t algo_size;

		algo_size = strlen(hv->algorithm) + 1;
		fprintf(stdout, "\t%s:\n", hv->algorithm);
		/* import key */
		if (hv->key != NULL) {

			memset(&kimport.f, 0, sizeof(kimport.f));
			kimport.f.key = key;
			kimport.f.data = hv->key;
			kimport.f.data_size = hv->key_size;
			kimport.id_head.nla_len
				= NLA_HDRLEN + sizeof(kimport.id);
			kimport.id_head.nla_type = NCR_ATTR_KEY_ID;
			kimport.id[0] = 'a';
			kimport.id[1] = 'b';
			kimport.type_head.nla_len
				= NLA_HDRLEN + sizeof(kimport.type);
			kimport.type_head.nla_type = NCR_ATTR_KEY_TYPE;
			kimport.type = NCR_KEY_TYPE_SECRET;
			kimport.flags_head.nla_len
				= NLA_HDRLEN + sizeof(kimport.flags);
			kimport.flags_head.nla_type = NCR_ATTR_KEY_FLAGS;
			kimport.flags = NCR_KEY_FLAG_EXPORTABLE;
			kimport.algo_head.nla_len = NLA_HDRLEN + algo_size;
			kimport.algo_head.nla_type = NCR_ATTR_ALGORITHM;
			memcpy(kimport.algo, hv->algorithm, algo_size);
			kimport.f.input_size
				= kimport.algo + algo_size - (char *)&kimport;
			if (ioctl(cfd, NCRIO_KEY_IMPORT, &kimport)) {
				fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
				perror("ioctl(NCRIO_KEY_IMPORT)");
				return 1;
			}
		}

		/* Initialize a session */
		memset(&kinit.f, 0, sizeof(kinit.f));
		kinit.f.op = hv->op;
		kinit.key_head.nla_len = NLA_HDRLEN + sizeof(kinit.key);
		kinit.key_head.nla_type = NCR_ATTR_KEY;
		kinit.key = hv->key != NULL ? key : NCR_KEY_INVALID;
		kinit.algo_head.nla_len = NLA_HDRLEN + algo_size;
		kinit.algo_head.nla_type = NCR_ATTR_ALGORITHM;
		memcpy(kinit.algo, hv->algorithm, algo_size);
		kinit.f.input_size = kinit.algo + algo_size - (char *)&kinit;

		ses = ioctl(cfd, NCRIO_SESSION_INIT, &kinit);
		if (ses < 0) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_SESSION_INIT)");
			return 1;
		}

		/* Submit half of the data */
		memset(&kupdate.f, 0, sizeof(kupdate.f));
		kupdate.f.input_size = sizeof(kupdate);
		kupdate.f.ses = ses;
		kupdate.input_head.nla_len = NLA_HDRLEN + sizeof(kupdate.input);
		kupdate.input_head.nla_type = NCR_ATTR_UPDATE_INPUT_DATA;
		kupdate.input.data = hv->plaintext;
		kupdate.input.data_size = hv->plaintext_size / 2;

		if (ioctl(cfd, NCRIO_SESSION_UPDATE, &kupdate)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_SESSION_UPDATE)");
			return 1;
		}

		/* Clone a session, submit the other half, verify. */
		memset(&kclone.f, 0, sizeof(kclone.f));
		kclone.f.input_size = sizeof(kclone);
		kclone.f.op = hv->op;
		kclone.clone_head.nla_len = NLA_HDRLEN + sizeof(kclone.clone);
		kclone.clone_head.nla_type = NCR_ATTR_SESSION_CLONE_FROM;
		kclone.clone = ses;
		kclone.input_head.nla_len = NLA_HDRLEN + sizeof(kclone.input);
		kclone.input_head.nla_type = NCR_ATTR_UPDATE_INPUT_DATA;
		kclone.input.data = hv->plaintext + hv->plaintext_size / 2;
		kclone.input.data_size
			= hv->plaintext_size - hv->plaintext_size / 2;
		kclone.output_head.nla_len = NLA_HDRLEN + sizeof(kclone.output);
		kclone.output_head.nla_type = NCR_ATTR_FINAL_OUTPUT_BUFFER;
		kclone.output.buffer = data;
		kclone.output.buffer_size = sizeof(data);
		kclone.output.result_size_ptr = &data_size;

		if (ioctl(cfd, NCRIO_SESSION_ONCE, &kclone)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_SESSION_ONCE)");
			return 1;
		}

		if (data_size != hv->output_size
		    || memcmp(data, hv->output, hv->output_size) != 0) {
			fprintf(stderr, "HASH test vector %td failed!\n",
				hv - hash_vectors);

			fprintf(stderr, "Output[%zu]: ", data_size);
			for(j = 0; j < data_size; j++)
				fprintf(stderr, "%.2x:", (int)data[j]);
			fprintf(stderr, "\n");

			fprintf(stderr, "Expected[%d]: ", hv->output_size);
			for (j = 0; j < hv->output_size; j++)
				fprintf(stderr, "%.2x:", (int)hv->output[j]);
			fprintf(stderr, "\n");
			return 1;
		}

		/* Submit the other half to the original session, verify. */
		memset(&kfinal.f, 0, sizeof(kfinal.f));
		kfinal.f.input_size = sizeof(kfinal);
		kfinal.f.ses = ses;
		kfinal.input_head.nla_len = NLA_HDRLEN + sizeof(kfinal.input);
		kfinal.input_head.nla_type = NCR_ATTR_UPDATE_INPUT_DATA;
		kfinal.input.data = hv->plaintext + hv->plaintext_size / 2;
		kfinal.input.data_size
			= hv->plaintext_size - hv->plaintext_size / 2;
		kfinal.output_head.nla_len = NLA_HDRLEN + sizeof(kfinal.output);
		kfinal.output_head.nla_type = NCR_ATTR_FINAL_OUTPUT_BUFFER;
		kfinal.output.buffer = data;
		kfinal.output.buffer_size = sizeof(data);
		kfinal.output.result_size_ptr = &data_size;

		if (ioctl(cfd, NCRIO_SESSION_FINAL, &kfinal)) {
			fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
			perror("ioctl(NCRIO_SESSION_FINAL)");
			return 1;
		}

		if (data_size != hv->output_size
		    || memcmp(data, hv->output, hv->output_size) != 0) {
			fprintf(stderr, "HASH test vector %td failed!\n",
				hv - hash_vectors);

			fprintf(stderr, "Output[%zu]: ", data_size);
			for(j = 0; j < data_size; j++)
				fprintf(stderr, "%.2x:", (int)data[j]);
			fprintf(stderr, "\n");

			fprintf(stderr, "Expected[%d]: ", hv->output_size);
			for (j = 0; j < hv->output_size; j++)
				fprintf(stderr, "%.2x:", (int)hv->output[j]);
			fprintf(stderr, "\n");
			return 1;
		}
	}

	fprintf(stdout, "\n");

	return 0;

}

static int
test_ncr_hash_key(int cfd)
{
	ncr_key_t key;
	ncr_session_t ses;
	struct __attribute__((packed)) {
		struct ncr_key_import f;
		struct nlattr id_head ALIGN_NL;
		uint8_t id[2] ALIGN_NL;
		struct nlattr type_head ALIGN_NL;
		uint32_t type ALIGN_NL;
		struct nlattr flags_head ALIGN_NL;
		uint32_t flags ALIGN_NL;
		struct nlattr algo_head ALIGN_NL;
		char algo[128] ALIGN_NL;
	} kimport;
	uint8_t data[HASH_DATA_SIZE];
	int j;
	size_t data_size, algo_size;
	struct __attribute__((packed)) {
		struct ncr_session_init f;
		struct nlattr algo_head ALIGN_NL;
		char algo[128] ALIGN_NL;
	} op_init;
	struct __attribute__((packed)) {
		struct ncr_session_update f;
		struct nlattr data_head ALIGN_NL;
		struct ncr_session_input_data data ALIGN_NL;
	} op_up_data;
	struct __attribute__((packed)) {
		struct ncr_session_update f;
		struct nlattr key_head ALIGN_NL;
		uint32_t key;
	} op_up_key;
	struct __attribute__((packed)) {
		struct ncr_session_final f;
		struct nlattr output_head ALIGN_NL;
		struct ncr_session_output_buffer output ALIGN_NL;
	} op_final;
	const uint8_t *output = (void*)"\xe2\xd7\x2c\x2e\x14\xad\x97\xc8\xd2\xdb\xce\xd8\xb3\x52\x9f\x1c\xb3\x2c\x5c\xec";

	/* convert it to key */
	key = ioctl(cfd, NCRIO_KEY_INIT);
	if (key == -1) {
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	fprintf(stdout, "Tests on Hashes of Keys\n");

	fprintf(stdout, "\t%s:\n", hash_vectors[0].algorithm);
	algo_size = strlen(hash_vectors[0].algorithm) + 1;
	/* import key */
	memset(&kimport.f, 0, sizeof(kimport.f));
	kimport.f.key = key;
	kimport.f.data = hash_vectors[0].plaintext;
	kimport.f.data_size = hash_vectors[0].plaintext_size;
	kimport.id_head.nla_len = NLA_HDRLEN + sizeof(kimport.id);
	kimport.id_head.nla_type = NCR_ATTR_KEY_ID;
	kimport.id[0] = 'a';
	kimport.id[1] = 'b';
	kimport.type_head.nla_len = NLA_HDRLEN + sizeof(kimport.type);
	kimport.type_head.nla_type = NCR_ATTR_KEY_TYPE;
	kimport.type = NCR_KEY_TYPE_SECRET;
	kimport.flags_head.nla_len = NLA_HDRLEN + sizeof(kimport.flags);
	kimport.flags_head.nla_type = NCR_ATTR_KEY_FLAGS;
	kimport.flags = NCR_KEY_FLAG_EXPORTABLE;
	kimport.algo_head.nla_len = NLA_HDRLEN + algo_size;
	kimport.algo_head.nla_type = NCR_ATTR_ALGORITHM;
	memcpy(kimport.algo, hash_vectors[0].algorithm, algo_size);
	kimport.f.input_size = kimport.algo + algo_size - (char *)&kimport;
	if (ioctl(cfd, NCRIO_KEY_IMPORT, &kimport)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

	memset(&op_init.f, 0, sizeof(op_init.f));
	op_init.f.op = hash_vectors[0].op;
	op_init.algo_head.nla_len = NLA_HDRLEN + algo_size;
	op_init.algo_head.nla_type = NCR_ATTR_ALGORITHM;
	memcpy(op_init.algo, hash_vectors[0].algorithm, algo_size);
	op_init.f.input_size = op_init.algo + algo_size - (char *)&op_init;

	ses = ioctl(cfd, NCRIO_SESSION_INIT, &op_init);
	if (ses < 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_SESSION_INIT)");
		return 1;
	}

	memset(&op_up_data.f, 0, sizeof(op_up_data.f));
	op_up_data.f.input_size = sizeof(op_up_data);
	op_up_data.f.ses = ses;
	op_up_data.data_head.nla_len = NLA_HDRLEN + sizeof(op_up_data.data);
	op_up_data.data_head.nla_type = NCR_ATTR_UPDATE_INPUT_DATA;
	op_up_data.data.data = hash_vectors[0].plaintext;
	op_up_data.data.data_size = hash_vectors[0].plaintext_size;

	if (ioctl(cfd, NCRIO_SESSION_UPDATE, &op_up_data)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_SESSION_UPDATE)");
		return 1;
	}

	memset(&op_up_key.f, 0, sizeof(op_up_key.f));
	op_up_key.f.input_size = sizeof(op_up_key);
	op_up_key.f.ses = ses;
	op_up_key.key_head.nla_len = NLA_HDRLEN + sizeof(op_up_key.key);
	op_up_key.key_head.nla_type = NCR_ATTR_UPDATE_INPUT_KEY_AS_DATA;
	op_up_key.key = key;

	if (ioctl(cfd, NCRIO_SESSION_UPDATE, &op_up_key)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_SESSION_UPDATE)");
		return 1;
	}

	memset(&op_final.f, 0, sizeof(op_final.f));
	op_final.f.input_size = sizeof(op_final);
	op_final.f.ses = ses;
	op_final.output_head.nla_len = NLA_HDRLEN + sizeof(op_final.output);
	op_final.output_head.nla_type = NCR_ATTR_FINAL_OUTPUT_BUFFER;
	op_final.output.buffer = data;
	op_final.output.buffer_size = sizeof(data);
	op_final.output.result_size_ptr = &data_size;

	if (ioctl(cfd, NCRIO_SESSION_FINAL, &op_final)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_SESSION_FINAL)");
		return 1;
	}		


	if (data_size != hash_vectors[0].output_size ||
			memcmp(data, output, hash_vectors[0].output_size) != 0) {
			fprintf(stderr, "HASH test vector %d failed!\n", 0);

			fprintf(stderr, "Output[%d]: ", (int)data_size);
			for(j=0;j<data_size;j++)
			  fprintf(stderr, "%.2x:", (int)data[j]);
			fprintf(stderr, "\n");

			fprintf(stderr, "Expected[%d]: ", hash_vectors[0].output_size);
			for(j=0;j<hash_vectors[0].output_size;j++)
			  fprintf(stderr, "%.2x:", (int)output[j]);
			fprintf(stderr, "\n");
			return 1;
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

	if (test_ncr_key(fd))
		return 1;

	if (test_ncr_aes(fd))
		return 1;

	if (test_ncr_hash(fd))
		return 1;

	if (test_ncr_hash_clone(fd))
		return 1;

	if (test_ncr_hash_key(fd))
		return 1;

	if (test_ncr_wrap_key(fd))
		return 1;

	if (test_ncr_wrap_key2(fd))
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
