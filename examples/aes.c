/*
 * Demo on how to use /dev/ncr device for HMAC.
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
/* #include <crypto/ncr.h> */
#include "../ncr.h"
#include <stdlib.h>

static int test_ncr_aes(int cfd)
{
	ncr_key_t key;
	NCR_STRUCT(ncr_key_import) kimport;
	uint8_t *pkey = (uint8_t *)
	    "\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	uint8_t *plaintext = (uint8_t *)
	    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	uint8_t *ciphertext = (uint8_t *)
	    "\x4b\xc3\xf8\x83\x45\x0c\x11\x3c\x64\xca\x42\xe1\x11\x2a\x9e\x87";
	uint8_t data[32];
	NCR_STRUCT(ncr_session_once) op;
	struct nlattr *nla;
	size_t data_size;

	/* create a key */
	key = ioctl(cfd, NCRIO_KEY_INIT);
	if (key == -1) {
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	/* import the pkey to key */
	nla = NCR_INIT(kimport);
	kimport.f.key = key;
	kimport.f.data = pkey;
	kimport.f.data_size = 16;

	ncr_put(&nla, NCR_ATTR_KEY_ID, "my_id", 5);
	ncr_put_u32(&nla, NCR_ATTR_KEY_TYPE, NCR_KEY_TYPE_SECRET);
	ncr_put_u32(&nla, NCR_ATTR_ALGORITHM, NCR_ALG_AES_ECB);
	ncr_put_u32(&nla, NCR_ATTR_KEY_FLAGS, 0);
	NCR_FINISH(kimport, nla);
	if (ioctl(cfd, NCRIO_KEY_IMPORT, &kimport)) {
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

	/* encrypt */
	nla = NCR_INIT(op);
	op.f.op = NCR_OP_ENCRYPT;
	ncr_put_u32(&nla, NCR_ATTR_ALGORITHM, NCR_ALG_AES_ECB);
	ncr_put_u32(&nla, NCR_ATTR_KEY, key);
	ncr_put_session_input_data(&nla, NCR_ATTR_UPDATE_INPUT_DATA,
		plaintext, 16);
	ncr_put_session_output_buffer(&nla,
		NCR_ATTR_UPDATE_OUTPUT_BUFFER,
		data, sizeof(data), &data_size);
	NCR_FINISH(op, nla);

	if (ioctl(cfd, NCRIO_SESSION_ONCE, &op)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_SESSION_ONCE)");
		return 1;
	}

	/* now verify that the ciphertext is as expected */

	if (data_size != 16
	    || memcmp(data, ciphertext, 16) != 0) {
		fprintf(stderr, "AES encryption failed!\n");
		return 1;
	}

	return 0;

}

int main()
{
	int fd = -1;

	/* Open the crypto device */
	fd = open("/dev/ncr", O_RDWR, 0);
	if (fd < 0) {
		perror("open(/dev/ncr)");
		return 1;
	}

	if (test_ncr_aes(fd))
		return 1;

	/* Close the original descriptor */
	if (close(fd)) {
		perror("close(fd)");
		return 1;
	}

	return 0;
}
