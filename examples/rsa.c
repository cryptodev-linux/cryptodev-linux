/*
 * Demo on how to use /dev/ncr device for RSA.
 *
 * Placed under public domain.
 *
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/netlink.h>
/* #include <crypto/ncr.h> */
#include "../ncr.h"
#include <stdlib.h>

/* This example will sign data using RSA and try to 
 * verify them.
 */

static int rsa_key_sign_verify(int cfd, 
	ncr_key_t privkey, 
	ncr_key_t pubkey, 
	void* data, size_t data_size,
	int pss)
{
	NCR_STRUCT(ncr_session_once) ksign;
	NCR_STRUCT(ncr_session_once) kverify;
	struct nlattr *nla;
	uint8_t sig[256];
	size_t sig_size;
	int ret;

	fprintf(stdout, "Signing using RSA (%s)\n",
		(pss != 0) ? "PSS" : "PKCS V1.5");

	/* sign data 
	 */
	nla = NCR_INIT(ksign);
	ksign.f.op = NCR_OP_SIGN;
	ncr_put_u32(&nla, NCR_ATTR_ALGORITHM, NCR_ALG_RSA);
	ncr_put_u32(&nla, NCR_ATTR_KEY, privkey);
	ncr_put_u32(&nla, NCR_ATTR_RSA_ENCODING_METHOD,
		    (pss != 0) ? RSA_PKCS1_PSS : RSA_PKCS1_V1_5);
	ncr_put_u32(&nla, NCR_ATTR_SIGNATURE_HASH_ALGORITHM, NCR_ALG_SHA1);
	ncr_put_session_input_data(&nla, NCR_ATTR_UPDATE_INPUT_DATA, data,
				   data_size);
	ncr_put_session_output_buffer(&nla, NCR_ATTR_FINAL_OUTPUT_BUFFER, sig,
				      sizeof(sig), &sig_size);
	NCR_FINISH(ksign, nla);

	if (ioctl(cfd, NCRIO_SESSION_ONCE, &ksign)) {
		perror("ioctl(NCRIO_SESSION_ONCE)");
		return 1;
	}

	/* signature completed. Now verify data.
	 */
	nla = NCR_INIT(kverify);
	kverify.f.op = NCR_OP_VERIFY;
	ncr_put_u32(&nla, NCR_ATTR_ALGORITHM, NCR_ALG_RSA);
	ncr_put_u32(&nla, NCR_ATTR_KEY, pubkey);
	ncr_put_u32(&nla, NCR_ATTR_RSA_ENCODING_METHOD,
		    (pss != 0) ? RSA_PKCS1_PSS : RSA_PKCS1_V1_5);
	ncr_put_u32(&nla, NCR_ATTR_SIGNATURE_HASH_ALGORITHM, NCR_ALG_SHA1);
	ncr_put_session_input_data(&nla, NCR_ATTR_UPDATE_INPUT_DATA, data,
				   data_size);
	ncr_put_session_input_data(&nla, NCR_ATTR_FINAL_INPUT_DATA, sig,
				   sig_size);
	NCR_FINISH(kverify, nla);

	ret = ioctl(cfd, NCRIO_SESSION_ONCE, &kverify);
	if (ret < 0) {
		perror("ioctl(NCRIO_SESSION_ONCE)");
		return 1;
	}

	if (ret)
		fprintf(stdout, " Data were verified\n");
	else {
		fprintf(stdout, " Verification Failed!\n");
		return 1;
	}

	return 0;

}

/* Generates a private/public key pair and tries to
 * sign and verify data.
 */
static int test_ncr_rsa(int cfd)
{
	int ret;
	NCR_STRUCT(ncr_key_generate_pair) kgen;
	struct ncr_key_storage_wrap kwrap;
	struct ncr_key_export kexport;
	struct nlattr *nla;
	ncr_key_t pubkey, privkey;
	uint8_t data[4*1024];
	int data_size;
	FILE* fp;

	fprintf(stdout, "Tests on RSA key generation:");
	fflush(stdout);

	/* create two keys
	 */
	privkey = ioctl(cfd, NCRIO_KEY_INIT);
	if (privkey == -1) {
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	pubkey = ioctl(cfd, NCRIO_KEY_INIT);
	if (pubkey == -1) {
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	/* Generate the key pair
	 */
	nla = NCR_INIT(kgen);
	kgen.f.private_key = privkey;
	kgen.f.public_key = pubkey;
	ncr_put_u32(&nla, NCR_ATTR_ALGORITHM, NCR_ALG_RSA);
	ncr_put_u32(&nla, NCR_ATTR_KEY_FLAGS, NCR_KEY_FLAG_ALLOW_TRANSPARENT_HASH);
	ncr_put_u32(&nla, NCR_ATTR_RSA_MODULUS_BITS, 1024);
	NCR_FINISH(kgen, nla);

	if (ioctl(cfd, NCRIO_KEY_GENERATE_PAIR, &kgen)) {
		perror("ioctl(NCRIO_KEY_GENERATE_PAIR)");
		return 1;
	}

	data_size = sizeof(data);
	memset(data, 0x35, data_size);

	memset(&kexport, 0, sizeof(kexport));
	kexport.key = pubkey;
	kexport.buffer = data;
	kexport.buffer_size = sizeof(data);

	data_size = ioctl(cfd, NCRIO_KEY_EXPORT, &kexport);
	if (data_size == -1) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_EXPORT)");
		return 1;
	}

#ifdef STORE_KEY
	fp = fopen("public.key", "w");
	if (fp != NULL)
	  {
	    fwrite(data, 1, data_size, fp);
	    fclose(fp);
	  }
#endif

	memset(&kwrap, 0, sizeof(kwrap));
	kwrap.key = privkey;
	kwrap.buffer = data;
	kwrap.buffer_size = sizeof(data);

	data_size = ioctl(cfd, NCRIO_KEY_STORAGE_WRAP, &kwrap);
	if (data_size == -1) {
		perror("ioctl(NCRIO_KEY_STORAGE_WRAP)");
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}

#ifdef STORE_KEY
	fp = fopen("private.key", "w");
	if (fp != NULL)
	  {
	    fwrite(data, 1, data_size, fp);
	    fclose(fp);
	  }
#endif

	ret = rsa_key_sign_verify(cfd, privkey, pubkey, data, data_size, 1);
	if (ret != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}

	ret = rsa_key_sign_verify(cfd, privkey, pubkey, data, data_size, 0);
	if (ret != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}

	return 0;
}


int main()
{
	int fd = -1;

	/* open the NCR device 
	 */
	fd = open("/dev/ncr", O_RDWR, 0);
	if (fd < 0) {
		perror("open(/dev/ncr)");
		return 1;
	}

	if (test_ncr_rsa(fd))
		return 1;

	/* Close the original descriptor */
	if (close(fd)) {
		perror("close(fd)");
		return 1;
	}

	return 0;
}
