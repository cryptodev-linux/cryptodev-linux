/*
 * Demo on how to use /dev/crypto device for ciphering.
 *
 * Placed under public domain.
 *
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>
#include "842.h"

int c842_ctx_init(struct cryptodev_ctx* ctx, int cfd)
{
#ifdef CIOCGSESSINFO
	struct session_info_op siop;
#endif

	memset(ctx, 0, sizeof(*ctx));
	ctx->cfd = cfd;

	ctx->sess.compr = CRYPTO_842;

	if (ioctl(ctx->cfd, CIOCGSESSION, &ctx->sess)) {
		perror("ioctl(CIOCGSESSION)");
		return -1;
	}

#ifdef CIOCGSESSINFO
	siop.ses = ctx->sess.ses;
	if (ioctl(ctx->cfd, CIOCGSESSINFO, &siop)) {
		perror("ioctl(CIOCGSESSINFO)");
		return -1;
	}
	printf("Got %s with driver %s\n",
			siop.compr_info.cra_name, siop.compr_info.cra_driver_name);
	if (!(siop.flags & SIOP_FLAG_KERNEL_DRIVER_ONLY)) {
		printf("Note: This is not an accelerated compressor\n");
	}
	ctx->alignmask = siop.alignmask;
#endif
	return 0;
}

void c842_ctx_deinit(struct cryptodev_ctx* ctx) 
{
	if (ioctl(ctx->cfd, CIOCFSESSION, &ctx->sess.ses)) {
		perror("ioctl(CIOCFSESSION)");
	}
}

int c842_compress(struct cryptodev_ctx* ctx, const void* input, void* output, size_t size)
{
	struct crypt_op cryp;
	void* p;
	
	/* check input and output alignment */
	if (ctx->alignmask) {
		p = (void*)(((unsigned long)input + ctx->alignmask) & ~ctx->alignmask);
		if (input != p) {
			fprintf(stderr, "input is not aligned\n");
			return -1;
		}

		p = (void*)(((unsigned long)output + ctx->alignmask) & ~ctx->alignmask);
		if (output != p) {
			fprintf(stderr, "output is not aligned\n");
			return -1;
		}
	}

	memset(&cryp, 0, sizeof(cryp));

	/* Encrypt data.in to data.encrypted */
	cryp.ses = ctx->sess.ses;
	cryp.len = size;
	cryp.dlen = size + 8;
	cryp.src = (void*)input;
	cryp.dst = output;
	cryp.op = COP_ENCRYPT;
	if (ioctl(ctx->cfd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		return -1;
	}

	return 0;
}

int
main()
{
	int cfd = -1, i;
	struct cryptodev_ctx ctx;
	uint8_t output[16];
	char input[] = "0011223\x0a";

	memset (output, 0, 16);

	/* Open the crypto device */
	cfd = open("/dev/crypto", O_RDWR, 0);
	if (cfd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}

	/* Set close-on-exec (not really neede here) */
	if (fcntl(cfd, F_SETFD, 1) == -1) {
		perror("fcntl(F_SETFD)");
		return 1;
	}

	c842_ctx_init(&ctx, cfd);
	
	c842_compress(&ctx, input, output, 8);
	
	c842_ctx_deinit(&ctx);

	printf("Raw data:\n");
	for (i = 0; i < 8; i++) {
		printf("%02x:", input[i]);
	}
	printf("\n");


	printf("Compressed result:\n");
	for (i = 0; i < 16; i++) {
		printf("%02x:", output[i]);
	}
	printf("\n");

	/* Close the original descriptor */
	if (close(cfd)) {
		perror("close(cfd)");
		return 1;
	}

	return 0;
}

