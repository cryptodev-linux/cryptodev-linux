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
	printf("SIOP_FLAG_KERNEL_DRIVER_ONLY: %d", SIOP_FLAG_KERNEL_DRIVER_ONLY);
	printf("siop.flags %02x\n", siop.flags);
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

int c842_compress(struct cryptodev_ctx* ctx, const void* in, unsigned int ilen,
					     void* out, unsigned int *olen)
{
	struct crypt_op cryp;
	void* p;

	/* check input and output alignment */
	if (ctx->alignmask) {
		p = (void*)(((unsigned long)in + ctx->alignmask) & ~ctx->alignmask);
		if (in != p) {
			fprintf(stderr, "in is not aligned\n");
			return -1;
		}

		p = (void*)(((unsigned long)out + ctx->alignmask) & ~ctx->alignmask);
		if (out != p) {
			fprintf(stderr, "out is not aligned\n");
			return -1;
		}
	}

	memset(&cryp, 0, sizeof(cryp));

	/* Compress cryp.src to cryp.dst */
	cryp.ses = ctx->sess.ses;
	cryp.op = COP_ENCRYPT;
	cryp.len = ilen;
	cryp.dlen = *olen;
	cryp.src = (void*)in;
	cryp.dst = out;
	if (ioctl(ctx->cfd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		return -1;
	}

	*olen = cryp.dlen;

	return 0;
}

int c842_decompress(struct cryptodev_ctx* ctx, const void* in, unsigned int ilen,
					       void* out, unsigned int *olen)
{
	struct crypt_op cryp;
	void* p;

	/* check input and output alignment */
	if (ctx->alignmask) {
		p = (void*)(((unsigned long)in + ctx->alignmask) & ~ctx->alignmask);
		if (in != p) {
			fprintf(stderr, "in is not aligned\n");
			return -1;
		}

		p = (void*)(((unsigned long)out + ctx->alignmask) & ~ctx->alignmask);
		if (out != p) {
			fprintf(stderr, "out is not aligned\n");
			return -1;
		}
	}

	memset(&cryp, 0, sizeof(cryp));

	/* Decompress cryp.src to cryp.dst */
	cryp.ses = ctx->sess.ses;
	cryp.op = COP_DECRYPT;
	cryp.len = ilen;
	cryp.dlen = *olen;
	cryp.src = (void*)in;
	cryp.dst = out;
	if (ioctl(ctx->cfd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		return -1;
	}

	*olen = cryp.dlen;

	return 0;
}

int
main()
{
	int cfd = -1, i;
	struct cryptodev_ctx ctx;
	uint8_t output[128] = {0};
	uint8_t input[128] = {0};
	uint8_t decompressed[128] = {0};
	char tmp[] = "How much wood would a woodchuck chuck, if a woodchuck could chuck wood?";
	unsigned int olen = sizeof(output), dlen = sizeof(decompressed);

	strncpy(input, tmp, sizeof(input) - 1);

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

	printf("Raw data:\n");
	for (i = 0; i < strlen(tmp); i++) {
		printf("%02x:", input[i]);
	}
	printf("\n");


	c842_compress(&ctx, input, strlen(tmp), output, &olen);

	printf("Compressed result:\n");
	for (i = 0; i < olen; i++) {
		printf("%02x:", output[i]);
	}
	printf("\n");

	c842_decompress(&ctx, output, olen, decompressed, &dlen);

	printf("Restored raw data:\n");
	for (i = 0; i < dlen; i++) {
		printf("%02x:", decompressed[i]);
	}
	printf("\n");

	c842_ctx_deinit(&ctx);




	/* Close the original descriptor */
	if (close(cfd)) {
		perror("close(cfd)");
		return 1;
	}

	return 0;
}

