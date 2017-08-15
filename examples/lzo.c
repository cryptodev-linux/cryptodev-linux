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
#include "lzo.h"

int lzo_ctx_init(struct cryptodev_ctx* ctx, int cfd)
{
#ifdef CIOCGSESSINFO
	struct session_info_op siop;
#endif

	memset(ctx, 0, sizeof(*ctx));
	ctx->cfd = cfd;

	ctx->sess.compr = CRYPTO_LZO;

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
		printf("Note: This is not an accelerated cipher\n");
	}
	ctx->alignmask = siop.alignmask;
#endif
	return 0;
}

void lzo_ctx_deinit(struct cryptodev_ctx* ctx) 
{
	if (ioctl(ctx->cfd, CIOCFSESSION, &ctx->sess.ses)) {
		perror("ioctl(CIOCFSESSION)");
	}
}

int lzo_compress(struct cryptodev_ctx* ctx, const void* input, void* output, size_t size)
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

	/* Compress cryp.src to cryp.dst */
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

int lzo_decompress(struct cryptodev_ctx* ctx, const void* input, void* output, size_t size)
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

	/* Compress cryp.src to cryp.dst */
	cryp.ses = ctx->sess.ses;
	cryp.len = size;
	cryp.dlen = size*2;
	cryp.src = (void*)input;
	cryp.dst = output;
	cryp.op = COP_DECRYPT;
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
	uint8_t output[64];
	char input[64];
	char tmp[] = "The quick brown fox jumps over the lazy dog";

	memset(input, 0, 64);
	memset(output, 0, 64);
	strncpy(input, tmp, sizeof input - 1);

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

	lzo_ctx_init(&ctx, cfd);

	printf("Raw data:\n");
	for (i = 0; i < strlen(input); i++) {
		printf("%02x:", input[i]);
	}
	printf("\n");

	lzo_compress(&ctx, input, output, strlen(input));

	printf("Compressed result:\n");
	for (i = 0; i < 64; i++) {
		printf("%02x:", output[i]);
	}
	printf("\n");

	lzo_ctx_deinit(&ctx);

	/* Close the original descriptor */
	if (close(cfd)) {
		perror("close(cfd)");
		return 1;
	}

	return 0;
}

