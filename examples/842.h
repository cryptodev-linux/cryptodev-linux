#ifndef c842_H
# define c842_H

#include <stdint.h>

struct cryptodev_ctx {
	int cfd;
	struct session_op sess;
	uint16_t alignmask;
};

int c842_ctx_init(struct cryptodev_ctx* ctx, int cfd);
int c842_ctx_deinit(struct cryptodev_ctx* ctx) ;
int c842_compress(struct cryptodev_ctx* ctx, const void* in, unsigned int ilen,
					     void* out, unsigned int *olen);
int c842_decompress(struct cryptodev_ctx* ctx, const void* in, unsigned int ilen,
					       void* out, unsigned int *olen);

#endif
