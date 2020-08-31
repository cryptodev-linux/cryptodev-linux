#ifndef LZO_H
# define LZO_H

#include <stdint.h>

struct cryptodev_ctx {
	int cfd;
	struct session_op sess;
	uint16_t alignmask;
};

int lzo_ctx_init(struct cryptodev_ctx* ctx, int cfd);
int lzo_ctx_deinit(struct cryptodev_ctx* ctx) ;
int lzo_compress(struct cryptodev_ctx* ctx, const void* in, unsigned int ilen,
					    void* out, unsigned int *olen);
int lzo_decompress(struct cryptodev_ctx* ctx, const void* in, unsigned int ilen,
					      void* out, unsigned int *olen);

#endif
