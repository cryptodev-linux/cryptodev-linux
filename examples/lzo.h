#ifndef LZO_H
# define LZO_H

#include <stdint.h>

struct cryptodev_ctx {
	int cfd;
	struct session_op sess;
	uint16_t alignmask;
};

int lzo_ctx_init(struct cryptodev_ctx* ctx, int cfd);
void lzo_ctx_deinit(struct cryptodev_ctx* ctx) ;
int lzo_compress(struct cryptodev_ctx* ctx, const void* input, void* output, size_t size);

#endif
