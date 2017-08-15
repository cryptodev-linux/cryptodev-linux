#ifndef c842_H
# define c842_H

#include <stdint.h>

struct cryptodev_ctx {
	int cfd;
	struct session_op sess;
	uint16_t alignmask;
};

int c842_ctx_init(struct cryptodev_ctx* ctx, int cfd);
void c842_ctx_deinit(struct cryptodev_ctx* ctx) ;
int c842_compress(struct cryptodev_ctx* ctx, const void* input, void* output, size_t size);

#endif
