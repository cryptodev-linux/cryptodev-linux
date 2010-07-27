#ifndef NCR_DH_H
# define NCR_DH_H

#include <tomcrypt.h>

typedef struct {
	int type; /* PK_PRIVATE or PK_PUBLIC */
	mp_int p;
	mp_int g;
	mp_int x; /* private */
	mp_int y; /* public: y=g^x */
} dh_key;

int dh_generate_key(dh_key * key);
int dh_import_params(dh_key * key, uint8_t* p, size_t p_size, uint8_t* g, size_t g_size);
void dh_free(dh_key * key);
int dh_generate_public(dh_key * public, dh_key* private);

int dh_export(uint8_t *out, size_t *outlen, int type, dh_key *key);
int dh_import(const uint8_t *in, size_t inlen, dh_key *key);
#endif
