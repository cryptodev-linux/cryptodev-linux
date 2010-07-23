#ifndef NCR_PK_H
# define NCR_PK_H

#include <tomcrypt.h>

struct ncr_pk_ctx {
	const struct algo_properties_st *algorithm; /* algorithm */
	
	const struct algo_properties_st *sign_hash; /* for verification */
	
	const struct algo_properties_st *oaep_hash;
	int salt_len; /* for RSA-PSS signatures */
	
	int type; /* libtomcrypt type */
	int init; /* non zero if initialized */
	
	struct key_item_st * key;
};

/* PK */
void ncr_pk_clear(struct key_item_st* key);
int ncr_pk_generate(ncr_algorithm_t algo,
	struct ncr_key_generate_params_st * params,
	struct key_item_st* private, struct key_item_st* public);
int ncr_pk_pack( const struct key_item_st * key, uint8_t * packed, uint32_t * packed_size);
int ncr_pk_unpack( struct key_item_st * key, const void * packed, size_t packed_size);


int ncr_pk_queue_init(void);
void ncr_pk_queue_deinit(void);

/* encryption/decryption */
int ncr_pk_cipher_init(const struct algo_properties_st *algo,
	struct ncr_pk_ctx* ctx, struct ncr_key_params_st* params,
	struct key_item_st *key);
void ncr_pk_cipher_deinit(struct ncr_pk_ctx* ctx);
int ncr_pk_cipher_encrypt(const struct ncr_pk_ctx* ctx, const void* input, 
	size_t input_size, void* output, size_t *output_size);
int ncr_pk_cipher_decrypt(const struct ncr_pk_ctx* ctx, const void* input, 
	size_t input_size, void* output, size_t *output_size);
int ncr_pk_cipher_sign(const struct ncr_pk_ctx* ctx, const void* input, 
	size_t input_size, void* output, size_t *output_size);

int ncr_pk_cipher_verify(const struct ncr_pk_ctx* ctx, 
	const void* signature, size_t signature_size, 
	const void* hash, size_t hash_size, ncr_error_t*);

#endif
