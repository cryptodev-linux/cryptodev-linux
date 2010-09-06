/* ---- HASH FUNCTIONS ---- */

struct algo_properties_st;

int hash_is_valid(const struct algo_properties_st *hash);

int hash_memory(const struct algo_properties_st *hash,
		const unsigned char *in, unsigned long inlen,
		unsigned char *out, unsigned long *outlen);
int hash_memory_multi(const struct algo_properties_st *hash, unsigned char *out,
		      unsigned long *outlen, const unsigned char *in,
		      unsigned long inlen, ...);

int hash_get_oid(const struct algo_properties_st *hash, oid_st * st);
