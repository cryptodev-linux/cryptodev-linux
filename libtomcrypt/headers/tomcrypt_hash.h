/* ---- HASH FUNCTIONS ---- */

int hash_is_valid(int idx);

int hash_memory(int hash, 
                const unsigned char *in,  unsigned long inlen, 
                      unsigned char *out, unsigned long *outlen);
int hash_memory_multi(int hash, unsigned char *out, unsigned long *outlen,
                      const unsigned char *in, unsigned long inlen, ...);

int hash_get_oid(int hash, oid_st* st);

