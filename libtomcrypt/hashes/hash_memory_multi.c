/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */
#include "tomcrypt.h"
#include <stdarg.h>
#include <ncr-int.h>
#include <cryptodev_int.h>

/**
  @file hash_memory_multi.c
  Hash (multiple buffers) memory helper, Tom St Denis
*/

/**
  Hash multiple (non-adjacent) blocks of memory at once.  
  @param hash   The hash you wish to use
  @param out    [out] Where to store the digest
  @param outlen [in/out] Max size and resulting size of the digest
  @param in     The data you wish to hash
  @param inlen  The length of the data to hash (octets)
  @param ...    tuples of (data,len) pairs to hash, terminated with a (NULL,x) (x=don't care)
  @return CRYPT_OK if successful
*/
int hash_memory_multi(const struct algo_properties_st *hash, unsigned char *out,
		      unsigned long *outlen, const unsigned char *in,
		      unsigned long inlen, ...)
{
	struct hash_data hdata;
	int err;
	va_list args;
	const unsigned char *curptr;
	unsigned long curlen;

	LTC_ARGCHK(in != NULL);
	LTC_ARGCHK(out != NULL);
	LTC_ARGCHK(outlen != NULL);

	if ((err = hash_is_valid(hash)) != CRYPT_OK) {
		return err;
	}

	if (*outlen < hash->digest_size) {
		*outlen = hash->digest_size;
		return CRYPT_BUFFER_OVERFLOW;
	}

	err = cryptodev_hash_init(&hdata, hash->kstr, NULL, 0);
	if (err < 0) {
		err = CRYPT_INVALID_HASH;
		goto LBL_ERR;
	}

	va_start(args, inlen);
	curptr = in;
	curlen = inlen;
	for (;;) {
		/* process buf */
		if ((err = _cryptodev_hash_update(&hdata, curptr, curlen)) < 0) {
			err = CRYPT_ERROR;
			goto LBL_ERR;
		}
		/* step to next */
		curptr = va_arg(args, const unsigned char *);
		if (curptr == NULL) {
			break;
		}
		curlen = va_arg(args, unsigned long);
	}

	err = cryptodev_hash_final(&hdata, out);

	*outlen = hash->digest_size;
LBL_ERR:
	cryptodev_hash_deinit(&hdata);
	va_end(args);
	return err;
}
