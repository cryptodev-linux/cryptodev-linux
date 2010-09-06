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
#include <ncr-int.h>
#include <cryptodev_int.h>

/**
  @file hash_memory.c
  Hash memory helper, Tom St Denis
*/

/**
  Hash a block of memory and store the digest.
  @param hash   The hash you wish to use
  @param in     The data you wish to hash
  @param inlen  The length of the data to hash (octets)
  @param out    [out] Where to store the digest
  @param outlen [in/out] Max size and resulting size of the digest
  @return CRYPT_OK if successful
*/
int hash_memory(const struct algo_properties_st *hash, const unsigned char *in,
		unsigned long inlen, unsigned char *out, unsigned long *outlen)
{
	int err;
	struct hash_data hdata;

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

	if ((err = _cryptodev_hash_update(&hdata, in, inlen)) < 0) {
		err = CRYPT_ERROR;
		goto LBL_ERR;
	}

	err = cryptodev_hash_final(&hdata, out);

	*outlen = hash->digest_size;
LBL_ERR:
	cryptodev_hash_deinit(&hdata);

	return err;
}
