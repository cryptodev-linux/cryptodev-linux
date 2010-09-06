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

/**
  @file pkcs_1_mgf1.c
  The Mask Generation Function (MGF1) for LTC_PKCS #1, Tom St Denis 
*/

#ifdef LTC_PKCS_1

/**
   Perform LTC_PKCS #1 MGF1 (internal)
   @param seed        The seed for MGF1
   @param seedlen     The length of the seed
   @param hash        The desired hash
   @param mask        [out] The destination
   @param masklen     The length of the mask desired
   @return CRYPT_OK if successful
*/
int pkcs_1_mgf1(const struct algo_properties_st *hash,
		const unsigned char *seed, unsigned long seedlen,
		unsigned char *mask, unsigned long masklen)
{
	unsigned long hLen, x;
	ulong32 counter;
	int err;
	unsigned char *buf;

	LTC_ARGCHK(seed != NULL);
	LTC_ARGCHK(mask != NULL);

	/* ensure valid hash */
	if ((err = hash_is_valid(hash)) != CRYPT_OK) {
		return err;
	}

	/* get hash output size */
	hLen = hash->digest_size;

	/* allocate memory */
	buf = XMALLOC(hLen);
	if (buf == NULL) {
		return CRYPT_MEM;
	}

	/* start counter */
	counter = 0;

	while (masklen > 0) {
		/* handle counter */
		STORE32H(counter, buf);
		++counter;

		err =
		    hash_memory_multi(hash, buf, &hLen, seed, seedlen, buf,
				      (unsigned long)4, NULL, 0);
		if (err != CRYPT_OK) {
			goto LBL_ERR;
		}

		/* store it */
		for (x = 0; x < hLen && masklen > 0; x++, masklen--) {
			*mask++ = buf[x];
		}
	}

	err = CRYPT_OK;
LBL_ERR:
#ifdef LTC_CLEAN_STACK
	zeromem(buf, hLen);
#endif

	XFREE(buf);

	return err;
}

#endif /* LTC_PKCS_1 */

/* $Source: /cvs/libtom/libtomcrypt/src/pk/pkcs1/pkcs_1_mgf1.c,v $ */
/* $Revision: 1.8 $ */
/* $Date: 2007/05/12 14:32:35 $ */
