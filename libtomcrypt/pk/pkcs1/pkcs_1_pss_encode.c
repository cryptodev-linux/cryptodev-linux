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
  @file pkcs_1_pss_encode.c
  LTC_PKCS #1 PSS Signature Padding, Tom St Denis 
*/

#ifdef LTC_PKCS_1

/**
   LTC_PKCS #1 v2.00 Signature Encoding
   @param msghash          The hash to encode
   @param msghashlen       The length of the hash (octets)
   @param saltlen          The length of the salt desired (octets)
   @param hash_algo        The desired hash
   @param modulus_bitlen   The bit length of the RSA modulus
   @param out              [out] The destination of the encoding
   @param outlen           [in/out] The max size and resulting size of the encoded data
   @return CRYPT_OK if successful
*/
int pkcs_1_pss_encode(const unsigned char *msghash, unsigned long msghashlen,
		      unsigned long saltlen,
		      const struct algo_properties_st *hash_algo,
		      unsigned long modulus_bitlen, unsigned char *out,
		      unsigned long *outlen)
{
	unsigned char *DB, *mask, *salt, *hash;
	unsigned long x, y, hLen, modulus_len;
	int err;

	LTC_ARGCHK(msghash != NULL);
	LTC_ARGCHK(out != NULL);
	LTC_ARGCHK(outlen != NULL);

	/* ensure hash and PRNG are valid */
	if ((err = hash_is_valid(hash_algo)) != CRYPT_OK) {
		return err;
	}

	hLen = hash_algo->digest_size;
	modulus_len = (modulus_bitlen >> 3) + (modulus_bitlen & 7 ? 1 : 0);

	/* check sizes */
	if ((saltlen > modulus_len) || (modulus_len < hLen + saltlen + 2)) {
		return CRYPT_PK_INVALID_SIZE;
	}

	/* allocate ram for DB/mask/salt/hash of size modulus_len */
	DB = XMALLOC(modulus_len);
	mask = XMALLOC(modulus_len);
	salt = XMALLOC(modulus_len);
	hash = XMALLOC(modulus_len);
	if (DB == NULL || mask == NULL || salt == NULL || hash == NULL) {
		if (DB != NULL) {
			XFREE(DB);
		}
		if (mask != NULL) {
			XFREE(mask);
		}
		if (salt != NULL) {
			XFREE(salt);
		}
		if (hash != NULL) {
			XFREE(hash);
		}
		return CRYPT_MEM;
	}

	/* generate random salt */
	if (saltlen > 0) {
		get_random_bytes(salt, saltlen);
	}

	zeromem(DB, 8);

	/* M = (eight) 0x00 || msghash || salt, hash = H(M) */
	err =
	    hash_memory_multi(hash_algo, hash, &hLen, DB, (unsigned long)8,
			      msghash, (unsigned long)msghashlen, salt,
			      (unsigned long)saltlen, NULL, 0);
	if (err != CRYPT_OK) {
		goto LBL_ERR;
	}

	/* generate DB = PS || 0x01 || salt, PS == modulus_len - saltlen - hLen - 2 zero bytes */
	x = 0;
	XMEMSET(DB + x, 0, modulus_len - saltlen - hLen - 2);
	x += modulus_len - saltlen - hLen - 2;
	DB[x++] = 0x01;
	XMEMCPY(DB + x, salt, saltlen);
	x += saltlen;

	/* generate mask of length modulus_len - hLen - 1 from hash */
	if ((err =
	     pkcs_1_mgf1(hash_algo, hash, hLen, mask,
			 modulus_len - hLen - 1)) != CRYPT_OK) {
		goto LBL_ERR;
	}

	/* xor against DB */
	for (y = 0; y < (modulus_len - hLen - 1); y++) {
		DB[y] ^= mask[y];
	}

	/* output is DB || hash || 0xBC */
	if (*outlen < modulus_len) {
		*outlen = modulus_len;
		err = CRYPT_BUFFER_OVERFLOW;
		goto LBL_ERR;
	}

	/* DB len = modulus_len - hLen - 1 */
	y = 0;
	XMEMCPY(out + y, DB, modulus_len - hLen - 1);
	y += modulus_len - hLen - 1;

	/* hash */
	XMEMCPY(out + y, hash, hLen);
	y += hLen;

	/* 0xBC */
	out[y] = 0xBC;

	/* now clear the 8*modulus_len - modulus_bitlen most significant bits */
	out[0] &= 0xFF >> ((modulus_len << 3) - (modulus_bitlen - 1));

	/* store output size */
	*outlen = modulus_len;
	err = CRYPT_OK;
LBL_ERR:
#ifdef LTC_CLEAN_STACK
	zeromem(DB, modulus_len);
	zeromem(mask, modulus_len);
	zeromem(salt, modulus_len);
	zeromem(hash, modulus_len);
#endif

	XFREE(hash);
	XFREE(salt);
	XFREE(mask);
	XFREE(DB);

	return err;
}

#endif /* LTC_PKCS_1 */

/* $Source: /cvs/libtom/libtomcrypt/src/pk/pkcs1/pkcs_1_pss_encode.c,v $ */
/* $Revision: 1.9 $ */
/* $Date: 2007/05/12 14:32:35 $ */
