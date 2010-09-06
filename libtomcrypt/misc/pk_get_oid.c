/* LibTomCrypt, modular cryptographic library
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 */
#include "tomcrypt.h"
#include <ncr-int.h>

/*
   Returns the OID of the public key algorithm.
   @return CRYPT_OK if valid
*/
int pk_get_oid(const struct algo_properties_st *pk, oid_st * st)
{
	if (pk->is_pk == 0 || pk->oids[0].key_size != -1) { 
		/* not a pk */
		return CRYPT_INVALID_ARG;
	}

	memcpy(st, &pk->oids[0].oid, sizeof(*st));

	return CRYPT_OK;
}
