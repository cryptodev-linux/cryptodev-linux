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
   Returns the OID of the hash.
   @param idx   The hash identifier of the hash to search for
   @return CRYPT_OK if valid
*/

int hash_get_oid(const struct algo_properties_st *hash, oid_st * st)
{
	if (hash->can_digest == 0 || hash->oids[0].key_size != -1) { 
		/* not a digest */
		return CRYPT_INVALID_ARG;
	}
	
	memcpy(st, &hash->oids[0].oid, sizeof(*st));

	return CRYPT_OK;
}

/* $Source: /cvs/libtom/libtomcrypt/src/misc/crypt/crypt_hash_is_valid.c,v $ */
/* $Revision: 1.6 $ */
/* $Date: 2006/12/28 01:27:24 $ */
