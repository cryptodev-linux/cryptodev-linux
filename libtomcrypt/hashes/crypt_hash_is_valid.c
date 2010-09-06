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
  @file crypt_hash_is_valid.c
  Determine if hash is valid, Tom St Denis
*/

/*
   Test if a hash index is valid
   @param idx   The hash to search for
   @return CRYPT_OK if valid
*/
int hash_is_valid(const struct algo_properties_st *hash)
{
	if (hash->can_digest == 0) return CRYPT_INVALID_ARG;
        
        return CRYPT_OK;
}

/* $Source: /cvs/libtom/libtomcrypt/src/misc/crypt/crypt_hash_is_valid.c,v $ */
/* $Revision: 1.6 $ */
/* $Date: 2006/12/28 01:27:24 $ */
