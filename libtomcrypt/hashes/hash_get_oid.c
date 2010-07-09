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
#include <ncr_int.h>

/*
   Returns the OID of the hash.
   @param idx   The hash identifier of the hash to search for
   @return CRYPT_OK if valid
*/

static const oid_st sha1_oid = {
   .OIDlen = 6,
   .OID = { 1, 3, 14, 3, 2, 26  },
};

static const oid_st md5_oid = {
   .OIDlen = 6,
   .OID = { 1, 2, 840, 113549, 2, 5,  },
};

static const oid_st sha224_oid = {
   .OIDlen = 9,
   .OID = { 2, 16, 840, 1, 101, 3, 4, 2, 4,  },
};

static const oid_st sha256_oid = {
   .OIDlen = 9,
   .OID = { 2, 16, 840, 1, 101, 3, 4, 2, 1,  },
};

static const oid_st sha384_oid = {
   .OIDlen = 9,
   .OID = { 2, 16, 840, 1, 101, 3, 4, 2, 2,  },
};

static const oid_st sha512_oid = {
   .OIDlen = 9,
   .OID = { 2, 16, 840, 1, 101, 3, 4, 2, 3,  },
};

int hash_get_oid(int hash, oid_st *st)
{
   switch (hash) {
      case NCR_ALG_SHA1:
         memcpy(st, &sha1_oid, sizeof(*st));
         break;
      case NCR_ALG_MD5:
         memcpy(st, &md5_oid, sizeof(*st));
         break;
      case NCR_ALG_SHA2_224:
         memcpy(st, &sha224_oid, sizeof(*st));
         break;
      case NCR_ALG_SHA2_256:
         memcpy(st, &sha256_oid, sizeof(*st));
         break;
      case NCR_ALG_SHA2_384:
         memcpy(st, &sha384_oid, sizeof(*st));
         break;
      case NCR_ALG_SHA2_512:
         memcpy(st, &sha512_oid, sizeof(*st));
         break;
      default:
         return CRYPT_INVALID_ARG;
   }
   return CRYPT_OK;
}

/* $Source: /cvs/libtom/libtomcrypt/src/misc/crypt/crypt_hash_is_valid.c,v $ */
/* $Revision: 1.6 $ */
/* $Date: 2006/12/28 01:27:24 $ */
