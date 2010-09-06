/*
 * New driver for /dev/crypto device (aka CryptoDev)

 * Copyright (c) 2010 Katholieke Universiteit Leuven
 *
 * Author: Nikos Mavrogiannopoulos <nmav@gnutls.org>
 *
 * This file is part of linux cryptodev.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include "tomcrypt.h"

/**
  @file der_encode_sequence_multi.c
  ASN.1 DER, encode a Subject Public Key structure --nmav
*/

#ifdef LTC_DER

/* AlgorithmIdentifier := SEQUENCE {
 *    algorithm OBJECT IDENTIFIER,
 *    parameters ANY DEFINED BY algorithm
 * }
 * 
 * SubjectPublicKeyInfo := SEQUENCE {
 *    algorithm AlgorithmIdentifier,
 *    subjectPublicKey BIT STRING
 * }
 */
/**
  Encode a SEQUENCE type using a VA list
  @param out    [out] Destination for data
  @param outlen [in/out] Length of buffer and resulting length of output
  @remark <...> is of the form <type, size, data> (int, unsigned long, void*)
  @return CRYPT_OK on success
*/  
int der_encode_subject_public_key_info(unsigned char *out, unsigned long *outlen, 
        const struct algo_properties_st *algorithm, void* public_key, unsigned long public_key_len, 
        unsigned long parameters_type, void* parameters, unsigned long parameters_len)
{
   int           err;
   ltc_asn1_list alg_id[2];
   oid_st oid;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   
   err = pk_get_oid(algorithm, &oid);
   if (err != CRYPT_OK) {
        return err;
   }

   alg_id[0].data = oid.OID;
   alg_id[0].size = oid.OIDlen;
   alg_id[0].type = LTC_ASN1_OBJECT_IDENTIFIER;

   alg_id[1].data = parameters;
   alg_id[1].size = parameters_len;
   alg_id[1].type = parameters_type;

   return der_encode_sequence_multi(out, outlen, 
        LTC_ASN1_SEQUENCE, (unsigned long)sizeof(alg_id)/sizeof(alg_id[0]), alg_id, 
        LTC_ASN1_BIT_STRING, (unsigned long)(public_key_len*8), public_key,
        LTC_ASN1_EOL,     0UL, NULL);

}

#endif


