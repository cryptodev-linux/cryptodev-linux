/*
 * New driver for /dev/ncr device (aka NCR)

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

#include <linux/ioctl.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/uaccess.h>
#include <linux/scatterlist.h>
#include <ncr.h>
#include <ncr-int.h>
#include <tomcrypt.h>
#include <ncr-dh.h>

void dh_free(dh_key * key)
{
	mp_clear_multi(&key->p, &key->g, &key->x, NULL);
}

int dh_import_params(dh_key * key, uint8_t * p, size_t p_size, uint8_t * g,
		     size_t g_size)
{
	int ret;
	int err;

	if ((err =
	     mp_init_multi(&key->p, &key->g, &key->x, &key->y,
			   NULL)) != CRYPT_OK) {
		err();
		return -ENOMEM;
	}

	if ((err =
	     mp_read_unsigned_bin(&key->p, (unsigned char *)p,
				  p_size)) != CRYPT_OK) {
		err();
		ret = _ncr_tomerr(err);
		goto fail;
	}

	if ((err =
	     mp_read_unsigned_bin(&key->g, (unsigned char *)g,
				  g_size)) != CRYPT_OK) {
		err();
		ret = _ncr_tomerr(err);
		goto fail;
	}

	return 0;
fail:
	mp_clear_multi(&key->p, &key->g, &key->x, &key->y, NULL);

	return ret;
}

int dh_generate_key(dh_key * key)
{
	void *buf;
	int size;
	int err, ret;

	size = mp_unsigned_bin_size(&key->p);
	if (size == 0) {
		err();
		return -EINVAL;
	}

	buf = kmalloc(size, GFP_KERNEL);
	if (buf == NULL) {
		err();
		return -ENOMEM;
	}

	do {
		get_random_bytes(buf, size);

		if ((err =
		     mp_read_unsigned_bin(&key->x, buf, size)) != CRYPT_OK) {
			err();
			ret = _ncr_tomerr(err);
			goto fail;
		}

		err = mp_mod(&key->x, &key->p, &key->x);
		if (err != CRYPT_OK) {
			err();
			ret = _ncr_tomerr(err);
			goto fail;
		}
	} while (mp_cmp_d(&key->x, 0) == MP_EQ
		 || mp_cmp_d(&key->x, 1) == MP_EQ);

	key->type = PK_PRIVATE;

	ret = 0;
fail:
	kfree(buf);

	return ret;

}

int dh_generate_public(dh_key * public, dh_key * private)
{
	int err, ret;

	err = mp_exptmod(&private->g, &private->x, &private->p, &public->y);
	if (err != CRYPT_OK) {
		err();
		ret = _ncr_tomerr(err);
		goto fail;
	}

	public->type = PK_PUBLIC;

	ret = 0;
fail:

	return ret;
}

int dh_export(uint8_t * out, unsigned long *outlen, int type, dh_key * key)
{
	unsigned long zero = 0;
	int err;

	if (out == NULL || outlen == NULL || key == NULL) {
		err();
		return -EINVAL;
	}

	/* can we store the static header?  */
	if (type == PK_PRIVATE && key->type != PK_PRIVATE) {
		return -EINVAL;
	}

	if (type != PK_PUBLIC && type != PK_PRIVATE) {
		return -EINVAL;
	}

	/* This encoding is different from the one in original
	 * libtomcrypt. It uses a compatible encoding with gnutls
	 * and openssl 
	 */
	if (type == PK_PRIVATE) {
		err = der_encode_sequence_multi(out, outlen,
						LTC_ASN1_SHORT_INTEGER, 1UL,
						&zero, LTC_ASN1_INTEGER, 1UL,
						&key->p, LTC_ASN1_INTEGER, 1UL,
						&key->g, LTC_ASN1_INTEGER, 1UL,
						&key->x, LTC_ASN1_EOL, 0UL,
						NULL);
	} else {
		err = mp_unsigned_bin_size(&key->y);
		if (err > *outlen) {
			err();
			return -EOVERFLOW;
		}

		*outlen = err;

		err = mp_to_unsigned_bin(&key->y, out);
	}

	if (err != CRYPT_OK) {
		err();
		return _ncr_tomerr(err);
	}

	return 0;
}

int dh_import(const uint8_t * in, size_t inlen, dh_key * key)
{
	int err;
	unsigned long zero = 0;

	if (in == NULL || key == NULL) {
		err();
		return -EINVAL;
	}

	/* init key */
	if (mp_init_multi(&key->p, &key->g, &key->x, &key->y, NULL) != CRYPT_OK) {
		return -ENOMEM;
	}

	/* get key type */
	if ((err = der_decode_sequence_multi(in, inlen,
					     LTC_ASN1_SHORT_INTEGER, 1UL, &zero,
					     LTC_ASN1_INTEGER, 1UL, &key->p,
					     LTC_ASN1_INTEGER, 1UL, &key->g,
					     LTC_ASN1_INTEGER, 1UL, &key->x,
					     LTC_ASN1_EOL, 0UL,
					     NULL)) == CRYPT_OK) {
		key->type = PK_PRIVATE;
	} else {		/* public */
		err = mp_read_unsigned_bin(&key->y, in, inlen);
		key->type = PK_PUBLIC;
	}

	if (err != CRYPT_OK) {
		goto LBL_ERR;
	}

	return 0;

LBL_ERR:
	mp_clear_multi(&key->p, &key->g, &key->x, &key->y, NULL);
	return _ncr_tomerr(err);
}

int dh_derive_gxy(struct key_item_st *newkey, dh_key * key,
		  void *pk, size_t pk_size)
{
	int ret, err;
	mp_int y, gxy;
	/* newkey will be a secret key with value of g^{xy}
	 */

	if (mp_init_multi(&y, &gxy, NULL) != CRYPT_OK) {
		err();
		return -ENOMEM;
	}

	if (key->type != PK_PRIVATE) {
		err();
		return -EINVAL;
	}

	if ((err = mp_read_unsigned_bin(&y, pk, pk_size)) != CRYPT_OK) {
		err();
		ret = _ncr_tomerr(err);
		goto fail;
	}

	if ((err = mp_exptmod(&y, &key->x, &key->p, &gxy)) != CRYPT_OK) {
		err();
		ret = _ncr_tomerr(err);
		goto fail;
	}

	err = mp_unsigned_bin_size(&gxy);
	if (err > NCR_CIPHER_MAX_KEY_LEN) {
		err();
		ret = -EOVERFLOW;
		goto fail;
	}
	newkey->key.secret.size = err;

	err = mp_to_unsigned_bin(&gxy, newkey->key.secret.data);
	if (err != CRYPT_OK) {
		err();
		ret = _ncr_tomerr(err);
		goto fail;
	}

	newkey->type = NCR_KEY_TYPE_SECRET;

	ret = 0;
fail:
	mp_clear_multi(&y, &gxy, NULL);

	return ret;
}

int ncr_pk_get_dh_size(dh_key * key)
{
	int ret;
	ret = mp_count_bits(&key->p);
	if (ret <= 0) {
		err();
		return -EINVAL;
	}

	return ret;
}
