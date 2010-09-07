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
#include <net/netlink.h>
#include "ncr.h"
#include "ncr-int.h"
#include <tomcrypt.h>

#ifdef CONFIG_CRYPTO_USERSPACE_ASYMMETRIC

int _ncr_tomerr(int err)
{
	switch (err) {
	case CRYPT_BUFFER_OVERFLOW:
		return -ERANGE;
	case CRYPT_MEM:
		return -ENOMEM;
	default:
		return -EINVAL;
	}
}

void ncr_pk_clear(struct key_item_st *key)
{
	if (key->algorithm == NULL)
		return;
	switch (key->algorithm->algo) {
	case NCR_ALG_RSA:
		rsa_free(&key->key.pk.rsa);
		break;
	case NCR_ALG_DSA:
		dsa_free(&key->key.pk.dsa);
		break;
	case NCR_ALG_DH:
		dh_free(&key->key.pk.dh);
		break;
	default:
		return;
	}
}

static int ncr_pk_make_public_and_id(struct key_item_st *private,
				     struct key_item_st *public)
{
	uint8_t *tmp;
	unsigned long max_size;
	int ret, cret;
	unsigned long key_id_size;

	max_size = KEY_DATA_MAX_SIZE;
	tmp = kmalloc(max_size, GFP_KERNEL);
	if (tmp == NULL) {
		err();
		return -ENOMEM;
	}

	switch (private->algorithm->algo) {
	case NCR_ALG_RSA:
		cret =
		    rsa_export(tmp, &max_size, PK_PUBLIC, &private->key.pk.rsa);
		if (cret != CRYPT_OK) {
			err();
			ret = _ncr_tomerr(cret);
			goto fail;
		}

		cret = rsa_import(tmp, max_size, &public->key.pk.rsa);
		if (cret != CRYPT_OK) {
			err();
			ret = _ncr_tomerr(cret);
			goto fail;
		}
		break;
	case NCR_ALG_DSA:
		cret =
		    dsa_export(tmp, &max_size, PK_PUBLIC, &private->key.pk.dsa);
		if (cret != CRYPT_OK) {
			err();
			ret = _ncr_tomerr(cret);
			goto fail;
		}

		cret = dsa_import(tmp, max_size, &public->key.pk.dsa);
		if (cret != CRYPT_OK) {
			err();
			ret = _ncr_tomerr(cret);
			goto fail;
		}
		break;
	case NCR_ALG_DH:
		ret =
		    dh_generate_public(&public->key.pk.dh, &private->key.pk.dh);
		if (ret < 0) {
			err();
			goto fail;
		}
		break;
	default:
		err();
		ret = -EINVAL;
		goto fail;
	}

	key_id_size = MAX_KEY_ID_SIZE;
	cret = hash_memory(_ncr_algo_to_properties(NCR_ALG_SHA1), tmp, max_size,
			   private->key_id, &key_id_size);
	if (cret != CRYPT_OK) {
		err();
		ret = _ncr_tomerr(cret);
		goto fail;
	}
	private->key_id_size = public->key_id_size = key_id_size;
	memcpy(public->key_id, private->key_id, key_id_size);

	ret = 0;
fail:
	kfree(tmp);

	return ret;
}

int ncr_pk_pack(const struct key_item_st *key, uint8_t * packed,
		uint32_t * packed_size)
{
	unsigned long max_size = *packed_size;
	int cret, ret;

	if (packed == NULL || packed_size == NULL) {
		err();
		return -EINVAL;
	}

	switch (key->algorithm->algo) {
	case NCR_ALG_RSA:
		cret =
		    rsa_export(packed, &max_size, key->key.pk.rsa.type,
			       (void *)&key->key.pk.rsa);
		if (cret != CRYPT_OK) {
			*packed_size = max_size;
			err();
			return _ncr_tomerr(cret);
		}
		break;
	case NCR_ALG_DSA:
		cret =
		    dsa_export(packed, &max_size, key->key.pk.dsa.type,
			       (void *)&key->key.pk.dsa);
		if (cret != CRYPT_OK) {
			*packed_size = max_size;
			err();
			return _ncr_tomerr(cret);
		}
		break;
	case NCR_ALG_DH:
		ret =
		    dh_export(packed, &max_size, key->key.pk.dh.type,
			      (void *)&key->key.pk.dh);
		if (ret < 0) {
			*packed_size = max_size;
			err();
			return ret;
		}
		break;
	default:
		err();
		return -EINVAL;
	}

	*packed_size = max_size;

	return 0;
}

int ncr_pk_unpack(struct key_item_st *key, const void *packed,
		  size_t packed_size)
{
	int cret, ret;

	if (key == NULL || packed == NULL) {
		err();
		return -EINVAL;
	}

	switch (key->algorithm->algo) {
	case NCR_ALG_RSA:
		cret =
		    rsa_import(packed, packed_size, (void *)&key->key.pk.rsa);
		if (cret != CRYPT_OK) {
			err();
			return _ncr_tomerr(cret);
		}
		break;
	case NCR_ALG_DSA:
		cret =
		    dsa_import(packed, packed_size, (void *)&key->key.pk.dsa);
		if (cret != CRYPT_OK) {
			err();
			return _ncr_tomerr(cret);
		}
		break;
	case NCR_ALG_DH:
		ret = dh_import(packed, packed_size, (void *)&key->key.pk.dh);
		if (ret < 0) {
			err();
			return ret;
		}
		break;
	default:
		err();
		return -EINVAL;
	}

	return 0;
}

static int binary_to_ulong(unsigned long *dest, const struct nlattr *nla)
{
	unsigned long value;
	const uint8_t *start, *end, *p;

	value = 0;
	start = nla_data(nla);
	end = start + nla_len(nla);
	for (p = start; p < end; p++) {
		if (value > (ULONG_MAX - *p) / 256)
			return -EOVERFLOW;
		value = value * 256 + *p;
	}
	*dest = value;
	return 0;
}

int ncr_pk_generate(const struct algo_properties_st *algo, struct nlattr *tb[],
		    struct key_item_st *private, struct key_item_st *public)
{
	const struct nlattr *nla;
	unsigned long e;
	int cret, ret;

	private->algorithm = public->algorithm = algo;

	ret = 0;
	switch (algo->algo) {
	case NCR_ALG_RSA:
		nla = tb[NCR_ATTR_RSA_E];
		if (nla != NULL) {
			ret = binary_to_ulong(&e, nla);
			if (ret != 0)
				break;
		} else
			e = 65537;

		nla = tb[NCR_ATTR_RSA_MODULUS_BITS];
		if (nla == NULL) {
			ret = -EINVAL;
			break;
		}
		cret =
		    rsa_make_key(nla_get_u32(nla) / 8, e, &private->key.pk.rsa);
		if (cret != CRYPT_OK) {
			err();
			return _ncr_tomerr(cret);
		}
		break;
	case NCR_ALG_DSA:{
			u32 q_bits, p_bits;

			nla = tb[NCR_ATTR_DSA_Q_BITS];
			if (nla != NULL)
				q_bits = nla_get_u32(nla);
			else
				q_bits = 160;
			nla = tb[NCR_ATTR_DSA_P_BITS];
			if (nla != NULL)
				p_bits = nla_get_u32(nla);
			else
				p_bits = 1024;
			cret = dsa_make_key(q_bits / 8, p_bits / 8,
					    &private->key.pk.dsa);
			if (cret != CRYPT_OK) {
				err();
				return _ncr_tomerr(cret);
			}
			break;
		}
	case NCR_ALG_DH:{
			const struct nlattr *p, *g;

			p = tb[NCR_ATTR_DH_PRIME];
			g = tb[NCR_ATTR_DH_BASE];
			if (p == NULL || g == NULL) {
				ret = -EINVAL;
				goto fail;
			}

			ret = dh_import_params(&private->key.pk.dh, nla_data(p),
					       nla_len(p), nla_data(g),
					       nla_len(g));
			if (ret < 0) {
				err();
				goto fail;
			}

			ret = dh_generate_key(&private->key.pk.dh);
			if (ret < 0) {
				err();
				goto fail;
			}
			break;
		}
	default:
		err();
		return -EINVAL;
	}

fail:
	if (ret < 0) {
		err();
		return ret;
	}

	ret = ncr_pk_make_public_and_id(private, public);
	if (ret < 0) {
		err();
		return ret;
	}

	return 0;
}

/* Encryption/Decryption
 */

void ncr_pk_cipher_deinit(struct ncr_pk_ctx *ctx)
{
	if (ctx->init) {
		ctx->init = 0;
		ctx->key = NULL;
	}
}

int ncr_pk_cipher_init(const struct algo_properties_st *algo,
		       struct ncr_pk_ctx *ctx, struct nlattr *tb[],
		       struct key_item_st *key,
		       const struct algo_properties_st *sign_hash)
{
	const struct nlattr *nla;

	memset(ctx, 0, sizeof(*ctx));

	/* Allow using the same key for transparent and non-transparent
	   hashing. */
	if (key->algorithm->algo != algo->algo) {
		err();
		return -EINVAL;
	}

	ctx->algorithm = algo;
	ctx->key = key;
	ctx->sign_hash = sign_hash;
	ctx->salt_len = 0;

	switch (algo->algo) {
	case NCR_ALG_RSA:
		nla = tb[NCR_ATTR_RSA_ENCODING_METHOD];
		if (nla == NULL) {
			err();
			return -EINVAL;
		}
		switch (nla_get_u32(nla)) {
		case RSA_PKCS1_V1_5:
			ctx->type = LTC_LTC_PKCS_1_V1_5;
			break;
		case RSA_PKCS1_OAEP:
			ctx->type = LTC_LTC_PKCS_1_OAEP;
			nla = tb[NCR_ATTR_RSA_OAEP_HASH_ALGORITHM];
			ctx->oaep_hash = _ncr_nla_to_properties(nla);
			if (ctx->oaep_hash == NULL) {
				err();
				return -EINVAL;
			}
			break;
		case RSA_PKCS1_PSS:
			ctx->type = LTC_LTC_PKCS_1_PSS;
			nla = tb[NCR_ATTR_RSA_PSS_SALT_LENGTH];
			if (nla != NULL)
				ctx->salt_len = nla_get_u32(nla);
			break;
		default:
			err();
			return -EINVAL;
		}
		break;
	case NCR_ALG_DSA:
		break;
	default:
		err();
		return -EINVAL;
	}

	ctx->init = 1;

	return 0;
}

int ncr_pk_cipher_encrypt(const struct ncr_pk_ctx *ctx,
			  const struct scatterlist *isg, unsigned int isg_cnt,
			  size_t isg_size, struct scatterlist *osg,
			  unsigned int osg_cnt, size_t * osg_size)
{
	int cret, ret;
	unsigned long osize = *osg_size;
	uint8_t *tmp;
	void *input, *output;

	tmp = kmalloc(isg_size + *osg_size, GFP_KERNEL);
	if (tmp == NULL) {
		err();
		return -ENOMEM;
	}

	ret =
	    sg_copy_to_buffer((struct scatterlist *)isg, isg_cnt, tmp,
			      isg_size);
	if (ret != isg_size) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	input = tmp;
	output = &tmp[isg_size];

	switch (ctx->algorithm->algo) {
	case NCR_ALG_RSA:
		cret = rsa_encrypt_key_ex(input, isg_size, output, &osize,
					  NULL, 0, ctx->oaep_hash, ctx->type,
					  &ctx->key->key.pk.rsa);

		if (cret != CRYPT_OK) {
			err();
			ret = _ncr_tomerr(cret);
			goto fail;
		}
		*osg_size = osize;

		break;
	case NCR_ALG_DSA:
		ret = -EINVAL;
		goto fail;
	default:
		err();
		ret = -EINVAL;
		goto fail;
	}

	ret = sg_copy_from_buffer(osg, osg_cnt, output, *osg_size);
	if (ret != *osg_size) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	ret = 0;

fail:
	kfree(tmp);
	return ret;
}

int ncr_pk_cipher_decrypt(const struct ncr_pk_ctx *ctx,
			  const struct scatterlist *isg, unsigned int isg_cnt,
			  size_t isg_size, struct scatterlist *osg,
			  unsigned int osg_cnt, size_t * osg_size)
{
	int cret, ret;
	int stat;
	unsigned long osize = *osg_size;
	uint8_t *tmp;
	void *input, *output;

	tmp = kmalloc(isg_size + *osg_size, GFP_KERNEL);
	if (tmp == NULL) {
		err();
		return -ENOMEM;
	}

	input = tmp;
	output = &tmp[isg_size];

	ret =
	    sg_copy_to_buffer((struct scatterlist *)isg, isg_cnt, input,
			      isg_size);
	if (ret != isg_size) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	switch (ctx->algorithm->algo) {
	case NCR_ALG_RSA:
		cret = rsa_decrypt_key_ex(input, isg_size, output, &osize,
					  NULL, 0, ctx->oaep_hash, ctx->type,
					  &stat, &ctx->key->key.pk.rsa);

		if (cret != CRYPT_OK) {
			err();
			ret = _ncr_tomerr(cret);
			goto fail;
		}

		if (stat == 0) {
			err();
			ret = -EINVAL;
			goto fail;
		}
		*osg_size = osize;
		break;
	case NCR_ALG_DSA:
		ret = -EINVAL;
		goto fail;
	default:
		err();
		ret = -EINVAL;
		goto fail;
	}

	ret = sg_copy_from_buffer(osg, osg_cnt, output, *osg_size);
	if (ret != *osg_size) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	ret = 0;
fail:
	kfree(tmp);

	return ret;
}

int ncr_pk_cipher_sign(const struct ncr_pk_ctx *ctx, const void *hash,
		       size_t hash_size, void *sig, size_t * sig_size)
{
	int cret;
	unsigned long osize = *sig_size;

	switch (ctx->algorithm->algo) {
	case NCR_ALG_RSA:
		if (ctx->sign_hash == NULL) {
			err();
			return -EINVAL;
		}
		cret = rsa_sign_hash_ex(hash, hash_size, sig, &osize,
					ctx->type, ctx->sign_hash,
					ctx->salt_len, &ctx->key->key.pk.rsa);
		if (cret != CRYPT_OK) {
			err();
			return _ncr_tomerr(cret);
		}
		*sig_size = osize;
		break;
	case NCR_ALG_DSA:
		cret = dsa_sign_hash(hash, hash_size, sig, &osize,
				     &ctx->key->key.pk.dsa);

		if (cret != CRYPT_OK) {
			err();
			return _ncr_tomerr(cret);
		}
		*sig_size = osize;
		break;
	default:
		err();
		return -EINVAL;
	}
	return 0;
}

int ncr_pk_cipher_verify(const struct ncr_pk_ctx *ctx, const void *sig,
			 size_t sig_size, const void *hash, size_t hash_size)
{
	int cret, ret, stat;

	switch (ctx->algorithm->algo) {
	case NCR_ALG_RSA:
		if (ctx->sign_hash == NULL) {
			err();
			return -EINVAL;
		}
		cret = rsa_verify_hash_ex(sig, sig_size, hash,
					  hash_size, ctx->type,
					  ctx->sign_hash, ctx->salt_len,
					  &stat, &ctx->key->key.pk.rsa);
		if (cret != CRYPT_OK) {
			err();
			ret = _ncr_tomerr(cret);
			goto fail;
		}

		ret = (stat == 1);
		break;
	case NCR_ALG_DSA:
		cret = dsa_verify_hash(sig, sig_size, hash, hash_size,
				       &stat, &ctx->key->key.pk.dsa);
		if (cret != CRYPT_OK) {
			err();
			ret = _ncr_tomerr(cret);
			goto fail;
		}

		ret = (stat == 1);
		break;
	default:
		err();
		ret = -EINVAL;
		goto fail;
	}

fail:
	return ret;
}

int ncr_pk_derive(struct key_item_st *newkey, struct key_item_st *oldkey,
		  struct nlattr *tb[])
{
	const struct nlattr *nla;
	int ret;

	nla = tb[NCR_ATTR_DERIVATION_ALGORITHM];
	if (nla == NULL) {
		err();
		return -EINVAL;
	}
	if (nla_strcmp(nla, NCR_DERIVE_DH) == 0) {
		if (oldkey->type != NCR_KEY_TYPE_PRIVATE &&
		    oldkey->algorithm->algo != NCR_ALG_DH) {
			err();
			return -EINVAL;
		}

		nla = tb[NCR_ATTR_DH_PUBLIC];
		if (nla == NULL) {
			err();
			return -EINVAL;
		}
		ret = dh_derive_gxy(newkey, &oldkey->key.pk.dh, nla_data(nla),
				    nla_len(nla));
		if (ret < 0) {
			err();
			return ret;
		}
	} else {
		err();
		return -EINVAL;
	}

	return 0;
}

int ncr_pk_get_rsa_size(rsa_key * key)
{
	int ret;
	ret = mp_count_bits(&key->N);
	if (ret <= 0) {
		err();
		return -EINVAL;
	}

	return ret;
}

int ncr_pk_get_dsa_size(dsa_key * key)
{
	int ret;
	ret = mp_count_bits(&key->p);
	if (ret <= 0) {
		err();
		return -EINVAL;
	}

	return ret;
}

#endif /* CONFIG_CRYPTO_USERSPACE_ASYMMETRIC */
