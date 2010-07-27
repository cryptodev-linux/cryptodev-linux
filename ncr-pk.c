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

#include <linux/mm.h>
#include <linux/random.h>
#include "cryptodev.h"
#include <asm/uaccess.h>
#include <asm/ioctl.h>
#include <linux/scatterlist.h>
#include "ncr.h"
#include "ncr-int.h"
#include <tomcrypt.h>

static struct workqueue_struct * pk_wq = NULL;

static int tomerr(int err)
{
	switch (err) {
		case CRYPT_BUFFER_OVERFLOW:
			return -EOVERFLOW;
		case CRYPT_MEM:
			return -ENOMEM;
		default:
			return -EINVAL;
	}
}

void ncr_pk_clear(struct key_item_st* key)
{
	if (key->algorithm == NULL)
		return;
	switch(key->algorithm->algo) {
		case NCR_ALG_RSA:
			rsa_free(&key->key.pk.rsa);
			break;
		case NCR_ALG_DSA:
			dsa_free(&key->key.pk.dsa);
			break;
		default:
			return;
	}
}

static int ncr_pk_make_public_and_id( struct key_item_st * private, struct key_item_st * public)
{
	uint8_t * tmp;
	unsigned long max_size;
	int ret, cret;
	unsigned long key_id_size;

	max_size = KEY_DATA_MAX_SIZE;
	tmp = kmalloc(max_size, GFP_KERNEL);
	if (tmp == NULL) {
		err();
		return -ENOMEM;
	}

	switch(private->algorithm->algo) {
		case NCR_ALG_RSA:
			cret = rsa_export(tmp, &max_size, PK_PUBLIC, &private->key.pk.rsa);
			if (cret != CRYPT_OK) {
				err();
				ret = tomerr(cret);
				goto fail;
			}

			cret = rsa_import(tmp, max_size, &public->key.pk.rsa);
			if (cret != CRYPT_OK) {
				err();
				ret = tomerr(cret);
				goto fail;
			}
			break;
		case NCR_ALG_DSA:
			cret = dsa_export(tmp, &max_size, PK_PUBLIC, &private->key.pk.dsa);
			if (cret != CRYPT_OK) {
				err();
				ret = tomerr(cret);
				goto fail;
			}

			cret = dsa_import(tmp, max_size, &public->key.pk.dsa);
			if (cret != CRYPT_OK) {
				err();
				ret = tomerr(cret);
				goto fail;
			}
			break;
		default:
			err();
			ret = -EINVAL;
			goto fail;
	}

	key_id_size = MAX_KEY_ID_SIZE;
	cret = hash_memory(_ncr_algo_to_properties(NCR_ALG_SHA1), tmp, max_size, private->key_id, &key_id_size);
	if (cret != CRYPT_OK) {
		err();
		ret = tomerr(cret);
		goto fail;
	}
	private->key_id_size = public->key_id_size = key_id_size;
	memcpy(public->key_id, private->key_id, key_id_size);			

	ret = 0;
fail:	
	kfree(tmp);
	
	return ret;
}

int ncr_pk_pack( const struct key_item_st * key, uint8_t * packed, uint32_t * packed_size)
{
	unsigned long max_size = *packed_size;
	int cret;

	if (packed == NULL || packed_size == NULL) {
		err();
		return -EINVAL;
	}

	switch(key->algorithm->algo) {
		case NCR_ALG_RSA:
			cret = rsa_export(packed, &max_size, key->key.pk.rsa.type, (void*)&key->key.pk.rsa);
			if (cret != CRYPT_OK) {
				*packed_size = max_size;
				err();
				return tomerr(cret);
			}
			break;
		case NCR_ALG_DSA:
			cret = dsa_export(packed, &max_size, key->key.pk.dsa.type, (void*)&key->key.pk.dsa);
			if (cret != CRYPT_OK) {
				*packed_size = max_size;
				err();
				return tomerr(cret);
			}
			break;
		default:
			err();
			return -EINVAL;
	}

	*packed_size = max_size;
	return 0;
}

int ncr_pk_unpack( struct key_item_st * key, const void * packed, size_t packed_size)
{
	int cret;

	if (key == NULL || packed == NULL) {
		err();
		return -EINVAL;
	}

	switch(key->algorithm->algo) {
		case NCR_ALG_RSA:
			cret = rsa_import(packed, packed_size, (void*)&key->key.pk.rsa);
			if (cret != CRYPT_OK) {
				err();
				return tomerr(cret);
			}
			break;
		case NCR_ALG_DSA:
			cret = dsa_import(packed, packed_size, (void*)&key->key.pk.dsa);
			if (cret != CRYPT_OK) {
				err();
				return tomerr(cret);
			}
			break;
		default:
			err();
			return -EINVAL;
	}

	return 0;
}

struct keygen_st {
	struct work_struct pk_gen;
	struct completion completed;
	int ret;
	const struct algo_properties_st *algo;
	struct key_item_st* private;
	struct key_item_st* public;
	struct ncr_key_generate_params_st * params;
};

static void keygen_handler(struct work_struct *instance)
{
	unsigned long e;
	int cret;
	struct keygen_st *st =
	    container_of(instance, struct keygen_st, pk_gen);

	switch(st->algo->algo) {
		case NCR_ALG_RSA:
			e = st->params->params.rsa.e;
			
			if (e == 0)
				e = 65537;
			cret = rsa_make_key(st->params->params.rsa.bits/8, e, &st->private->key.pk.rsa);
			if (cret != CRYPT_OK) {
				err();
				st->ret = tomerr(cret);
			} else
				st->ret = 0;
			break;
		case NCR_ALG_DSA:
			if (st->params->params.dsa.q_bits==0)
				st->params->params.dsa.q_bits = 160;
			if (st->params->params.dsa.p_bits==0)
				st->params->params.dsa.p_bits = 1024;

			cret = dsa_make_key(st->params->params.dsa.q_bits/8, 
				st->params->params.dsa.p_bits/8, &st->private->key.pk.dsa);
			if (cret != CRYPT_OK) {
				err();
				st->ret = tomerr(cret);
			} else 
				st->ret = 0;
			break;
		default:
			err();
			st->ret = -EINVAL;
	}

	complete(&st->completed);
}


int ncr_pk_generate(const struct algo_properties_st *algo,
	struct ncr_key_generate_params_st * params,
	struct key_item_st* private, struct key_item_st* public) 
{
int ret;
struct keygen_st st;

	private->algorithm = public->algorithm = algo;

	st.algo = algo;
	st.private = private;
	st.public = public;
	st.params = params;
	st.ret = 0;
	
	init_completion(&st.completed);
	INIT_WORK(&st.pk_gen, keygen_handler);
	
	ret = queue_work(pk_wq, &st.pk_gen);
	if (ret < 0) {
		err();
		return ret;
	}

	wait_for_completion(&st.completed);
	if (st.ret < 0) {
		err();
		return st.ret;
	}

	ret = ncr_pk_make_public_and_id(private, public);
	if (ret < 0) {
		err();
		return ret;
	}
	
	return 0;
}

int ncr_pk_queue_init(void)
{
	pk_wq =
	    create_singlethread_workqueue("ncr-pk");
	if (pk_wq == NULL) {
		err();
		return -ENOMEM;
	}
	
	return 0;
}

void ncr_pk_queue_deinit(void)
{
	flush_workqueue(pk_wq);
	destroy_workqueue(pk_wq);
}

const struct algo_properties_st *ncr_key_params_get_sign_hash(const struct algo_properties_st *algo, struct ncr_key_params_st * params)
{
	ncr_algorithm_t id;

	switch(algo->algo) {
		case NCR_ALG_RSA:
			id = params->params.rsa.sign_hash;
			break;
		case NCR_ALG_DSA:
			id = params->params.dsa.sign_hash;
			break;
		default:
			return ERR_PTR(-EINVAL);
	}
	return _ncr_algo_to_properties(id);
}

/* Encryption/Decryption
 */

void ncr_pk_cipher_deinit(struct ncr_pk_ctx* ctx)
{
	if (ctx->init) {
		ctx->init = 0;
		ctx->key = NULL;
	}
}

int ncr_pk_cipher_init(const struct algo_properties_st *algo,
	struct ncr_pk_ctx* ctx, struct ncr_key_params_st* params,
	struct key_item_st *key, const struct algo_properties_st *sign_hash)
{
	memset(ctx, 0, sizeof(*ctx));
	
	if (key->algorithm != algo) {
		err();
		return -EINVAL;
	}

	ctx->algorithm = algo;
	ctx->key = key;
	ctx->sign_hash = sign_hash;

	switch(algo->algo) {
		case NCR_ALG_RSA:
			if (params->params.rsa.type == RSA_PKCS1_V1_5)
				ctx->type = LTC_LTC_PKCS_1_V1_5;
			else if (params->params.rsa.type == RSA_PKCS1_OAEP) {
				ctx->type = LTC_LTC_PKCS_1_OAEP;
				ctx->oaep_hash = _ncr_algo_to_properties(params->params.rsa.oaep_hash);
				if (ctx->oaep_hash == NULL) {
				  err();
				  return -EINVAL;
				}
			} else if (params->params.rsa.type == RSA_PKCS1_PSS) {
				ctx->type = LTC_LTC_PKCS_1_PSS;
			} else {
				err();
				return -EINVAL;
			}

			ctx->salt_len = params->params.rsa.pss_salt;
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

int ncr_pk_cipher_encrypt(const struct ncr_pk_ctx* ctx, 
	const struct scatterlist* isg, unsigned int isg_cnt, size_t isg_size,
	struct scatterlist *osg, unsigned int osg_cnt, size_t* osg_size)
{
int cret, ret;
unsigned long osize = *osg_size;
uint8_t* tmp;
void * input, *output;

	tmp = kmalloc(isg_size + *osg_size, GFP_KERNEL);
	if (tmp == NULL) {
		err();
		return -ENOMEM;
	}

	ret = sg_copy_to_buffer((struct scatterlist*)isg, isg_cnt, tmp, isg_size);
	if (ret != isg_size) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	input = tmp;
	output = &tmp[isg_size];


	switch(ctx->algorithm->algo) {
		case NCR_ALG_RSA:
			cret = rsa_encrypt_key_ex( input, isg_size, output, &osize, 
				NULL, 0, ctx->oaep_hash, ctx->type, &ctx->key->key.pk.rsa);

			if (cret != CRYPT_OK) {
				err();
				ret = tomerr(cret);
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

int ncr_pk_cipher_decrypt(const struct ncr_pk_ctx* ctx, 
	const struct scatterlist* isg, unsigned int isg_cnt, size_t isg_size,
	struct scatterlist *osg, unsigned int osg_cnt, size_t* osg_size)
{
int cret, ret;
int stat;
unsigned long osize = *osg_size;
uint8_t* tmp;
void * input, *output;

	tmp = kmalloc(isg_size + *osg_size, GFP_KERNEL);
	if (tmp == NULL) {
		err();
		return -ENOMEM;
	}

	input = tmp;
	output = &tmp[isg_size];

	ret = sg_copy_to_buffer((struct scatterlist*)isg, isg_cnt, input, isg_size);
	if (ret != isg_size) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	switch(ctx->algorithm->algo) {
		case NCR_ALG_RSA:
			cret = rsa_decrypt_key_ex( input, isg_size, output, &osize, 
				NULL, 0, ctx->oaep_hash, ctx->type, &stat, &ctx->key->key.pk.rsa);

			if (cret != CRYPT_OK) {
				err();
				ret = tomerr(cret);
				goto fail;
			}

			if (stat==0) {
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

int ncr_pk_cipher_sign(const struct ncr_pk_ctx* ctx, 
	const struct scatterlist* isg, unsigned int isg_cnt, size_t isg_size,
	struct scatterlist *osg, unsigned int osg_cnt, size_t* osg_size)
{
int cret, ret;
unsigned long osize = *osg_size;
uint8_t* tmp;
void * input, *output;

	tmp = kmalloc(isg_size + *osg_size, GFP_KERNEL);
	if (tmp == NULL) {
		err();
		return -ENOMEM;
	}

	input = tmp;
	output = &tmp[isg_size];

	ret = sg_copy_to_buffer((struct scatterlist*)isg, isg_cnt, input, isg_size);
	if (ret != isg_size) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	switch(ctx->algorithm->algo) {
		case NCR_ALG_RSA:
			cret = rsa_sign_hash_ex( input, isg_size, output, &osize, 
				ctx->type, ctx->sign_hash, ctx->salt_len, &ctx->key->key.pk.rsa);
			if (cret != CRYPT_OK) {
				err();
				return tomerr(cret);
			}
			*osg_size = osize;
			break;
		case NCR_ALG_DSA:
			cret = dsa_sign_hash( input, isg_size, output, &osize, 
				&ctx->key->key.pk.dsa);

			if (cret != CRYPT_OK) {
				err();
				return tomerr(cret);
			}
			*osg_size = osize;
			break;
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

int ncr_pk_cipher_verify(const struct ncr_pk_ctx* ctx, 
	const struct scatterlist* sign_sg, unsigned int sign_sg_cnt, size_t sign_sg_size,
	const void* hash, size_t hash_size, ncr_error_t*  err)
{
int cret, ret;
int stat = 0;
uint8_t* sig;

	sig = kmalloc(sign_sg_size, GFP_KERNEL);
	if (sig == NULL) {
		err();
		return -ENOMEM;
	}

	ret = sg_copy_to_buffer((struct scatterlist*)sign_sg, sign_sg_cnt, sig, sign_sg_size);
	if (ret != sign_sg_size) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	switch(ctx->algorithm->algo) {
		case NCR_ALG_RSA:
			cret = rsa_verify_hash_ex( sig, sign_sg_size, 
				hash, hash_size, ctx->type, ctx->sign_hash,
				ctx->salt_len, &stat, &ctx->key->key.pk.rsa);
			if (cret != CRYPT_OK) {
				err();
				ret = tomerr(cret);
				goto fail;
			}

			if (stat == 1)
				*err = 0;
			else
				*err = NCR_VERIFICATION_FAILED;
			
			break;
		case NCR_ALG_DSA:
			cret = dsa_verify_hash( sig, sign_sg_size,
				hash, hash_size, &stat, &ctx->key->key.pk.dsa);
			if (cret != CRYPT_OK) {
				err();
				ret = tomerr(cret);
				goto fail;
			}

			if (stat == 1)
				*err = 0;
			else
				*err = NCR_VERIFICATION_FAILED;

			break;
		default:
			err();
			ret = -EINVAL;
			goto fail;
	}

	ret = 0;
fail:
	kfree(sig);
	return ret;
}
