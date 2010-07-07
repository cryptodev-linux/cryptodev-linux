/*
 * New driver for /dev/crypto device (aka CryptoDev)

 * Copyright (c) 2010 Nikos Mavrogiannopoulos <nmav@gnutls.org>
 *
 * This file is part of linux cryptodev.
 *
 * cryptodev is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cryptodev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/mm.h>
#include <linux/random.h>
#include "cryptodev.h"
#include <asm/uaccess.h>
#include <asm/ioctl.h>
#include <linux/scatterlist.h>
#include "ncr.h"
#include "ncr_int.h"
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
	switch(key->algorithm) {
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
	long max_size;
	int ret, cret;
	unsigned long key_id_size;

	max_size = KEY_DATA_MAX_SIZE;
	tmp = kmalloc(max_size, GFP_KERNEL);
	if (tmp == NULL) {
		err();
		return -ENOMEM;
	}

	switch(private->algorithm) {
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
	cret = hash_memory(NCR_ALG_SHA1, tmp, max_size, private->key_id, &key_id_size);
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

	switch(key->algorithm) {
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

struct keygen_st {
	struct work_struct pk_gen;
	struct completion completed;
	int ret;
	ncr_algorithm_t algo;
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

	switch(st->algo) {
		case NCR_ALG_RSA:
			e = st->params->params.rsa.e;
			
			if (e == 0)
				e = 65537;
			cret = rsa_make_key(st->params->params.rsa.bits/8, e, &st->private->key.pk.rsa);
			if (cret != CRYPT_OK) {
				err();
				st->ret = tomerr(cret);
			}
			
			st->ret = 0;
			break;
		case NCR_ALG_DSA:
			cret = dsa_make_key(st->params->params.dsa.q_bits/8, 
				st->params->params.dsa.p_bits/8, &st->private->key.pk.dsa);
			if (cret != CRYPT_OK) {
				err();
				st->ret = tomerr(cret);
			}
			
			st->ret = 0;
			break;
		default:
			err();
			st->ret = -EINVAL;
	}

	complete(&st->completed);
}


int ncr_pk_generate(ncr_algorithm_t algo,
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
		return ret;
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
