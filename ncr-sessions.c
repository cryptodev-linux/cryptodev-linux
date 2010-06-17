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

#include <linux/crypto.h>
#include "cryptodev.h"
#include "ncr.h"
#include "ncr_int.h"

static void _ncr_session_remove(struct list_sem_st* lst, ncr_session_t desc);

void ncr_sessions_list_deinit(struct list_sem_st* lst)
{
	if(lst) {
		struct session_item_st * item, *tmp;

		down(&lst->sem);
		
		list_for_each_entry_safe(item, tmp, &lst->list, list) {
			list_del(&item->list);
			_ncr_sessions_item_put( item); /* decrement ref count */
		}
		up(&lst->sem);

	}
}

/* must be called with data semaphore down
 */
static ncr_session_t _ncr_sessions_get_new_desc( struct list_sem_st* lst)
{
struct session_item_st* item;
int mx = 1;

	list_for_each_entry(item, &lst->list, list) {
		mx = max(mx, item->desc);
	}
	mx++;

	return mx;
}

/* returns the data item corresponding to desc */
struct session_item_st* ncr_sessions_item_get( struct list_sem_st* lst, ncr_session_t desc)
{
struct session_item_st* item;

	down(&lst->sem);
	list_for_each_entry(item, &lst->list, list) {
		if (item->desc == desc) {
			atomic_inc(&item->refcnt);
			up(&lst->sem);
			return item;
		}
	}
	up(&lst->sem);

	err();
	return NULL;
}

void _ncr_sessions_item_put( struct session_item_st* item)
{
	if (atomic_dec_and_test(&item->refcnt)) {
		kfree(item);
	}
}

struct session_item_st* ncr_session_new(struct list_sem_st* lst)
{
	struct session_item_st* sess;

	sess = kmalloc(sizeof(*sess), GFP_KERNEL);
	if (sess == NULL) {
		err();
		return NULL;
	}

	memset(sess, 0, sizeof(*sess));

	atomic_set(&sess->refcnt, 1);

	down(&lst->sem);

	sess->desc = _ncr_sessions_get_new_desc(lst);
	list_add(&sess->list, &lst->list);
	
	up(&lst->sem);

	return sess;
}

static const struct algo_properties_st {
	ncr_algorithm_t algo;
	const char* kstr;
	int needs_iv;
	int digest_size;
} algo_properties[] = {
	{ .algo = NCR_ALG_3DES_CBC, .kstr = "cbc(des3_ede)", .needs_iv = 1 },
	{ .algo = NCR_ALG_AES_CBC, .kstr = "cbc(aes)", .needs_iv = 1 },
	{ .algo = NCR_ALG_CAMELLIA_CBC, .kstr = "ecb(camelia)", .needs_iv = 1 },
	{ .algo = NCR_ALG_ARCFOUR, .kstr = NULL, .needs_iv = 0 },
	{ .algo = NCR_ALG_AES_ECB, .kstr = "ecb(aes)", .needs_iv = 0 },
	{ .algo = NCR_ALG_SHA1, .kstr = "sha1", .needs_iv = 0, .digest_size = 20 },
	{ .algo = NCR_ALG_MD5, .kstr = "md5", .needs_iv = 0, .digest_size = 16 },
	{ .algo = NCR_ALG_SHA2_224, .kstr = "sha224", .needs_iv = 0, .digest_size = 28 },
	{ .algo = NCR_ALG_SHA2_256, .kstr = "sha256", .needs_iv = 0, .digest_size = 32 },
	{ .algo = NCR_ALG_SHA2_384, .kstr = "sha384", .needs_iv = 0, .digest_size = 48 },
	{ .algo = NCR_ALG_SHA2_512, .kstr = "sha512", .needs_iv = 0, .digest_size = 64 },
	{ .algo = NCR_ALG_HMAC_SHA1, .kstr = "hmac(sha1)", .needs_iv = 0, .digest_size = 20 },
	{ .algo = NCR_ALG_HMAC_MD5, .kstr = "hmac(md5)", .needs_iv = 0, .digest_size = 16 },
	{ .algo = NCR_ALG_HMAC_SHA2_224, .kstr = "hmac(sha224)", .needs_iv = 0, .digest_size = 28 },
	{ .algo = NCR_ALG_HMAC_SHA2_256, .kstr = "hmac(sha256)", .needs_iv = 0, .digest_size = 32 },
	{ .algo = NCR_ALG_HMAC_SHA2_384, .kstr = "hmac(sha384)", .needs_iv = 0, .digest_size = 48 },
	{ .algo = NCR_ALG_HMAC_SHA2_512, .kstr = "hmac(sha512)", .needs_iv = 0, .digest_size = 64 },
	{ .algo = NCR_ALG_RSA, .kstr = NULL, .needs_iv = 0 },
	{ .algo = NCR_ALG_DSA, .kstr = NULL, .needs_iv = 0 },
	{ .algo = NCR_ALG_NONE }
};

static inline const char* algo2str(ncr_algorithm_t algo)
{
ncr_algorithm_t a;
int i = 0;

	while((a=algo_properties[i].algo)!=NCR_ALG_NONE) {
		if (a == algo)
			return algo_properties[i].kstr;
		i++;
	}

	return NULL;
}

static int algo_needs_iv(ncr_algorithm_t algo)
{
ncr_algorithm_t a;
int i = 0;

	while((a=algo_properties[i].algo)!=NCR_ALG_NONE) {
		if (a == algo)
			return algo_properties[i].needs_iv;
		i++;
	}

	return 0;
}

static int algo_digest_size(ncr_algorithm_t algo)
{
ncr_algorithm_t a;
int i = 0;

	while((a=algo_properties[i].algo)!=NCR_ALG_NONE) {
		if (a == algo)
			return algo_properties[i].digest_size;
		i++;
	}

	return 0;
}

int ncr_session_init(struct ncr_lists* lists, void __user* arg)
{
	struct ncr_session_st session;
	struct session_item_st* ns = NULL;
	struct key_item_st *key = NULL;
	int ret;
	const char* str;

	copy_from_user( &session, arg, sizeof(session));

	str = algo2str(session.algorithm);
	if (str == NULL) {
		err();
		return NCR_SESSION_INVALID;
	}

	ns = ncr_session_new(&lists->sessions);
	if (ns == NULL) {
		err();
		return -EINVAL;
	}

	ns->op = session.op;
	ns->algo = session.algorithm;
	switch(session.op) {
		case NCR_OP_ENCRYPT:
		case NCR_OP_DECRYPT:
			/* read key */
			key = ncr_key_item_get( &lists->key, session.params.key);
			if (key == NULL) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			if (key->type != NCR_KEY_TYPE_SECRET) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			ret = cryptodev_cipher_init(&ns->ctx, str, key->key.secret.data, key->key.secret.size);
			if (ret < 0) {
				err();
				goto fail;
			}

			if (algo_needs_iv(session.algorithm)) {
				if (session.params.params.cipher.iv_size > sizeof(session.params.params.cipher.iv)) {
					err();
					ret = -EINVAL;
					goto fail;
				}
				cryptodev_cipher_set_iv(&ns->ctx, session.params.params.cipher.iv, session.params.params.cipher.iv_size);
			}
			break;

		case NCR_OP_MAC:
			/* read key */
			key = ncr_key_item_get( &lists->key, session.params.key);
			if (key == NULL) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			if (key->type != NCR_KEY_TYPE_SECRET) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			ret = cryptodev_hash_init(&ns->hctx, str, 1, key->key.secret.data, key->key.secret.size);
			if (ret < 0) {
				err();
				goto fail;
			}

			ret = cryptodev_hash_reset(&ns->hctx);
			if (ret < 0) {
				err();
				goto fail;
			}
			break;

		case NCR_OP_DIGEST:
			ret = cryptodev_hash_init(&ns->hctx, str, 0, NULL, 0);
			if (ret < 0) {
				err();
				goto fail;
			}

			ret = cryptodev_hash_reset(&ns->hctx);
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

	ret = 0;

	session.ses = ns->desc;
	copy_to_user( arg, &session, sizeof(session));

fail:
	if (key) _ncr_key_item_put(key);
	if (ret < 0) {
		if (ns->ctx.init)
			cryptodev_cipher_deinit(&ns->ctx);
		if (ns->hctx.init)
			cryptodev_hash_deinit(&ns->hctx);
		_ncr_session_remove(&lists->sessions, ns->desc);
	}

	return ret;
}

int ncr_session_update(struct ncr_lists* lists, void __user* arg)
{
	struct ncr_session_op_st op;
	struct key_item_st *key = NULL;
	int ret;
	struct session_item_st* sess;
	struct data_item_st* data = NULL;
	struct data_item_st* odata = NULL;

	copy_from_user( &op, arg, sizeof(op));

	sess = ncr_sessions_item_get( &lists->sessions, op.ses);
	if (sess == NULL) {
		err();
		return -EINVAL;
	}

	switch(sess->op) {
		case NCR_OP_ENCRYPT:
			/* obtain data item */
			data = ncr_data_item_get( &lists->data, op.data.cipher.plaintext);
			if (data == NULL) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			odata = ncr_data_item_get( &lists->data, op.data.cipher.ciphertext);
			if (odata == NULL) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			if (odata->max_data_size < data->data_size) {
				err();
				ret = -EINVAL;
				goto fail;
			}
			
			/* read key */
			ret = _cryptodev_cipher_encrypt(&sess->ctx, data->data, data->data_size, odata->data, data->data_size);
			if (ret < 0) {
				err();
				goto fail;
			}
			/* FIXME: handle ciphers that do not require that */
			odata->data_size = data->data_size;

			break;
		case NCR_OP_DECRYPT:
			/* obtain data item */
			data = ncr_data_item_get( &lists->data, op.data.cipher.ciphertext);
			if (data == NULL) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			odata = ncr_data_item_get( &lists->data, op.data.cipher.plaintext);
			if (odata == NULL) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			if (odata->max_data_size < data->data_size) {
				err();
				ret = -EINVAL;
				goto fail;
			}
			
			/* read key */
			ret = _cryptodev_cipher_decrypt(&sess->ctx, data->data, data->data_size, odata->data, data->data_size);
			if (ret < 0) {
				err();
				goto fail;
			}
			/* FIXME: handle ciphers that do not require that */
			odata->data_size = data->data_size;

			break;

		case NCR_OP_MAC:
		case NCR_OP_DIGEST:
			/* obtain data item */
			data = ncr_data_item_get( &lists->data, op.data.digest.text);
			if (data == NULL) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			ret = _cryptodev_hash_update(&sess->hctx, data->data, data->data_size);
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

	ret = 0;

fail:
	if (key) _ncr_key_item_put(key);
	if (odata) _ncr_data_item_put(odata);
	if (data) _ncr_data_item_put(data);
	_ncr_sessions_item_put(sess);

	return ret;
}

static void _ncr_session_remove(struct list_sem_st* lst, ncr_session_t desc)
{
	struct session_item_st * item, *tmp;

	down(&lst->sem);
	
	list_for_each_entry_safe(item, tmp, &lst->list, list) {
		if(item->desc == desc) {
			list_del(&item->list);
			_ncr_sessions_item_put( item); /* decrement ref count */
			break;
		}
	}
	
	up(&lst->sem);

	return;
}

int ncr_session_final(struct ncr_lists* lists, void __user* arg)
{
	struct ncr_session_op_st op;
	struct key_item_st *key = NULL;
	int ret;
	struct session_item_st* sess;
	struct data_item_st* data = NULL;
	struct data_item_st* odata = NULL;
	int digest_size;

	copy_from_user( &op, arg, sizeof(op));

	sess = ncr_sessions_item_get( &lists->sessions, op.ses);
	if (sess == NULL) {
		err();
		return -EINVAL;
	}

	switch(sess->op) {
		case NCR_OP_ENCRYPT:
		case NCR_OP_DECRYPT:
			/* obtain data item */
			if (op.data.cipher.plaintext != NCR_DATA_INVALID &&
				op.data.cipher.ciphertext != NCR_DATA_INVALID) {
				ncr_session_update(lists, arg);
			}
			cryptodev_cipher_deinit(&sess->ctx);
			break;
		case NCR_OP_MAC:
		case NCR_OP_DIGEST:
			/* obtain data item */
			if (op.data.digest.text != NCR_DATA_INVALID) {
				ncr_session_update(lists, arg);
			}
			odata = ncr_data_item_get( &lists->data, op.data.digest.output);
			if (odata == NULL) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			digest_size = algo_digest_size(sess->algo);
			if (digest_size == 0 || odata->max_data_size < digest_size) {
				err();
				ret = -EINVAL;
				goto fail;
			}
			ret = cryptodev_hash_final(&sess->hctx, odata->data);
			odata->data_size = digest_size;
			
			cryptodev_hash_deinit(&sess->hctx);
			break;
		default:
			err();
			ret = -EINVAL;
			goto fail;
	}

	ret = 0;

fail:
	if (key) _ncr_key_item_put(key);
	if (odata) _ncr_data_item_put(odata);
	if (data) _ncr_data_item_put(data);
	_ncr_sessions_item_put(sess);
	_ncr_session_remove(&lists->sessions, op.ses);

	return ret;
}

int ncr_session_once(struct ncr_lists* lists, void __user* arg)
{
	struct __user ncr_session_once_op_st* op = arg;
	struct ncr_session_once_op_st kop;
	int ret;

	ret = ncr_session_init(lists, &op->init);
	if (ret < 0) {
		err();
		return ret;
	}

	copy_from_user(&kop, arg, sizeof(kop));
	kop.op.ses = kop.init.ses;
	copy_to_user(arg, &kop, sizeof(kop));

	ret = ncr_session_final(lists, &op->op);
	if (ret < 0) {
		err();
		return ret;
	}

	return 0;
}

