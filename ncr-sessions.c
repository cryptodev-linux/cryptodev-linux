/*
 * New driver for /dev/crypto device (aka CryptoDev)

 * Copyright (c) 2010 Katholieke Universiteit Leuven
 * Portions Copyright (c) 2010 Phil Sutter
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

#include <linux/crypto.h>
#include "cryptodev.h"
#include "ncr.h"
#include "ncr-int.h"
#include <linux/mm_types.h>
#include <linux/scatterlist.h>

static int _ncr_session_update_key(struct ncr_lists* lists, struct ncr_session_op_st* op);
static void _ncr_session_remove(struct ncr_lists *lst, ncr_session_t desc);

void ncr_sessions_list_deinit(struct ncr_lists *lst_)
{
	struct list_sem_st *lst;
	struct session_item_st * item, *tmp;

	lst = &lst_->sessions;
	down(&lst->sem);

	list_for_each_entry_safe(item, tmp, &lst->list, list) {
		list_del(&item->list);
		_ncr_sessions_item_put( item); /* decrement ref count */
	}
	up(&lst->sem);
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
struct session_item_st* ncr_sessions_item_get(struct ncr_lists *lst_, ncr_session_t desc)
{
struct list_sem_st *lst;
struct session_item_st* item;

	lst = &lst_->sessions;
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
		cryptodev_cipher_deinit(&item->cipher);
		ncr_pk_cipher_deinit(&item->pk);
		cryptodev_hash_deinit(&item->hash);
		if (item->key)
			_ncr_key_item_put(item->key);
		kfree(item->sg);
		kfree(item->pages);
		kfree(item);
	}
}

struct session_item_st* ncr_session_new(struct ncr_lists *lst_)
{
	struct list_sem_st *lst;
	struct session_item_st* sess;

	lst = &lst_->sessions;
	sess = kzalloc(sizeof(*sess), GFP_KERNEL);
	if (sess == NULL) {
		err();
		return NULL;
	}

	sess->array_size = DEFAULT_PREALLOC_PAGES;
	sess->pages = kzalloc(sess->array_size *
			sizeof(struct page *), GFP_KERNEL);
	sess->sg = kzalloc(sess->array_size *
			sizeof(struct scatterlist), GFP_KERNEL);
	if (sess->sg == NULL || sess->pages == NULL) {
		err();
		kfree(sess->sg);
		kfree(sess->pages);
		kfree(sess);
		return NULL;
	}
	init_MUTEX(&sess->mem_mutex);

	atomic_set(&sess->refcnt, 2); /* One for lst->list, one for "sess" */

	down(&lst->sem);

	sess->desc = _ncr_sessions_get_new_desc(lst);
	list_add(&sess->list, &lst->list);
	
	up(&lst->sem);

	return sess;
}

static const struct algo_properties_st algo_properties[] = {
	{ .algo = NCR_ALG_NULL, .kstr = "ecb(cipher_null)", 
		.needs_iv = 0, .is_symmetric=1, .can_encrypt=1,
		.key_type = NCR_KEY_TYPE_INVALID },
	{ .algo = NCR_ALG_3DES_CBC, .kstr = "cbc(des3_ede)", 
		.needs_iv = 1, .is_symmetric=1, .can_encrypt=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ .algo = NCR_ALG_AES_CBC, .kstr = "cbc(aes)", 
		.needs_iv = 1, .is_symmetric=1, .can_encrypt=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ .algo = NCR_ALG_CAMELLIA_CBC, .kstr = "cbc(camelia)", 
		.needs_iv = 1, .is_symmetric=1, .can_encrypt=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ .algo = NCR_ALG_AES_CTR, .kstr = "ctr(aes)", 
		.needs_iv = 1, .is_symmetric=1, .can_encrypt=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ .algo = NCR_ALG_CAMELLIA_CTR, .kstr = "ctr(camelia)", 
		.needs_iv = 1, .is_symmetric=1, .can_encrypt=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ .algo = NCR_ALG_ARCFOUR, .kstr = NULL, 
		.needs_iv = 0, .is_symmetric=1, .can_encrypt=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ .algo = NCR_ALG_AES_ECB, .kstr = "ecb(aes)", 
		.needs_iv = 0, .is_symmetric=1, .can_encrypt=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ .algo = NCR_ALG_CAMELLIA_ECB, .kstr = "ecb(camelia)", 
		.needs_iv = 0, .is_symmetric=1, .can_encrypt=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ .algo = NCR_ALG_SHA1, .kstr = "sha1", 
		.digest_size = 20, .can_digest=1,
		.key_type = NCR_KEY_TYPE_INVALID },
	{ .algo = NCR_ALG_MD5, .kstr = "md5", 
		.digest_size = 16, .can_digest=1,
		.key_type = NCR_KEY_TYPE_INVALID },
	{ .algo = NCR_ALG_SHA2_224, .kstr = "sha224", 
		.digest_size = 28, .can_digest=1,
		.key_type = NCR_KEY_TYPE_INVALID },
	{ .algo = NCR_ALG_SHA2_256, .kstr = "sha256", 
		.digest_size = 32, .can_digest=1,
		.key_type = NCR_KEY_TYPE_INVALID },
	{ .algo = NCR_ALG_SHA2_384, .kstr = "sha384", 
		.digest_size = 48, .can_digest=1,
		.key_type = NCR_KEY_TYPE_INVALID },
	{ .algo = NCR_ALG_SHA2_512, .kstr = "sha512", 
		.digest_size = 64, .can_digest=1,
		.key_type = NCR_KEY_TYPE_INVALID },
	{ .algo = NCR_ALG_HMAC_SHA1, .is_hmac = 1, .kstr = "hmac(sha1)", 
		.digest_size = 20, .can_sign=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ .algo = NCR_ALG_HMAC_MD5, .is_hmac = 1, .kstr = "hmac(md5)", 
		.digest_size = 16, .can_sign=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ .algo = NCR_ALG_HMAC_SHA2_224, .is_hmac = 1, .kstr = "hmac(sha224)", 
		.digest_size = 28, .can_sign=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ .algo = NCR_ALG_HMAC_SHA2_256, .is_hmac = 1, .kstr = "hmac(sha256)", 
		.digest_size = 32, .can_sign=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ .algo = NCR_ALG_HMAC_SHA2_384, .is_hmac = 1, .kstr = "hmac(sha384)", 
		.digest_size = 48, .can_sign=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ .algo = NCR_ALG_HMAC_SHA2_512, .is_hmac = 1, .kstr = "hmac(sha512)", 
		.digest_size = 64, .can_sign=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ .algo = NCR_ALG_RSA, .kstr = NULL, .is_pk = 1,
		.can_encrypt=1, .can_sign=1, .key_type = NCR_KEY_TYPE_PUBLIC },
	{ .algo = NCR_ALG_DSA, .kstr = NULL, .is_pk = 1,
		.can_sign=1, .key_type = NCR_KEY_TYPE_PUBLIC },
	{ .algo = NCR_ALG_DH, .kstr = NULL, .is_pk = 1,
		.can_kx=1, .key_type = NCR_KEY_TYPE_PUBLIC },
	{ .algo = NCR_ALG_NONE }

};

const struct algo_properties_st *_ncr_algo_to_properties(ncr_algorithm_t algo)
{
	ncr_algorithm_t a;
	int i = 0;

	for (i = 0; (a = algo_properties[i].algo) != NCR_ALG_NONE; i++) {
		if (a == algo)
			return &algo_properties[i];
	}

	return NULL;
}

static int _ncr_session_init(struct ncr_lists* lists, struct ncr_session_st* session)
{
	struct session_item_st* ns = NULL;
	int ret;
	const struct algo_properties_st *sign_hash;

	ns = ncr_session_new(lists);
	if (ns == NULL) {
		err();
		return -ENOMEM;
	}

	ns->op = session->op;
	ns->algorithm = _ncr_algo_to_properties(session->algorithm);
	if (ns->algorithm == NULL) {
		err();
		ret = -EINVAL;
		goto fail;
	}
	
	switch(session->op) {
		case NCR_OP_ENCRYPT:
		case NCR_OP_DECRYPT:
			if (!ns->algorithm->can_encrypt) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			/* read key */
			ret = ncr_key_item_get_read( &ns->key, lists, session->key);
			if (ret < 0) {
				err();
				goto fail;
			}
			if (ns->key->type == NCR_KEY_TYPE_SECRET) {
				int keysize = ns->key->key.secret.size;
				
				if (session->algorithm == NCR_ALG_NULL)
				  keysize = 0;
				
				if (ns->algorithm->kstr == NULL) {
					err();
					ret = -EINVAL;
					goto fail;
				}

				ret = cryptodev_cipher_init(&ns->cipher, ns->algorithm->kstr,
					ns->key->key.secret.data, keysize);
				if (ret < 0) {
					err();
					goto fail;
				}

				if (ns->algorithm->needs_iv) {
					if (session->params.params.cipher.iv_size > sizeof(session->params.params.cipher.iv)) {
						err();
						ret = -EINVAL;
						goto fail;
					}
					cryptodev_cipher_set_iv(&ns->cipher, session->params.params.cipher.iv, session->params.params.cipher.iv_size);
				}
			} else if (ns->key->type == NCR_KEY_TYPE_PRIVATE || ns->key->type == NCR_KEY_TYPE_PUBLIC) {
				ret = ncr_pk_cipher_init(ns->algorithm, &ns->pk, 
					&session->params, ns->key, NULL);
				if (ret < 0) {
					err();
					goto fail;
				}
			} else {
				err();
				ret = -EINVAL;
				goto fail;
			}
			break;

		case NCR_OP_SIGN:
		case NCR_OP_VERIFY:
			if (!ns->algorithm->can_sign && !ns->algorithm->can_digest) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			if (ns->algorithm->can_digest) {
				if (ns->algorithm->kstr == NULL) {
					err();
					ret = -EINVAL;
					goto fail;
				}

				ret = cryptodev_hash_init(&ns->hash, ns->algorithm->kstr, 0, NULL, 0);
				if (ret < 0) {
					err();
					goto fail;
				}
			
			} else {
				/* read key */
				ret = ncr_key_item_get_read( &ns->key, lists, session->key);
				if (ret < 0) {
					err();
					goto fail;
				}

				if (ns->algorithm->is_hmac && ns->key->type == NCR_KEY_TYPE_SECRET) {
					if (ns->algorithm->kstr == NULL) {
						err();
						ret = -EINVAL;
						goto fail;
					}

					ret = cryptodev_hash_init(&ns->hash, ns->algorithm->kstr, 1,
						ns->key->key.secret.data, ns->key->key.secret.size);
					if (ret < 0) {
						err();
						goto fail;
					}

				} else if (ns->algorithm->is_pk && (ns->key->type == NCR_KEY_TYPE_PRIVATE || ns->key->type == NCR_KEY_TYPE_PUBLIC)) {
					sign_hash = ncr_key_params_get_sign_hash(ns->key->algorithm, &session->params);
					if (IS_ERR(sign_hash)) {
						err();
						ret = PTR_ERR(sign_hash);
						goto fail;
					}

					if (!sign_hash->can_digest) {
						err();
						ret = -EINVAL;
						goto fail;
					}

					if (sign_hash->kstr == NULL) {
						err();
						ret = -EINVAL;
						goto fail;
					}

					ret = ncr_pk_cipher_init(ns->algorithm, &ns->pk, 
						&session->params, ns->key, sign_hash);
					if (ret < 0) {
						err();
						goto fail;
					}

					ret = cryptodev_hash_init(&ns->hash, sign_hash->kstr, 0, NULL, 0);
					if (ret < 0) {
						err();
						goto fail;
					}
				} else {
					err();
					ret = -EINVAL;
					goto fail;
				}
			}

			break;
		default:
			err();
			ret = -EINVAL;
			goto fail;
	}
	
	ret = 0;
	session->ses = ns->desc;

fail:
	if (ret < 0) {
		_ncr_session_remove(lists, ns->desc);
	}
	_ncr_sessions_item_put(ns);

	return ret;
}

int ncr_session_init(struct ncr_lists* lists, void __user* arg)
{
	struct ncr_session_st session;
	int ret;

	if (unlikely(copy_from_user(&session, arg, sizeof(session)))) {
		err();
		return -EFAULT;
	}

	ret = _ncr_session_init(lists, &session);
	if (unlikely(ret)) {
		err();
		return ret;
	}

	ret = copy_to_user( arg, &session, sizeof(session));
	if (unlikely(ret)) {
		err();
		_ncr_session_remove(lists, session.ses);
		return -EFAULT;
	}
	return ret;
}

static int _ncr_session_encrypt(struct session_item_st* sess, const struct scatterlist* input, unsigned input_cnt,
	size_t input_size, void *output, unsigned output_cnt, size_t *output_size)
{
int ret;

	if (sess->algorithm->is_symmetric) {
		/* read key */
		ret = cryptodev_cipher_encrypt(&sess->cipher, input, 
			output, input_size);
		if (ret < 0) {
			err();
			return ret;
		}
		/* FIXME: handle ciphers that do not require that */
		*output_size = input_size;
	} else { /* public key */
		ret = ncr_pk_cipher_encrypt(&sess->pk, input, input_cnt, input_size,
			output, output_cnt, output_size);
		
		if (ret < 0) {
			err();
			return ret;
		}
	}
	
	return 0;
}

static int _ncr_session_decrypt(struct session_item_st* sess, const struct scatterlist* input, 
	unsigned input_cnt, size_t input_size,
	struct scatterlist *output, unsigned output_cnt, size_t *output_size)
{
int ret;

	if (sess->algorithm->is_symmetric) {
		/* read key */
		ret = cryptodev_cipher_decrypt(&sess->cipher, input, 
			output, input_size);
		if (ret < 0) {
			err();
			return ret;
		}
		/* FIXME: handle ciphers that do not require equality */
		*output_size = input_size;
	} else { /* public key */
		ret = ncr_pk_cipher_decrypt(&sess->pk, input, input_cnt, input_size,
			output, output_cnt, output_size);
		
		if (ret < 0) {
			err();
			return ret;
		}
	}
	
	return 0;
}

static void _ncr_session_remove(struct ncr_lists *lst_, ncr_session_t desc)
{
	struct list_sem_st* lst;
	struct session_item_st * item, *tmp;

	lst = &lst_->sessions;
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

static int _ncr_session_grow_pages(struct session_item_st *ses, int pagecount)
{
	struct scatterlist *sg;
	struct page **pages;
	int array_size;

	if (likely(pagecount < ses->array_size))
		return 0;

	for (array_size = ses->array_size; array_size < pagecount;
	     array_size *= 2)
		;

	dprintk(2, KERN_DEBUG, "%s: reallocating to %d elements\n",
		__func__, array_size);
	pages = krealloc(ses->pages, array_size * sizeof(struct page *),
			 GFP_KERNEL);
	if (unlikely(pages == NULL))
		return -ENOMEM;
	ses->pages = pages;
	sg = krealloc(ses->sg, array_size * sizeof(struct scatterlist),
		      GFP_KERNEL);
	if (unlikely(sg == NULL))
		return -ENOMEM;
	ses->sg = sg;

	ses->array_size = array_size;
	return 0;
}

/* Only the output buffer is given as scatterlist */
static int get_userbuf1(struct session_item_st* ses,
		void __user * udata, size_t udata_size, struct scatterlist **dst_sg, unsigned *dst_cnt)
{
	int pagecount = 0;

	if (unlikely(udata == NULL)) {
		err();
		return -EINVAL;
	}

	pagecount = PAGECOUNT(udata, udata_size);
	_ncr_session_grow_pages(ses, pagecount);

	if (__get_userbuf(udata, udata_size, 1,
			pagecount, ses->pages, ses->sg)) {
		err();
		return -EINVAL;
	}
	(*dst_sg) = ses->sg;
	*dst_cnt = pagecount;

	ses->available_pages = pagecount;

	return 0;
}

/* make op->data.udata.input and op->data.udata.output available in scatterlists */
static int get_userbuf2(struct session_item_st* ses,
		struct ncr_session_op_st* op, struct scatterlist **src_sg,
		unsigned *src_cnt, struct scatterlist **dst_sg, unsigned *dst_cnt)
{
	int src_pagecount, dst_pagecount = 0, pagecount, write_src = 1;
	size_t input_size = op->data.udata.input_size;

	if (unlikely(op->data.udata.input == NULL)) {
		err();
		return -EINVAL;
	}

	src_pagecount = PAGECOUNT(op->data.udata.input, input_size);

	if (op->data.udata.input != op->data.udata.output) {	/* non-in-situ transformation */
		write_src = 0;
		if (op->data.udata.output != NULL) {
			dst_pagecount = PAGECOUNT(op->data.udata.output, op->data.udata.output_size);
		} else {
			dst_pagecount = 0;
		}
	} else {
		src_pagecount = max((int)(PAGECOUNT(op->data.udata.output, op->data.udata.output_size)),
			src_pagecount);
		input_size = max(input_size, (size_t)op->data.udata.output_size);
	}

	pagecount = src_pagecount + dst_pagecount;
	_ncr_session_grow_pages(ses, pagecount);

	if (__get_userbuf(op->data.udata.input, input_size, write_src,
			src_pagecount, ses->pages, ses->sg)) {
		err();
		printk("write: %d\n", write_src);
		return -EINVAL;
	}
	(*src_sg) = ses->sg;
	*src_cnt = src_pagecount;

	if (dst_pagecount) {
		*dst_cnt = dst_pagecount;
		(*dst_sg) = ses->sg + src_pagecount;

		if (__get_userbuf(op->data.udata.output, op->data.udata.output_size, 1, dst_pagecount,
					ses->pages + src_pagecount, *dst_sg)) {
			err();
			release_user_pages(ses->pages, src_pagecount);
			return -EINVAL;
		}
	} else {
		if (op->data.udata.output != NULL) {
			*dst_cnt = src_pagecount;
			(*dst_sg) = (*src_sg);
		} else {
			*dst_cnt = 0;
			*dst_sg = NULL;
		}
	}
	
	ses->available_pages = pagecount;

	return 0;
}

/* Called when userspace buffers are used */
static int _ncr_session_update(struct ncr_lists* lists, struct ncr_session_op_st* op)
{
	int ret;
	struct session_item_st* sess;
	struct scatterlist *isg;
	struct scatterlist *osg;
	unsigned osg_cnt=0, isg_cnt=0;
	size_t isg_size, osg_size;

	sess = ncr_sessions_item_get(lists, op->ses);
	if (sess == NULL) {
		err();
		return -EINVAL;
	}

	if (down_interruptible(&sess->mem_mutex)) {
		err();
		_ncr_sessions_item_put(sess);
		return -ERESTARTSYS;
	}

	ret = get_userbuf2(sess, op, &isg, &isg_cnt, &osg, &osg_cnt);
	if (ret < 0) {
		err();
		goto fail;
	}
	isg_size = op->data.udata.input_size;
	osg_size = op->data.udata.output_size;

	switch(sess->op) {
		case NCR_OP_ENCRYPT:
			if (osg == NULL) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			if (osg_size < isg_size) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			ret = _ncr_session_encrypt(sess, isg, isg_cnt, isg_size, 
				osg, osg_cnt, &osg_size);
			if (ret < 0) {
				err();
				goto fail;
			}
			op->data.udata.output_size = osg_size;
			
			break;
		case NCR_OP_DECRYPT:
			if (osg == NULL) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			if (osg_size < isg_size) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			ret = _ncr_session_decrypt(sess, isg, isg_cnt, isg_size, 
				osg, osg_cnt, &osg_size);
			if (ret < 0) {
				err();
				goto fail;
			}
			op->data.udata.output_size = osg_size;

			break;

		case NCR_OP_SIGN:
		case NCR_OP_VERIFY:
			ret = cryptodev_hash_update(&sess->hash, isg, isg_size);
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
	if (sess->available_pages) {
		release_user_pages(sess->pages, sess->available_pages);
		sess->available_pages = 0;
	}
	up(&sess->mem_mutex);
	_ncr_sessions_item_put(sess);

	return ret;
}

static int try_session_update(struct ncr_lists* lists, struct ncr_session_op_st* op)
{
	if (op->type == NCR_KEY_DATA) {
		if (op->data.kdata.input != NCR_KEY_INVALID)
			return _ncr_session_update_key(lists, op);
	} else if (op->type == NCR_DIRECT_DATA) {
		if (op->data.udata.input != NULL)
			return _ncr_session_update(lists, op);
	}

	return 0;
}

static int _ncr_session_final(struct ncr_lists* lists, struct ncr_session_op_st* op)
{
	int ret;
	struct session_item_st* sess;
	int digest_size;
	uint8_t digest[NCR_HASH_MAX_OUTPUT_SIZE];
	uint8_t vdigest[NCR_HASH_MAX_OUTPUT_SIZE];
	struct scatterlist *osg;
	unsigned osg_cnt=0;
	size_t osg_size = 0;
	size_t orig_osg_size;
	void __user * udata = NULL;
	size_t *udata_size;

	sess = ncr_sessions_item_get(lists, op->ses);
	if (sess == NULL) {
		err();
		return -EINVAL;
	}

	ret = try_session_update(lists, op);
	if (ret < 0) {
		err();
		_ncr_sessions_item_put(sess);
		return ret;
	}

	if (down_interruptible(&sess->mem_mutex)) {
		err();
		_ncr_sessions_item_put(sess);
		return -ERESTARTSYS;
	}
	
	if (op->type == NCR_DIRECT_DATA) {
		udata = op->data.udata.output;
		udata_size = &op->data.udata.output_size;
	} else if (op->type == NCR_KEY_DATA) {
		udata = op->data.kdata.output;
		udata_size = &op->data.kdata.output_size;
	} else {
		err();
		ret = -EINVAL;
		goto fail;
	}

	switch(sess->op) {
		case NCR_OP_ENCRYPT:
		case NCR_OP_DECRYPT:
			break;
		case NCR_OP_VERIFY:
			ret = get_userbuf1(sess, udata, *udata_size, &osg, &osg_cnt);
			if (ret < 0) {
				err();
				goto fail;
			}
			orig_osg_size = osg_size = *udata_size;

			digest_size = sess->hash.digestsize;
			if (digest_size == 0 || sizeof(digest) < digest_size) {
				err();
				ret = -EINVAL;
				goto fail;
			}
			ret = cryptodev_hash_final(&sess->hash, digest);
			if (ret < 0) {
				err();
				goto fail;
			}

			if (sess->algorithm->is_hmac) {
				ret = sg_copy_to_buffer(osg, osg_cnt, vdigest, digest_size);
				if (ret != digest_size) {
					err();
					ret = -EINVAL;
					goto fail;
				}
				
				if (digest_size != osg_size ||
					memcmp(vdigest, digest, digest_size) != 0) {
						
					op->err = NCR_VERIFICATION_FAILED;
				} else {
					op->err = NCR_SUCCESS;
				}
			} else {
				/* PK signature */
				ret = ncr_pk_cipher_verify(&sess->pk, osg, osg_cnt, osg_size,
					digest, digest_size, &op->err);
				if (ret < 0) {
					err();
					goto fail;
				}
			}
			break;

		case NCR_OP_SIGN:
			ret = get_userbuf1(sess, udata, *udata_size, &osg, &osg_cnt);
			if (ret < 0) {
				err();
				goto fail;
			}
			orig_osg_size = osg_size = *udata_size;

			digest_size = sess->hash.digestsize;
			if (digest_size == 0 || osg_size < digest_size) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			ret = cryptodev_hash_final(&sess->hash, digest);
			if (ret < 0) {
				err();
				goto fail;
			}

			ret = sg_copy_from_buffer(osg, osg_cnt, digest, digest_size);
			if (ret != digest_size) {
				err();
				ret = -EINVAL;
				goto fail;
			}
			osg_size = digest_size;
			
			cryptodev_hash_deinit(&sess->hash);

			if (sess->algorithm->is_pk) {
				/* PK signature */
				
				ret = ncr_pk_cipher_sign(&sess->pk, osg, osg_cnt, osg_size,
					osg, osg_cnt, &orig_osg_size);
				if (ret < 0) {
					err();
					goto fail;
				}
				osg_size = orig_osg_size;
			}
			break;
		default:
			err();
			ret = -EINVAL;
			goto fail;
	}

	if (osg_size > 0)
		*udata_size = osg_size;

	ret = 0;

fail:
	if (sess->available_pages) {
		release_user_pages(sess->pages, sess->available_pages);
		sess->available_pages = 0;
	}
	up(&sess->mem_mutex);

	cryptodev_hash_deinit(&sess->hash);
	if (sess->algorithm->is_symmetric) {
		cryptodev_cipher_deinit(&sess->cipher);
	} else {
		ncr_pk_cipher_deinit(&sess->pk);
	}

	_ncr_sessions_item_put(sess);
	_ncr_session_remove(lists, op->ses);

	return ret;
}

/* Direct with key: Allows to hash a key */
/* Called when userspace buffers are used */
static int _ncr_session_update_key(struct ncr_lists* lists, struct ncr_session_op_st* op)
{
	int ret;
	struct session_item_st* sess;
	struct key_item_st* key = NULL;

	sess = ncr_sessions_item_get(lists, op->ses);
	if (sess == NULL) {
		err();
		return -EINVAL;
	}

	/* read key */
	ret = ncr_key_item_get_read( &key, lists, op->data.kdata.input);
	if (ret < 0) {
		err();
		goto fail;
	}
	
	if (key->type != NCR_KEY_TYPE_SECRET) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	switch(sess->op) {
		case NCR_OP_ENCRYPT:
		case NCR_OP_DECRYPT:
			err();
			ret = -EINVAL;
			goto fail;
		case NCR_OP_SIGN:
		case NCR_OP_VERIFY:
			ret = _cryptodev_hash_update(&sess->hash, 
				key->key.secret.data, key->key.secret.size);
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
	_ncr_sessions_item_put(sess);

	return ret;
}

int ncr_session_update(struct ncr_lists* lists, void __user* arg)
{
	struct ncr_session_op_st op;
	int ret;

	if (unlikely(copy_from_user( &op, arg, sizeof(op)))) {
		err();
		return -EFAULT;
	}

	if (op.type == NCR_DIRECT_DATA)
		ret = _ncr_session_update(lists, &op);
	else if (op.type == NCR_KEY_DATA)
		ret = _ncr_session_update_key(lists, &op);
	else
		ret = -EINVAL;

	if (unlikely(ret)) {
		err();
		return ret;
	}

	if (unlikely(copy_to_user(arg, &op, sizeof(op)))) {
		err();
		return -EFAULT;
	}
	
	return 0;
}

int ncr_session_final(struct ncr_lists* lists, void __user* arg)
{
	struct ncr_session_op_st op;
	int ret;

	if (unlikely(copy_from_user(&op, arg, sizeof(op)))) {
		err();
		return -EFAULT;
	}

	ret = _ncr_session_final(lists, &op);
	if (unlikely(ret)) {
		err();
		return ret;
	}

	if (unlikely(copy_to_user(arg, &op, sizeof(op)))) {
		err();
		return -EFAULT;
	}
	return 0;
}

int ncr_session_once(struct ncr_lists* lists, void __user* arg)
{
	struct ncr_session_once_op_st kop;
	int ret;

	if (unlikely(copy_from_user(&kop, arg, sizeof(kop)))) {
		err();
		return -EFAULT;
	}

	ret = _ncr_session_init(lists, &kop.init);
	if (ret < 0) {
		err();
		return ret;
	}
	kop.op.ses = kop.init.ses;

	ret = _ncr_session_final(lists, &kop.op);
	if (ret < 0) {
		err();
		return ret;
	}

	if (unlikely(copy_to_user(arg, &kop, sizeof(kop))))
		return -EFAULT;
	return 0;
}
