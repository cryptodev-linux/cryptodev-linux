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
#include <linux/mutex.h>
#include "ncr.h"
#include "ncr-int.h"
#include <linux/mm_types.h>
#include <linux/scatterlist.h>
#include <net/netlink.h>

static void _ncr_sessions_item_put(struct session_item_st *item);
static int _ncr_session_update_key(struct ncr_lists *lists,
				   struct session_item_st *sess,
				   struct nlattr *tb[]);
static void _ncr_session_remove(struct ncr_lists *lst, ncr_session_t desc);

static int session_list_deinit_fn(int id, void *item, void *unused)
{
	(void)unused;
	_ncr_sessions_item_put(item);
	return 0;
}

void ncr_sessions_list_deinit(struct ncr_lists *lst)
{
	/* The mutex is not necessary, but doesn't hurt and makes it easier to
	   verify locking correctness. */
	mutex_lock(&lst->session_idr_mutex);
	idr_for_each(&lst->session_idr, session_list_deinit_fn, NULL);
	idr_remove_all(&lst->session_idr);
	idr_destroy(&lst->session_idr);
	mutex_unlock(&lst->session_idr_mutex);
}

/* Allocate a descriptor without making a sesssion available to userspace. */
static ncr_session_t session_alloc_desc(struct ncr_lists *lst)
{
	int ret, desc;

	mutex_lock(&lst->session_idr_mutex);
	if (idr_pre_get(&lst->session_idr, GFP_KERNEL) == 0) {
		ret = -ENOMEM;
		goto end;
	}
	/* idr_pre_get() should preallocate enough, and, due to
	   session_idr_mutex, nobody else can use the preallocated data.
	   Therefore the loop recommended in idr_get_new() documentation is not
	   necessary. */
	ret = idr_get_new(&lst->session_idr, NULL, &desc);
	if (ret != 0)
		goto end;
	ret = desc;
end:
	mutex_unlock(&lst->session_idr_mutex);
	return ret;
}

/* Drop a pre-allocated, unpublished session descriptor */
static void session_drop_desc(struct ncr_lists *lst, ncr_session_t desc)
{
	mutex_lock(&lst->session_idr_mutex);
	idr_remove(&lst->session_idr, desc);
	mutex_unlock(&lst->session_idr_mutex);
}

/* Make a session descriptor visible in user-space */
static void session_publish(struct ncr_lists *lst, struct session_item_st *sess)
{
	void *old;

	atomic_inc(&sess->refcnt);
	mutex_lock(&lst->session_idr_mutex);
	old = idr_replace(&lst->session_idr, sess, sess->desc);
	mutex_unlock(&lst->session_idr_mutex);
	BUG_ON(old != NULL);
}

/* returns the data item corresponding to desc */
static struct session_item_st *ncr_sessions_item_get(struct ncr_lists *lst,
						     ncr_session_t desc)
{
struct session_item_st* item;

	mutex_lock(&lst->session_idr_mutex);
	/* item may be NULL for pre-allocated session IDs. */
	item = idr_find(&lst->session_idr, desc);
	if (item != NULL) {
		atomic_inc(&item->refcnt);
		mutex_unlock(&lst->session_idr_mutex);
		return item;
	}
	mutex_unlock(&lst->session_idr_mutex);

	err();
	return NULL;
}

static void _ncr_sessions_item_put(struct session_item_st *item)
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

static struct session_item_st *ncr_session_new(ncr_session_t desc)
{
	struct session_item_st* sess;

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
		goto err_sess;
	}
	mutex_init(&sess->mem_mutex);

	atomic_set(&sess->refcnt, 1);
	sess->desc = desc;

	return sess;

err_sess:
	kfree(sess->sg);
	kfree(sess->pages);
	kfree(sess);
	return NULL;
}

static const struct algo_properties_st algo_properties[] = {
#define KSTR(x) .kstr = x, .kstr_len = sizeof(x) - 1
	{ .algo = NCR_ALG_NULL, KSTR("ecb(cipher_null)"),
		.needs_iv = 0, .is_symmetric=1, .can_encrypt=1,
		.key_type = NCR_KEY_TYPE_INVALID },
	{ .algo = NCR_ALG_3DES_CBC, KSTR("cbc(des3_ede)"),
		.needs_iv = 1, .is_symmetric=1, .can_encrypt=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ KSTR("cbc(aes)"),
		.needs_iv = 1, .is_symmetric=1, .can_encrypt=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ KSTR("cbc(camelia)"),
		.needs_iv = 1, .is_symmetric=1, .can_encrypt=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ KSTR("ctr(aes)"),
		.needs_iv = 1, .is_symmetric=1, .can_encrypt=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ KSTR("ctr(camelia)"),
		.needs_iv = 1, .is_symmetric=1, .can_encrypt=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ KSTR("ecb(aes)"),
		.needs_iv = 0, .is_symmetric=1, .can_encrypt=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ KSTR("ecb(camelia)"),
		.needs_iv = 0, .is_symmetric=1, .can_encrypt=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ .algo = NCR_ALG_SHA1, KSTR("sha1"),
		.digest_size = 20, .can_digest=1,
		.key_type = NCR_KEY_TYPE_INVALID },
	{ .algo = NCR_ALG_MD5, KSTR("md5"),
		.digest_size = 16, .can_digest=1,
		.key_type = NCR_KEY_TYPE_INVALID },
	{ .algo = NCR_ALG_SHA2_224, KSTR("sha224"),
		.digest_size = 28, .can_digest=1,
		.key_type = NCR_KEY_TYPE_INVALID },
	{ .algo = NCR_ALG_SHA2_256, KSTR("sha256"),
		.digest_size = 32, .can_digest=1,
		.key_type = NCR_KEY_TYPE_INVALID },
	{ .algo = NCR_ALG_SHA2_384, KSTR("sha384"),
		.digest_size = 48, .can_digest=1,
		.key_type = NCR_KEY_TYPE_INVALID },
	{ .algo = NCR_ALG_SHA2_512, KSTR("sha512"),
		.digest_size = 64, .can_digest=1,
		.key_type = NCR_KEY_TYPE_INVALID },
	{ .is_hmac = 1, KSTR("hmac(sha1)"),
		.digest_size = 20, .can_sign=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ .is_hmac = 1, KSTR("hmac(md5)"),
		.digest_size = 16, .can_sign=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ .is_hmac = 1, KSTR("hmac(sha224)"),
		.digest_size = 28, .can_sign=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ .is_hmac = 1, KSTR("hmac(sha256)"),
		.digest_size = 32, .can_sign=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ .is_hmac = 1, KSTR("hmac(sha384)"),
		.digest_size = 48, .can_sign=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	{ .is_hmac = 1, KSTR("hmac(sha512)"),
		.digest_size = 64, .can_sign=1,
		.key_type = NCR_KEY_TYPE_SECRET },
	/* NOTE: These algorithm names are not available through the kernel API
	   (yet). */
	{ .algo = NCR_ALG_RSA, KSTR("rsa"), .is_pk = 1,
		.can_encrypt=1, .can_sign=1, .key_type = NCR_KEY_TYPE_PUBLIC },
	{ .algo = NCR_ALG_DSA, KSTR("dsa"), .is_pk = 1,
		.can_sign=1, .key_type = NCR_KEY_TYPE_PUBLIC },
	{ .algo = NCR_ALG_DH, KSTR("dh"), .is_pk = 1,
		.can_kx=1, .key_type = NCR_KEY_TYPE_PUBLIC },
#undef KSTR
};

/* The lookups by string are inefficient - can we look up all we need from
   crypto API? */
const struct algo_properties_st *_ncr_algo_to_properties(const char *algo)
{
	const struct algo_properties_st *a;
	size_t name_len;

	name_len = strlen(algo);
	for (a = algo_properties;
	     a < algo_properties + ARRAY_SIZE(algo_properties); a++) {
		if (a->kstr_len == name_len
		    && memcmp(a->kstr, algo, name_len) == 0)
			return a;
	}

	return NULL;
}

const struct algo_properties_st *_ncr_nla_to_properties(const struct nlattr *nla)
{
	const struct algo_properties_st *a;
	size_t name_len;

	if (nla == NULL)
		return NULL;

	/* nla_len() >= 1 ensured by validate_nla() case NLA_NUL_STRING */
	name_len = nla_len(nla) - 1;
	for (a = algo_properties;
	     a < algo_properties + ARRAY_SIZE(algo_properties); a++) {
		if (a->kstr_len == name_len
		    && memcmp(a->kstr, nla_data(nla), name_len + 1) == 0)
			return a;
	}
	return NULL;
}

static int key_item_get_nla_read(struct key_item_st **st,
				 struct ncr_lists *lists,
				 const struct nlattr *nla)
{
	int ret;

	if (nla == NULL) {
		err();
		return -EINVAL;
	}
	ret = ncr_key_item_get_read(st, lists, nla_get_u32(nla));
	if (ret < 0) {
		err();
		return ret;
	}
	return ret;
}

static struct session_item_st *_ncr_session_init(struct ncr_lists *lists,
						 ncr_session_t desc,
						 ncr_crypto_op_t op,
						 struct nlattr *tb[])
{
	const struct nlattr *nla;
	struct session_item_st *ns;
	int ret;
	const struct algo_properties_st *sign_hash;

	ns = ncr_session_new(desc);
	if (ns == NULL) {
		err();
		return ERR_PTR(-ENOMEM);
	}

	ns->op = op;
	ns->algorithm = _ncr_nla_to_properties(tb[NCR_ATTR_ALGORITHM]);
	if (ns->algorithm == NULL) {
		err();
		ret = -EINVAL;
		goto fail;
	}
	
	switch(op) {
		case NCR_OP_ENCRYPT:
		case NCR_OP_DECRYPT:
			if (!ns->algorithm->can_encrypt) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			/* read key */
			ret = key_item_get_nla_read(&ns->key, lists,
						    tb[NCR_ATTR_KEY]);
			if (ret < 0) {
				err();
				goto fail;
			}
			
			/* wrapping keys cannot be used for encryption or decryption
			 */
			if (ns->key->flags & NCR_KEY_FLAG_WRAPPING) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			if (ns->key->type == NCR_KEY_TYPE_SECRET) {
				int keysize = ns->key->key.secret.size;
				
				if (ns->algorithm->algo == NCR_ALG_NULL)
				  keysize = 0;
				
				if (ns->algorithm->is_pk) {
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
					nla = tb[NCR_ATTR_IV];
					if (nla == NULL) {
						err();
						ret = -EINVAL;
						goto fail;
					}
					cryptodev_cipher_set_iv(&ns->cipher,
								nla_data(nla),
								nla_len(nla));
				}
			} else if (ns->key->type == NCR_KEY_TYPE_PRIVATE || ns->key->type == NCR_KEY_TYPE_PUBLIC) {
				ret = ncr_pk_cipher_init(ns->algorithm, &ns->pk, 
							 tb, ns->key, NULL);
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
				if (ns->algorithm->is_pk) {
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
				ret = key_item_get_nla_read(&ns->key, lists,
							    tb[NCR_ATTR_KEY]);
				if (ret < 0) {
					err();
					goto fail;
				}

				/* wrapping keys cannot be used for anything except wrapping.
				 */
				if (ns->key->flags & NCR_KEY_FLAG_WRAPPING) {
					err();
					ret = -EINVAL;
					goto fail;
				}

				if (ns->algorithm->is_hmac && ns->key->type == NCR_KEY_TYPE_SECRET) {
					if (ns->algorithm->is_pk) {
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
					nla = tb[NCR_ATTR_SIGNATURE_HASH_ALGORITHM];
					sign_hash = _ncr_nla_to_properties(nla);
					if (sign_hash == NULL) {
						err();
						ret = -EINVAL;
						goto fail;
					}

					if (!sign_hash->can_digest) {
						err();
						ret = -EINVAL;
						goto fail;
					}

					if (sign_hash->is_pk) {
						err();
						ret = -EINVAL;
						goto fail;
					}

					ret = ncr_pk_cipher_init(ns->algorithm, &ns->pk, 
						tb, ns->key, sign_hash);
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
	
	return ns;

fail:
	_ncr_sessions_item_put(ns);

	return ERR_PTR(ret);
}

int ncr_session_init(struct ncr_lists *lists,
		     const struct ncr_session_init *session,
		     struct nlattr *tb[])
{
	ncr_session_t desc;
	struct session_item_st *sess;

	desc = session_alloc_desc(lists);
	if (desc < 0) {
		err();
		return desc;
	}

	sess = _ncr_session_init(lists, desc, session->op, tb);
	if (IS_ERR(sess)) {
		err();
		session_drop_desc(lists, desc);
		return PTR_ERR(sess);
	}

	session_publish(lists, sess);
	_ncr_sessions_item_put(sess);

	return desc;
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

static void _ncr_session_remove(struct ncr_lists *lst, ncr_session_t desc)
{
	struct session_item_st * item;

	mutex_lock(&lst->session_idr_mutex);
	/* item may be NULL for pre-allocated session IDs. */
	item = idr_find(&lst->session_idr, desc);
	if (item != NULL)
		idr_remove(&lst->session_idr, desc); /* Steal the reference */
	mutex_unlock(&lst->session_idr_mutex);

	if (item != NULL)
		_ncr_sessions_item_put(item);
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

/* Make NCR_ATTR_UPDATE_INPUT_DATA and NCR_ATTR_UPDATE_OUTPUT_BUFFER available
   in scatterlists */
static int get_userbuf2(struct session_item_st *ses, struct nlattr *tb[],
			struct scatterlist **src_sg, unsigned *src_cnt,
			size_t *src_size, struct ncr_session_output_buffer *dst,
			struct scatterlist **dst_sg, unsigned *dst_cnt,
			int compat)
{
	const struct nlattr *src_nla, *dst_nla;
	struct ncr_session_input_data src;
	int src_pagecount, dst_pagecount = 0, pagecount, write_src = 1, ret;
	size_t input_size;

	src_nla = tb[NCR_ATTR_UPDATE_INPUT_DATA];
	dst_nla = tb[NCR_ATTR_UPDATE_OUTPUT_BUFFER];

	ret = ncr_session_input_data_from_nla(&src, src_nla, compat);
	if (unlikely(ret != 0)) {
		err();
		return ret;
	}
	*src_size = src.data_size;

	if (dst_nla != NULL) {
		ret = ncr_session_output_buffer_from_nla(dst, dst_nla, compat);
		if (unlikely(ret != 0)) {
			err();
			return ret;
		}
	}

	input_size = src.data_size;
	src_pagecount = PAGECOUNT(src.data, input_size);

	if (dst_nla == NULL || src.data != dst->buffer) {	/* non-in-situ transformation */
		write_src = 0;
		if (dst_nla != NULL) {
			dst_pagecount = PAGECOUNT(dst->buffer,
						  dst->buffer_size);
		} else {
			dst_pagecount = 0;
		}
	} else {
		src_pagecount = max((int)(PAGECOUNT(dst->buffer,
						    dst->buffer_size)),
				    src_pagecount);
		input_size = max(input_size, dst->buffer_size);
	}

	pagecount = src_pagecount + dst_pagecount;
	ret = _ncr_session_grow_pages(ses, pagecount);
	if (ret != 0) {
		err();
		return ret;
	}

	if (__get_userbuf((void __user *)src.data, input_size, write_src,
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

		if (__get_userbuf(dst->buffer, dst->buffer_size, 1,
				  dst_pagecount, ses->pages + src_pagecount,
				  *dst_sg)) {
			err();
			release_user_pages(ses->pages, src_pagecount);
			return -EINVAL;
		}
	} else {
		if (dst_nla != NULL) {
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
static int _ncr_session_update(struct session_item_st *sess,
			       struct nlattr *tb[], int compat)
{
	int ret;
	struct scatterlist *isg = NULL;
	struct scatterlist *osg = NULL;
	unsigned osg_cnt=0, isg_cnt=0;
	size_t isg_size = 0, osg_size;
	struct ncr_session_output_buffer out;

	ret = get_userbuf2(sess, tb, &isg, &isg_cnt, &isg_size, &out, &osg,
			   &osg_cnt, compat);
	if (ret < 0) {
		err();
		return ret;
	}

	switch(sess->op) {
		case NCR_OP_ENCRYPT:
			if (osg == NULL) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			osg_size = out.buffer_size;
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

			ret = ncr_session_output_buffer_set_size(&out, osg_size,
								 compat);
			if (ret != 0) {
				err();
				goto fail;
			}
			break;
		case NCR_OP_DECRYPT:
			if (osg == NULL) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			osg_size = out.buffer_size;
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

			ret = ncr_session_output_buffer_set_size(&out, osg_size,
								 compat);
			if (ret != 0) {
				err();
				goto fail;
			}
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

	return ret;
}

static int try_session_update(struct ncr_lists *lists,
			      struct session_item_st *sess, struct nlattr *tb[],
			      int compat)
{
	if (tb[NCR_ATTR_UPDATE_INPUT_KEY_AS_DATA] != NULL)
		return _ncr_session_update_key(lists, sess, tb);
	else if (tb[NCR_ATTR_UPDATE_INPUT_DATA] != NULL)
		return _ncr_session_update(sess, tb, compat);
	else
		return 0;
}

static int _ncr_session_final(struct ncr_lists *lists,
			      struct session_item_st *sess, struct nlattr *tb[],
			      int compat)
{
	const struct nlattr *nla;
	int ret;
	int digest_size;
	uint8_t digest[NCR_HASH_MAX_OUTPUT_SIZE];
	void *buffer = NULL;

	ret = try_session_update(lists, sess, tb, compat);
	if (ret < 0) {
		err();
		return ret;
	}

	switch(sess->op) {
	case NCR_OP_ENCRYPT:
	case NCR_OP_DECRYPT:
		break;
	case NCR_OP_VERIFY: {
		struct ncr_session_input_data src;

		nla = tb[NCR_ATTR_FINAL_INPUT_DATA];
		ret = ncr_session_input_data_from_nla(&src, nla, compat);
		if (unlikely(ret != 0)) {
			err();
			goto fail;
		}

		buffer = kmalloc(src.data_size, GFP_KERNEL);
		if (buffer == NULL) {
			err();
			ret = -ENOMEM;
			goto fail;
		}
		if (unlikely(copy_from_user(buffer, src.data, src.data_size))) {
			err();
			ret = -EFAULT;
			goto fail;
		}

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

		if (!sess->algorithm->is_pk)
			ret = (digest_size == src.data_size
			       && memcmp(buffer, digest, digest_size) == 0);
		else {
			ret = ncr_pk_cipher_verify(&sess->pk, buffer,
						   src.data_size, digest,
						   digest_size);
			if (ret < 0) {
				err();
				goto fail;
			}
		}
		break;
	}

	case NCR_OP_SIGN: {
		struct ncr_session_output_buffer dst;
		size_t output_size;

		nla = tb[NCR_ATTR_FINAL_OUTPUT_BUFFER];
		ret = ncr_session_output_buffer_from_nla(&dst, nla, compat);
		if (unlikely(ret != 0)) {
			err();
			goto fail;
		}

		digest_size = sess->hash.digestsize;
		if (digest_size == 0) {
			err();
			ret = -EINVAL;
			goto fail;
		}

		ret = cryptodev_hash_final(&sess->hash, digest);
		if (ret < 0) {
			err();
			goto fail;
		}

		cryptodev_hash_deinit(&sess->hash);

		if (!sess->algorithm->is_pk) {
			if (dst.buffer_size < digest_size) {
				err();
				ret = -ERANGE;
				goto fail;
			}
			if (unlikely(copy_to_user(dst.buffer, digest,
						  digest_size))) {
				err();
				ret = -EFAULT;
				goto fail;
			}
			output_size = digest_size;
		} else {
			output_size = dst.buffer_size;
			buffer = kmalloc(output_size, GFP_KERNEL);
			if (buffer == NULL) {
				err();
				ret = -ENOMEM;
				goto fail;
			}
			ret = ncr_pk_cipher_sign(&sess->pk, digest, digest_size,
						 buffer, &output_size);
			if (ret < 0) {
				err();
				goto fail;
			}
			if (unlikely(copy_to_user(dst.buffer, buffer,
						  output_size))) {
				err();
				ret = -EFAULT;
				goto fail;
			}
		}

		ret = ncr_session_output_buffer_set_size(&dst, output_size,
							 compat);
		if (ret != 0) {
			err();
			goto fail;
		}
		break;
	}
	default:
		err();
		ret = -EINVAL;
		goto fail;
	}

fail:
	kfree(buffer);

	return ret;
}

/* Direct with key: Allows to hash a key */
static int _ncr_session_update_key(struct ncr_lists *lists,
				   struct session_item_st* sess,
				   struct nlattr *tb[])
{
	int ret;
	struct key_item_st* key = NULL;

	/* read key */
	ret = key_item_get_nla_read(&key, lists,
				    tb[NCR_ATTR_UPDATE_INPUT_KEY_AS_DATA]);
	if (ret < 0) {
		err();
		return ret;
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
	_ncr_key_item_put(key);

	return ret;
}

int ncr_session_update(struct ncr_lists *lists,
		       const struct ncr_session_update *op, struct nlattr *tb[],
		       int compat)
{
	struct session_item_st *sess;
	int ret;

	sess = ncr_sessions_item_get(lists, op->ses);
	if (sess == NULL) {
		err();
		return -EINVAL;
	}

	if (mutex_lock_interruptible(&sess->mem_mutex)) {
		err();
		ret = -ERESTARTSYS;
		goto end;
	}
	if (tb[NCR_ATTR_UPDATE_INPUT_DATA] != NULL)
		ret = _ncr_session_update(sess, tb, compat);
	else if (tb[NCR_ATTR_UPDATE_INPUT_KEY_AS_DATA] != NULL)
		ret = _ncr_session_update_key(lists, sess, tb);
	else
		ret = -EINVAL;
	mutex_unlock(&sess->mem_mutex);

end:
	_ncr_sessions_item_put(sess);

	if (unlikely(ret)) {
		err();
		return ret;
	}

	return 0;
}

int ncr_session_final(struct ncr_lists *lists,
		      const struct ncr_session_final *op, struct nlattr *tb[],
		      int compat)
{
	struct session_item_st *sess;
	int ret;

	sess = ncr_sessions_item_get(lists, op->ses);
	if (sess == NULL) {
		err();
		return -EINVAL;
	}

	if (mutex_lock_interruptible(&sess->mem_mutex)) {
		err();
		_ncr_sessions_item_put(sess);
		return -ERESTARTSYS;
	}

	ret = _ncr_session_final(lists, sess, tb, compat);

	mutex_unlock(&sess->mem_mutex);
	_ncr_sessions_item_put(sess);
	_ncr_session_remove(lists, op->ses);

	return ret;
}

int ncr_session_once(struct ncr_lists *lists,
		     const struct ncr_session_once *once, struct nlattr *tb[],
		     int compat)
{
	struct session_item_st *sess;
	int ret, desc;

	desc = session_alloc_desc(lists);
	if (desc < 0) {
		err();
		return desc;
	}

	sess = _ncr_session_init(lists, desc, once->op, tb);
	if (IS_ERR(sess)) {
		err();
		session_drop_desc(lists, desc);
		return PTR_ERR(sess);
	}

	session_publish(lists, sess);

	if (mutex_lock_interruptible(&sess->mem_mutex)) {
		err();
		_ncr_sessions_item_put(sess);
		return -ERESTARTSYS;
	}

	ret = _ncr_session_final(lists, sess, tb, compat);

	mutex_unlock(&sess->mem_mutex);
	_ncr_sessions_item_put(sess);
	_ncr_session_remove(lists, desc);

	return ret;
}
