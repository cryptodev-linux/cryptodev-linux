/*
 * New driver for /dev/ncr device (aka NCR)

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

struct session_item_st {
	atomic_t refcnt;
	/* Constant values throughout the life of this object follow. */
	ncr_session_t desc;
	const struct algo_properties_st *algorithm;
	ncr_crypto_op_t op;
	struct key_item_st *key;

	/* Variable values, protected usually by mutex, follow. */
	struct mutex mutex;

	/* contexts for various options.
	 * simpler to have them like that than
	 * in a union.
	 */
	struct cipher_data cipher;
	struct ncr_pk_ctx pk;
	struct hash_data hash;
	/* This is a hack, ideally we'd have a hash algorithm that simply
	   outputs its input as a digest.  We'd still need to distinguish
	   between the hash to identify in the signature and the hash to
	   actually use, though. */
	void *transparent_hash;
	unsigned transparent_hash_size;

	struct scatterlist *sg;
	struct page **pages;
	unsigned array_size;
	unsigned available_pages;
};

static void _ncr_sessions_item_put(struct session_item_st *item);
static int _ncr_session_update_key(struct ncr_lists *lists,
				   struct session_item_st *sess,
				   struct nlattr *tb[]);

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
inline
static void session_drop_desc(struct ncr_lists *lst, ncr_session_t desc)
{
	mutex_lock(&lst->session_idr_mutex);
	idr_remove(&lst->session_idr, desc);
	mutex_unlock(&lst->session_idr_mutex);
}

/* Make a session descriptor visible in user-space, stealing the reference */
inline
static void session_publish_ref(struct ncr_lists *lst,
				struct session_item_st *sess)
{
	void *old;

	mutex_lock(&lst->session_idr_mutex);
	old = idr_replace(&lst->session_idr, sess, sess->desc);
	mutex_unlock(&lst->session_idr_mutex);
	BUG_ON(old != NULL);
}

/* returns the data item corresponding to desc */
inline
static struct session_item_st *session_get_ref(struct ncr_lists *lst,
					       ncr_session_t desc)
{
	struct session_item_st *item;

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

/* Find a session, stealing the reference, but keep the descriptor allocated. */
inline
static struct session_item_st *session_unpublish_ref(struct ncr_lists *lst,
						     ncr_session_t desc)
{
	struct session_item_st *sess;

	mutex_lock(&lst->session_idr_mutex);
	/* sess may be NULL for pre-allocated session IDs. */
	sess = idr_replace(&lst->session_idr, NULL, desc);
	mutex_unlock(&lst->session_idr_mutex);
	if (sess != NULL && !IS_ERR(sess))
		return sess;

	err();
	return NULL;
}

inline
static void _ncr_sessions_item_put(struct session_item_st *item)
{
	if (atomic_dec_and_test(&item->refcnt)) {
		cryptodev_cipher_deinit(&item->cipher);
		ncr_pk_cipher_deinit(&item->pk);
		cryptodev_hash_deinit(&item->hash);
		kfree(item->transparent_hash);
		if (item->key)
			_ncr_key_item_put(item->key);
		kfree(item->sg);
		kfree(item->pages);
		kfree(item);
	}
}

static struct session_item_st *ncr_session_new(ncr_session_t desc)
{
	struct session_item_st *sess;

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
	mutex_init(&sess->mutex);

	atomic_set(&sess->refcnt, 1);
	sess->desc = desc;

	return sess;

err_sess:
	kfree(sess->sg);
	kfree(sess->pages);
	kfree(sess);
	return NULL;
}

const oid_st *_ncr_properties_to_oid(const struct algo_properties_st *prop,
				     int key_size)
{
	int i = 0;

	if (prop->oids == NULL)
		return NULL;

	do {
		if (key_size == prop->oids[i].key_size ||
		    prop->oids[i].key_size == -1 /* catch all */ ) {

			return &prop->oids[i].oid;
		}
	} while (prop->oids[++i].key_size != 0);

	return NULL;
}

const static struct algo_oid_st aes_cbc_oids[] = {
	{.key_size = 16,
	 .oid = {{2, 16, 840, 1, 101, 3, 4, 1, 2}, 9}},
	{.key_size = 24,
	 .oid = {{2, 16, 840, 1, 101, 3, 4, 1, 22}, 9}},
	{.key_size = 32,
	 .oid = {{2, 16, 840, 1, 101, 3, 4, 1, 42}, 9}},
	{.key_size = 0}
};

const static struct algo_oid_st aes_ecb_oids[] = {
	{.key_size = 16,
	 .oid = {{2, 16, 840, 1, 101, 3, 4, 1, 1}, 9}},
	{.key_size = 24,
	 .oid = {{2, 16, 840, 1, 101, 3, 4, 1, 21}, 9}},
	{.key_size = 32,
	 .oid = {{2, 16, 840, 1, 101, 3, 4, 1, 41}, 9}},
	{.key_size = 0}
};

const static struct algo_oid_st des3_cbc_oids[] = {
	{.key_size = -1,
	 .oid = {{1, 2, 840, 113549, 3, 7}, 6}},
	{.key_size = 0}
};

/* http://www.oid-info.com/get/1.3.6.1.4.1.4929.1.7 
 */
const static struct algo_oid_st des3_ecb_oids[] = {
	{.key_size = -1,
	 .oid = {{1, 3, 6, 1, 4, 1, 4929, 1, 7}, 9}},
	{.key_size = 0}
};

const static struct algo_oid_st camelia_cbc_oids[] = {
	{.key_size = 16,
	 .oid = {{1, 2, 392, 200011, 61, 1, 1, 1, 2}, 9}},
	{.key_size = 24,
	 .oid = {{1, 2, 392, 200011, 61, 1, 1, 1, 3}, 9}},
	{.key_size = 32,
	 .oid = {{1, 2, 392, 200011, 61, 1, 1, 1, 4}, 9}},
	{.key_size = 0}
};

const static struct algo_oid_st rsa_oid[] = {
	{.key_size = -1,
	 .oid = {{1, 2, 840, 113549, 1, 1, 1}, 7}},
	{.key_size = 0}
};

const static struct algo_oid_st dsa_oid[] = {
	{.key_size = -1,
	 .oid = {{1, 2, 840, 10040, 4, 1}, 6}},
	{.key_size = 0}
};

const static struct algo_oid_st dh_oid[] = {
	{.key_size = -1,
	 .oid = {{1, 2, 840, 10046, 2, 1}, 6}},
	{.key_size = 0}
};

const static struct algo_oid_st sha1_oid[] = {
	{.key_size = -1,
	 .oid = {.OIDlen = 6, .OID = {1, 3, 14, 3, 2, 26}}},
	 {.key_size = 0}
};

const static struct algo_oid_st md5_oid[] = {
	{.key_size = -1,
	 .oid = {.OIDlen = 6,.OID = {1, 2, 840, 113549, 2, 5,}}},
	 {.key_size = 0}
};

const static struct algo_oid_st sha224_oid[] = {
	{.key_size = -1,
	 .oid = {.OIDlen = 9,.OID = {2, 16, 840, 1, 101, 3, 4, 2, 4,}}},
	 {.key_size = 0}
};

const static struct algo_oid_st sha256_oid[] = {
	{.key_size = -1,
	 .oid = {.OIDlen = 9,.OID = {2, 16, 840, 1, 101, 3, 4, 2, 1,}}},
	 {.key_size = 0}
};

const static struct algo_oid_st sha384_oid[] = {
	{.key_size = -1,
	 .oid = {.OIDlen = 9,.OID = {2, 16, 840, 1, 101, 3, 4, 2, 2,}}},
	 {.key_size = 0}
};

const static struct algo_oid_st sha512_oid[] = {
	{.key_size = -1,
	 .oid = {.OIDlen = 9,.OID = {2, 16, 840, 1, 101, 3, 4, 2, 3,}}},
	 {.key_size = 0}
};


/* OIDs are used in cipher algorithms to distinguish keys on key wrapping.
 */

static const struct algo_properties_st algo_properties[] = {
#define KSTR(x) .kstr = x, .kstr_len = sizeof(x) - 1
	{.algo = NCR_ALG_NULL, KSTR("ecb(cipher_null)"),
	 .needs_iv = 0,.is_symmetric = 1,.can_encrypt = 1,
	 .key_type = NCR_KEY_TYPE_INVALID},
	{.algo = NCR_ALG_3DES_CBC, KSTR("cbc(des3_ede)"),
	 .needs_iv = 1,.is_symmetric = 1,.can_encrypt = 1,
	 .key_type = NCR_KEY_TYPE_SECRET,.oids = des3_cbc_oids},
	{.algo = NCR_ALG_3DES_ECB, KSTR("ecb(des3_ede)"),
	 .needs_iv = 0,.is_symmetric = 1,.can_encrypt = 1,
	 .key_type = NCR_KEY_TYPE_SECRET,.oids = des3_ecb_oids},
	{.algo = NCR_ALG_AES_CBC, KSTR("cbc(aes)"),
	 .needs_iv = 1,.is_symmetric = 1,.can_encrypt = 1,
	 .key_type = NCR_KEY_TYPE_SECRET,.oids = aes_cbc_oids},
	{.algo = NCR_ALG_CAMELIA_CBC, KSTR("cbc(camelia)"),
	 .needs_iv = 1,.is_symmetric = 1,.can_encrypt = 1,
	 .key_type = NCR_KEY_TYPE_SECRET,.oids = camelia_cbc_oids},
	{.algo = NCR_ALG_AES_CTR, KSTR("ctr(aes)"),
	 .needs_iv = 1,.is_symmetric = 1,.can_encrypt = 1,
	 .key_type = NCR_KEY_TYPE_SECRET, /* FIXME: no OIDs */ },
	{.algo = NCR_ALG_CAMELIA_CTR, KSTR("ctr(camelia)"),
	 .needs_iv = 1,.is_symmetric = 1,.can_encrypt = 1,
	 .key_type = NCR_KEY_TYPE_SECRET, /* FIXME: no OIDs */ },
	{.algo = NCR_ALG_AES_ECB, KSTR("ecb(aes)"),
	 .needs_iv = 0,.is_symmetric = 1,.can_encrypt = 1,
	 .key_type = NCR_KEY_TYPE_SECRET,.oids = aes_ecb_oids},
	{.algo = NCR_ALG_CAMELIA_ECB, KSTR("ecb(camelia)"),
	 .needs_iv = 0,.is_symmetric = 1,.can_encrypt = 1,
	 .key_type = NCR_KEY_TYPE_SECRET, /* FIXME: no OIDs */ },
	{.algo = NCR_ALG_SHA1, KSTR("sha1"),
	 .digest_size = 20,.can_digest = 1, .oids = sha1_oid,
	 .key_type = NCR_KEY_TYPE_INVALID},
	{.algo = NCR_ALG_MD5, KSTR("md5"), 
	 .digest_size = 16,.can_digest = 1, .oids = md5_oid,
	 .key_type = NCR_KEY_TYPE_INVALID},
	{.algo = NCR_ALG_SHA2_224, KSTR("sha224"),
	 .digest_size = 28,.can_digest = 1, .oids = sha224_oid,
	 .key_type = NCR_KEY_TYPE_INVALID},
	{.algo = NCR_ALG_SHA2_256, KSTR("sha256"),
	 .digest_size = 32,.can_digest = 1, .oids = sha256_oid,
	 .key_type = NCR_KEY_TYPE_INVALID},
	{.algo = NCR_ALG_SHA2_384, KSTR("sha384"),
	 .digest_size = 48,.can_digest = 1, .oids = sha384_oid,
	 .key_type = NCR_KEY_TYPE_INVALID},
	{.algo = NCR_ALG_SHA2_512, KSTR("sha512"),
	 .digest_size = 64,.can_digest = 1, .oids = sha512_oid,
	 .key_type = NCR_KEY_TYPE_INVALID},
	{.algo = NCR_ALG_HMAC_SHA1, .is_hmac = 1, KSTR("hmac(sha1)"),
	 .digest_size = 20,.can_sign = 1,
	 .key_type = NCR_KEY_TYPE_SECRET},
	{.algo = NCR_ALG_HMAC_MD5, .is_hmac = 1, KSTR("hmac(md5)"),
	 .digest_size = 16,.can_sign = 1,
	 .key_type = NCR_KEY_TYPE_SECRET},
	{.algo = NCR_ALG_HMAC_SHA2_224, .is_hmac = 1, KSTR("hmac(sha224)"),
	 .digest_size = 28,.can_sign = 1,
	 .key_type = NCR_KEY_TYPE_SECRET},
	{.algo = NCR_ALG_HMAC_SHA2_256, .is_hmac = 1, KSTR("hmac(sha256)"),
	 .digest_size = 32,.can_sign = 1,
	 .key_type = NCR_KEY_TYPE_SECRET},
	{.algo = NCR_ALG_HMAC_SHA2_384, .is_hmac = 1, KSTR("hmac(sha384)"),
	 .digest_size = 48,.can_sign = 1,
	 .key_type = NCR_KEY_TYPE_SECRET},
	{.algo = NCR_ALG_HMAC_SHA2_512, .is_hmac = 1, KSTR("hmac(sha512)"),
	 .digest_size = 64,.can_sign = 1,
	 .key_type = NCR_KEY_TYPE_SECRET},

	/* NOTE: These algorithm names are not available through the kernel API
	   (yet). */
	{.algo = NCR_ALG_RSA, .is_pk = 1,
	 .can_encrypt = 1,.can_sign = 1,.key_type = NCR_KEY_TYPE_PUBLIC,
	 .oids = rsa_oid},
	{.algo = NCR_ALG_DSA, .is_pk = 1,
	 .can_sign = 1,.key_type = NCR_KEY_TYPE_PUBLIC,
	 .oids = dsa_oid},
	{.algo = NCR_ALG_DH, .is_pk = 1,
	 .can_kx = 1,.key_type = NCR_KEY_TYPE_PUBLIC,
	 .oids = dh_oid},

#undef KSTR
};

const struct algo_properties_st *_ncr_algo_to_properties(ncr_algorithm_t algo)
{
	const struct algo_properties_st *a;

	for (a = algo_properties;
	     a < algo_properties + ARRAY_SIZE(algo_properties); a++) {
		if (a->algo == algo)
			return a;
	}

	return NULL;
}

static void print_oid(const oid_st * oid)
{
	char txt[128] = "";
	char tmp[64];
	int i;

	for (i = 0; i < oid->OIDlen; i++) {
		sprintf(tmp, "%d.", (int)oid->OID[i]);
		strcat(txt, tmp);
	}

	dprintk(1, KERN_DEBUG, "unknown oid: %s\n", txt);
}

const struct algo_properties_st *_ncr_oid_to_properties(const oid_st * oid)
{
	const struct algo_properties_st *a;
	int i;

	for (a = algo_properties;
	     a < algo_properties + ARRAY_SIZE(algo_properties); a++) {

		i = 0;

		if (a->oids == NULL)
			continue;

		do {
			if (a->oids[i].oid.OIDlen == oid->OIDlen &&
			    memcmp(oid->OID, a->oids[i].oid.OID,
				   oid->OIDlen * sizeof(oid->OID[0])) == 0)
				return a;
		} while (a->oids[++i].key_size != 0);
	}

	print_oid(oid);
	return NULL;
}

const struct algo_properties_st *_ncr_nla_to_properties(const struct nlattr
							*nla)
{
	ncr_algorithm_t algo;

	if (nla == NULL)
		return NULL;

	/* nla_len() >= 1 ensured by validate_nla() case NLA_NUL_STRING */
	algo = nla_get_u32(nla);
	
	return _ncr_algo_to_properties(algo);
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

/* The caller is responsible for locking of "session".  old_session must not be
   locked on entry. */
static int
init_or_clone_hash(struct session_item_st *session,
		   struct session_item_st *old_session,
		   const struct algo_properties_st *algo,
		   const void *mac_key, size_t mac_key_size)
{
	int ret;

	if (old_session == NULL)
		return cryptodev_hash_init(&session->hash, algo->kstr,
					   mac_key, mac_key_size);

	if (mutex_lock_interruptible(&old_session->mutex)) {
		err();
		return -ERESTARTSYS;
	}
	ret = cryptodev_hash_clone(&session->hash, &old_session->hash, mac_key,
				   mac_key_size);
				   
	if (old_session->transparent_hash) {
		session->transparent_hash =
		    kzalloc(session->hash.digestsize,
			    GFP_KERNEL);
		if (session->transparent_hash == NULL) {
			err();
			ret = -ENOMEM;
		} else
			memcpy(session->transparent_hash, old_session->transparent_hash, session->hash.digestsize);
	}

	mutex_unlock(&old_session->mutex);

	return ret;
}

static struct session_item_st *_ncr_session_init(struct ncr_lists *lists,
						 ncr_session_t desc,
						 ncr_crypto_op_t op,
						 struct nlattr *tb[])
{
	const struct nlattr *nla;
	struct session_item_st *ns, *old_session = NULL;
	int ret;

	ns = ncr_session_new(desc);
	if (ns == NULL) {
		err();
		return ERR_PTR(-ENOMEM);
	}
	/* ns is the only reference throughout this function, so no locking
	   is necessary. */

	ns->op = op;
	nla = tb[NCR_ATTR_SESSION_CLONE_FROM];
	if (nla != NULL) {
		/* "ns" is not visible to userspace, so this is safe. */
		old_session = session_get_ref(lists, nla_get_u32(nla));
		if (old_session == NULL) {
			err();
			ret = -EINVAL;
			goto fail;
		}
		if (ns->op != old_session->op) {
			err();
			ret = -EINVAL;
			goto fail;
		}
	}

	if (old_session == NULL) {
		ns->algorithm = _ncr_nla_to_properties(tb[NCR_ATTR_ALGORITHM]);
		if (ns->algorithm == NULL) {
			err();
			ret = -EINVAL;
			goto fail;
		}
	} else
		ns->algorithm = old_session->algorithm;

	switch (op) {
	case NCR_OP_ENCRYPT:
	case NCR_OP_DECRYPT:
		if (!ns->algorithm->can_encrypt) {
			err();
			ret = -EINVAL;
			goto fail;
		}

		if (old_session != NULL) {
			err();
			ret = -EOPNOTSUPP;
			goto fail;
		}

		/* read key */
		ret = key_item_get_nla_read(&ns->key, lists, tb[NCR_ATTR_KEY]);
		if (ret < 0) {
			err();
			goto fail;
		}

		/* wrapping keys cannot be used for encryption or decryption
		 */
		if (ns->key->flags & NCR_KEY_FLAG_WRAPPING
		    || ns->key->flags & NCR_KEY_FLAG_UNWRAPPING) {
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

			ret =
			    cryptodev_cipher_init(&ns->cipher,
						  ns->algorithm->kstr,
						  ns->key->key.secret.data,
						  keysize);
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
		} else if (ns->key->type == NCR_KEY_TYPE_PRIVATE
			   || ns->key->type == NCR_KEY_TYPE_PUBLIC) {
			ret =
			    ncr_pk_cipher_init(ns->algorithm, &ns->pk, tb,
					       ns->key, NULL);
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

			ret = init_or_clone_hash(ns, old_session,
						 ns->algorithm, NULL, 0);
			if (ret < 0) {
				err();
				goto fail;
			}

		} else {
			/* Get key */
			if (old_session == NULL) {
				ret = key_item_get_nla_read(&ns->key,
							    lists,
							    tb[NCR_ATTR_KEY]);
				if (ret < 0) {
					err();
					goto fail;
				}
			} else {
				atomic_inc(&old_session->key->refcnt);
				ns->key = old_session->key;
			}

			/* wrapping keys cannot be used for anything except wrapping.
			 */
			if (ns->key->flags & NCR_KEY_FLAG_WRAPPING
			    || ns->key->flags & NCR_KEY_FLAG_UNWRAPPING) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			/* wrapping keys cannot be used for anything except wrapping.
			 */
			if (ns->key->flags & NCR_KEY_FLAG_WRAPPING) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			if (ns->algorithm->is_hmac
			    && ns->key->type == NCR_KEY_TYPE_SECRET) {
				if (ns->algorithm->is_pk) {
					err();
					ret = -EINVAL;
					goto fail;
				}

				ret =
				    init_or_clone_hash(ns, old_session,
						       ns->algorithm,
						       ns->key->key.secret.data,
						       ns->key->key.secret.
						       size);
				if (ret < 0) {
					err();
					goto fail;
				}
			} else if (ns->algorithm->is_pk
				   && (ns->key->type == NCR_KEY_TYPE_PRIVATE
				       || ns->key->type ==
				       NCR_KEY_TYPE_PUBLIC)) {
				const struct algo_properties_st *sign_hash = NULL;

				if (old_session != NULL) {
					err();
					ret = -EOPNOTSUPP;
					goto fail;
				}

				nla = tb[NCR_ATTR_SIGNATURE_TRANSPARENT];
				if (nla != NULL && nla_get_u32(nla) != 0) {
					/* transparent hash has to be allowed by the key
					 */
					if (!
					    (ns->key->
					     flags & NCR_KEY_FLAG_ALLOW_TRANSPARENT_HASH))
					{
						err();
						ret = -EPERM;
						goto fail;
					}

					ns->transparent_hash =
					    kzalloc(NCR_HASH_MAX_OUTPUT_SIZE, GFP_KERNEL);
					if (ns->transparent_hash == NULL) {
						err();
						ret = -ENOMEM;
						goto fail;
					}
				} else { /* digestsize is fixed */
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

					ret =
						cryptodev_hash_init(&ns->hash,
											sign_hash->kstr, NULL, 0);
					if (ret < 0) {
						err();
						goto fail;
					}
				}

				ret = ncr_pk_cipher_init(ns->algorithm, &ns->pk,
							 tb, ns->key,
							 sign_hash);
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

	if (old_session != NULL)
		_ncr_sessions_item_put(old_session);

	return ns;

fail:
	if (old_session != NULL)
		_ncr_sessions_item_put(old_session);
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

	session_publish_ref(lists, sess);

	return desc;
}

/* The caller is responsible for locking of the session. */
static int _ncr_session_encrypt(struct session_item_st *sess,
				const struct scatterlist *input,
				unsigned input_cnt, size_t input_size,
				void *output, unsigned output_cnt,
				size_t * output_size)
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
	} else {		/* public key */
		ret =
		    ncr_pk_cipher_encrypt(&sess->pk, input, input_cnt,
					  input_size, output, output_cnt,
					  output_size);

		if (ret < 0) {
			err();
			return ret;
		}
	}

	return 0;
}

/* The caller is responsible for locking of the session. */
static int _ncr_session_decrypt(struct session_item_st *sess,
				const struct scatterlist *input,
				unsigned input_cnt, size_t input_size,
				struct scatterlist *output, unsigned output_cnt,
				size_t * output_size)
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
	} else {		/* public key */
		ret =
		    ncr_pk_cipher_decrypt(&sess->pk, input, input_cnt,
					  input_size, output, output_cnt,
					  output_size);

		if (ret < 0) {
			err();
			return ret;
		}
	}

	return 0;
}

/* The caller is responsible for locking of the session. */
static int _ncr_session_grow_pages(struct session_item_st *ses, int pagecount)
{
	struct scatterlist *sg;
	struct page **pages;
	int array_size;

	if (likely(pagecount < ses->array_size))
		return 0;

	for (array_size = ses->array_size; array_size < pagecount;
	     array_size *= 2) ;

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
   in scatterlists.
   The caller is responsible for locking of the session. */
static int get_userbuf2(struct session_item_st *ses, struct nlattr *tb[],
			struct scatterlist **src_sg, unsigned *src_cnt,
			size_t * src_size,
			struct ncr_session_output_buffer *dst,
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

/* Called when userspace buffers are used.
   The caller is responsible for locking of the session. */
static int _ncr_session_update(struct session_item_st *sess,
			       struct nlattr *tb[], int compat)
{
	const struct nlattr *nla;
	int ret;
	struct scatterlist *isg = NULL;
	struct scatterlist *osg = NULL;
	unsigned osg_cnt = 0, isg_cnt = 0;
	size_t isg_size = 0, osg_size;
	struct ncr_session_output_buffer out;

	ret = get_userbuf2(sess, tb, &isg, &isg_cnt, &isg_size, &out, &osg,
			   &osg_cnt, compat);
	if (ret < 0) {
		err();
		return ret;
	}

	switch (sess->op) {
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

		if (sess->algorithm->is_symmetric && sess->algorithm->needs_iv) {
			nla = tb[NCR_ATTR_IV];
			if (nla != NULL)
				cryptodev_cipher_set_iv(&sess->cipher,
							nla_data(nla),
							nla_len(nla));
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

		if (sess->algorithm->is_symmetric && sess->algorithm->needs_iv) {
			nla = tb[NCR_ATTR_IV];
			if (nla != NULL)
				cryptodev_cipher_set_iv(&sess->cipher,
							nla_data(nla),
							nla_len(nla));
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
		if (sess->transparent_hash) {
			if (isg_size >= NCR_HASH_MAX_OUTPUT_SIZE) {
				err();
				ret = -EINVAL;
				goto fail;
			}
			ret = sg_copy_to_buffer(isg, isg_cnt,
									sess->transparent_hash,
									isg_size);
			if (ret != isg_size) {
				err();
				ret = -EINVAL;
				goto fail;
			}
			sess->transparent_hash_size = isg_size;

		} else {
			ret = cryptodev_hash_update(&sess->hash, isg, isg_size);
			if (ret < 0) {
				err();
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

fail:
	if (sess->available_pages) {
		release_user_pages(sess->pages, sess->available_pages);
		sess->available_pages = 0;
	}

	return ret;
}

/* The caller is responsible for locking of the session. */
inline 
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

/* The caller is responsible for locking of the session.
   Note that one or more _ncr_session_update()s may still be blocked on
   sess->mutex and will execute after this function! */
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

	switch (sess->op) {
	case NCR_OP_ENCRYPT:
	case NCR_OP_DECRYPT:
		break;
	case NCR_OP_VERIFY:{
			struct ncr_session_input_data src;

			nla = tb[NCR_ATTR_FINAL_INPUT_DATA];
			ret =
			    ncr_session_input_data_from_nla(&src, nla, compat);
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

			if (unlikely
			    (copy_from_user(buffer, src.data, src.data_size))) {
				err();
				ret = -EFAULT;
				goto fail;
			}

			
			if (sess->transparent_hash) {
				digest_size = sess->transparent_hash_size;
				if (digest_size == 0 || sizeof(digest) < digest_size) {
					err();
					ret = -EINVAL;
					goto fail;
				}				
				
				memcpy(digest, sess->transparent_hash,
				       sess->transparent_hash_size);
			} else {
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
			}

			if (!sess->algorithm->is_pk)
				ret = (digest_size == src.data_size
				       && memcmp(buffer, digest, digest_size) == 0);
			else {
				ret = ncr_pk_cipher_verify(&sess->pk, buffer,
							   src.data_size,
							   digest, digest_size);
				if (ret < 0) {
					err();
					goto fail;
				}
			}
			break;
		}

	case NCR_OP_SIGN:{
			struct ncr_session_output_buffer dst;
			size_t output_size;

			nla = tb[NCR_ATTR_FINAL_OUTPUT_BUFFER];
			ret =
			    ncr_session_output_buffer_from_nla(&dst, nla,
							       compat);
			if (unlikely(ret != 0)) {
				err();
				goto fail;
			}

			if (sess->transparent_hash) {
				digest_size = sess->transparent_hash_size;
				if (digest_size == 0 || sizeof(digest) < digest_size) {
					err();
					ret = -EINVAL;
					goto fail;
				}				
				
				memcpy(digest, sess->transparent_hash,
				       sess->transparent_hash_size);
			} else {
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

				cryptodev_hash_deinit(&sess->hash);
			}


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
				ret =
				    ncr_pk_cipher_sign(&sess->pk, digest,
						       digest_size, buffer,
						       &output_size);
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

			ret =
			    ncr_session_output_buffer_set_size(&dst,
							       output_size,
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

/* Direct with key: Allows to hash a key.
   The caller is responsible for locking of the session. */
static int _ncr_session_update_key(struct ncr_lists *lists,
				   struct session_item_st *sess,
				   struct nlattr *tb[])
{
	int ret;
	struct key_item_st *key = NULL;

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

	if (!(key->flags & NCR_KEY_FLAG_HASHABLE)) {
		err();
		ret = -EPERM;
		goto fail;
	}

	switch (sess->op) {
	case NCR_OP_ENCRYPT:
	case NCR_OP_DECRYPT:
		err();
		ret = -EINVAL;
		goto fail;
	case NCR_OP_SIGN:
	case NCR_OP_VERIFY:
		if (sess->transparent_hash) {
			err();
			ret = -EINVAL;
			goto fail;
		}
		ret = _cryptodev_hash_update(&sess->hash,
					     key->key.secret.data,
					     key->key.secret.size);
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

	sess = session_get_ref(lists, op->ses);
	if (sess == NULL) {
		err();
		return -EINVAL;
	}

	/* Note that op->ses may be reallocated from now on, making the audit
	   information confusing. */

	if (mutex_lock_interruptible(&sess->mutex)) {
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
	mutex_unlock(&sess->mutex);

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

	/* Make the session inaccessible atomically to avoid concurrent
	   session_final() callers, but keep the ID allocated to keep audit
	   information unambiguous. */
	sess = session_unpublish_ref(lists, op->ses);
	if (sess == NULL) {
		err();
		return -EINVAL;
	}

	if (mutex_lock_interruptible(&sess->mutex)) {
		err();
		/* Other threads may observe the session descriptor
		   disappearing and reappearing - but then they should not be
		   accessing it anyway if it is being freed.
		   session_unpublish_ref keeps the ID allocated for us. */
		session_publish_ref(lists, sess);
		return -ERESTARTSYS;
	}
	ret = _ncr_session_final(lists, sess, tb, compat);
	mutex_unlock(&sess->mutex);

	_ncr_sessions_item_put(sess);
	session_drop_desc(lists, op->ses);

	return ret;
}

int ncr_session_once(struct ncr_lists *lists,
		     const struct ncr_session_once *once, struct nlattr *tb[],
		     int compat)
{
	struct session_item_st *sess;
	int ret;

	sess = _ncr_session_init(lists, -1, once->op, tb);
	if (IS_ERR(sess)) {
		err();
		return PTR_ERR(sess);
	}

	/* No locking of sess necessary, "sess" is the only reference. */
	ret = _ncr_session_final(lists, sess, tb, compat);

	_ncr_sessions_item_put(sess);

	return ret;
}
