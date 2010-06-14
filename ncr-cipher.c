/*
 * Driver for /dev/crypto device (aka CryptoDev)
 *
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
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/random.h>
#include <asm/uaccess.h>
#include <asm/ioctl.h>
#include <crypto/algapi.h>
#include <crypto/hash.h>
#include "cryptodev.h"
#include "cryptodev_int.h"
#include "ncr_int.h"

static inline const char* algo2str(ncr_algorithm_t algo)
{
	switch(algo) {
		case NCR_ALG_AES_ECB:
			return "ecb(aes)";
		case NCR_ALG_3DES_CBC:
			return "cbc(des3_ede)";
		case NCR_ALG_AES_CBC:
			return "cbc(aes)";
		case NCR_ALG_CAMELLIA_CBC:
			return "cbc(camelia)";
		case NCR_ALG_SHA1:
			return "sha1";
		case NCR_ALG_MD5:
			return "md5";
		case NCR_ALG_SHA2_224:
			return "sha224";
		case NCR_ALG_SHA2_256:
			return "sha256";
		case NCR_ALG_SHA2_384:
			return "sha384";
		case NCR_ALG_SHA2_512:
			return "sha512";
		case NCR_ALG_HMAC_SHA1:
			return "hmac(sha1)";
		case NCR_ALG_HMAC_MD5:
			return "hmac(md5)";
		case NCR_ALG_HMAC_SHA2_224:
			return "hmac(sha224)";
		case NCR_ALG_HMAC_SHA2_256:
			return "hmac(sha256)";
		case NCR_ALG_HMAC_SHA2_384:
			return "hmac(sha384)";
		case NCR_ALG_HMAC_SHA2_512:
			return "hmac(sha512)";
		default:
			return NULL;
	}
}

ncr_session_t ncr_cipher_init(struct list_sem_st* sess_lst, ncr_algorithm_t algorithm, struct key_item_st *key, void* iv, size_t iv_size);
void ncr_cipher_deinit(struct list_sem_st* sess_lst, ncr_session_t session);
int ncr_cipher_encrypt(struct list_sem_st* sess_lst, ncr_session_t session, const struct data_item_st * plaintext, struct data_item_st* ciphertext);
int ncr_cipher_decrypt(struct list_sem_st* sess_lst, ncr_session_t session, const struct data_item_st * ciphertext, struct data_item_st* plaintext);

ncr_session_t ncr_cipher_init(struct list_sem_st* sess_lst, ncr_algorithm_t algorithm, struct key_item_st *key, void* iv, size_t iv_size)
{
struct session_item_st* sess;
int ret;
const char* str;

	if (key->type != NCR_KEY_TYPE_SECRET) {
		err();
		return NCR_SESSION_INVALID;
	}

	sess = ncr_session_new(sess_lst);
	if (sess == NULL) {
		err();
		return NCR_SESSION_INVALID;
	}

	str = algo2str(algorithm);
	if (str == NULL) {
		err();
		return NCR_SESSION_INVALID;
	}

	ret = cryptodev_cipher_init(&sess->ctx, str, key->key.secret.data, key->key.secret.size);
	if (ret < 0) {
		err();
		_ncr_sessions_item_put(sess);
		return NCR_SESSION_INVALID;
	}

	return sess->desc;
}

int ncr_cipher_encrypt(struct list_sem_st* sess_lst, ncr_session_t session, const struct data_item_st * plaintext, struct data_item_st* ciphertext)
{
ssize_t output;
struct scatterlist sg, sgo;
struct session_item_st* sess;

	sess = ncr_sessions_item_get( sess_lst, session);
	if (sess == NULL) {
		err();
		return -EINVAL;
	}

	sg_init_one(&sg, plaintext->data, plaintext->data_size);

	sg_init_one(&sgo, ciphertext->data, ciphertext->data_size);
	
	output = cryptodev_cipher_encrypt( &sess->ctx, &sg, &sgo, plaintext->data_size);
	_ncr_sessions_item_put(sess);

	if (output < 0) {
		err();
		return output;
	}

	return 0;
}

/* inplace encryption */
int _ncr_cipher_encrypt(struct list_sem_st* sess_lst, ncr_session_t session, void* plaintext, size_t plaintext_size)
{
ssize_t output;
struct scatterlist sg;
struct session_item_st* sess;

	sess = ncr_sessions_item_get( sess_lst, session);
	if (sess == NULL) {
		err();
		return -EINVAL;
	}

	sg_init_one(&sg, plaintext, plaintext_size);

	output = cryptodev_cipher_encrypt( &sess->ctx, &sg, &sg, plaintext_size);
	_ncr_sessions_item_put(sess);

	if (output < 0) {
		err();
		return output;
	}

	return 0;
}

/* inplace encryption */
int _ncr_cipher_decrypt(struct list_sem_st* sess_lst, ncr_session_t session, void* ciphertext, size_t ciphertext_size)
{
ssize_t output;
struct scatterlist sg;
struct session_item_st* sess;

	sess = ncr_sessions_item_get( sess_lst, session);
	if (sess == NULL) {
		err();
		return -EINVAL;
	}

	sg_init_one(&sg, ciphertext, ciphertext_size);

	output = cryptodev_cipher_encrypt( &sess->ctx, &sg, &sg, ciphertext_size);
	_ncr_sessions_item_put(sess);

	if (output < 0) {
		err();
		return output;
	}

	return 0;
}

int ncr_cipher_decrypt(struct list_sem_st* sess_lst, ncr_session_t session, const struct data_item_st * ciphertext, struct data_item_st* plaintext)
{
ssize_t output;
struct scatterlist sg, sgo;
struct session_item_st* sess;

	sess = ncr_sessions_item_get( sess_lst, session);
	if (sess == NULL) {
		err();
		return -EINVAL;
	}

	sg_init_one(&sgo, plaintext->data, plaintext->data_size);

	sg_init_one(&sg, ciphertext->data, ciphertext->data_size);
	
	output = cryptodev_cipher_decrypt( &sess->ctx, &sg, &sgo, ciphertext->data_size);
	_ncr_sessions_item_put(sess);
	
	if (output < 0) {
		err();
		return output;
	}

	return 0;
}

void ncr_cipher_deinit(struct list_sem_st* lst, ncr_session_t session)
{
	struct session_item_st * item, *tmp;

	down(&lst->sem);
	
	list_for_each_entry_safe(item, tmp, &lst->list, list) {
		if(item->desc == session) {
			list_del(&item->list);
			cryptodev_cipher_deinit(&item->ctx);
			_ncr_sessions_item_put( item); /* decrement ref count */
			break;
		}
	}
	
	up(&lst->sem);

	return;
}
