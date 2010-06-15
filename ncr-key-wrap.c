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
#include <linux/highmem.h>
#include <linux/random.h>
#include "cryptodev.h"
#include <asm/uaccess.h>
#include <asm/ioctl.h>
#include <linux/scatterlist.h>
#include "ncr.h"
#include "ncr_int.h"
#include "cryptodev_int.h"

typedef uint8_t val64_t[8];

static const val64_t initA = "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6";

void val64_zero( val64_t * val)
{
	memset(val, 0, sizeof(*val));
}

void val64_xor( val64_t * val, uint32_t x)
{
	(*val)[7] ^= x & 0xff;
	(*val)[6] ^= (x >> 8) & 0xff;
	(*val)[5] ^= (x >> 16) & 0xff;
	(*val)[4] ^= (x >> 24) & 0xff;
}

/* Wraps using the RFC3394 way.
 */
static int wrap_aes(struct key_item_st* tobewrapped, struct key_item_st *kek,
	struct data_item_st* output)
{
size_t key_size, n;
uint8_t *raw_key;
val64_t A;
int i, j, ret;
uint8_t aes_block[16];
struct cipher_data ctx;

	if (tobewrapped->type != NCR_KEY_TYPE_SECRET) {
		err();
		return -EINVAL;
	}

	ret = cryptodev_cipher_init(&ctx, "ecb(aes)", kek->key.secret.data, kek->key.secret.size);
	if (ret < 0) {
		err();
		return ret;
	}

	raw_key = tobewrapped->key.secret.data;
	key_size = tobewrapped->key.secret.size;

	if (key_size % 8 != 0) {
		err();
		ret = -EINVAL;
		goto cleanup;
	}

	n = key_size/8;

	if (output->max_data_size < (n+1)*8) {
		err();
		ret = -EINVAL;
		goto cleanup;
	}


	{
		val64_t R[n];

		/* R = P */
		for (i=0;i<n;i++) {
			memcpy(R[i], &raw_key[i*8], 8);
		}

		memcpy(A, initA, sizeof(initA));

		for (i=0;i<6*n;i++) {
			memcpy(aes_block, A, 8);
			memcpy(&aes_block[8], R[0], 8);

			_cryptodev_cipher_encrypt(&ctx, aes_block, sizeof(aes_block),
				aes_block, sizeof(aes_block));

			memcpy(A, aes_block, 8); /* A = MSB64(AES(A^{t-1}|R_{1}^{t-1})) */
			val64_xor(&A, i+1); /* A ^= t */

			for (j=0;j<n-1;j++)
				memcpy(R[j], R[j+1], sizeof(R[j]));
			memcpy(R[n-1], &aes_block[8], 8); /* R[n-1] = LSB64(AES(A^{t-1}|R_{1}^{t-1})) */
		}

		memcpy(output->data, A, sizeof(A));
		for (j=0;j<n;j++)
			memcpy(&output->data[(j+1)*8], R[j], 8);
		output->data_size = (n+1)*8;
	}


	ret = 0;

cleanup:
	cryptodev_cipher_deinit(&ctx);

	return ret;
}

static int unwrap_aes(struct key_item_st* output, struct key_item_st *kek,
	struct data_item_st* wrapped)
{
size_t key_size, n;
uint8_t *raw_key;
val64_t A;
int i, j, ret;
uint8_t aes_block[16];
struct cipher_data ctx;

	ret = cryptodev_cipher_init(&ctx, "ecb(aes)", kek->key.secret.data, kek->key.secret.size);
	if (ret < 0) {
		err();
		return ret;
	}

	output->type = NCR_KEY_TYPE_SECRET;

	raw_key = wrapped->data;
	key_size = wrapped->data_size;

	if (key_size % 8 != 0) {
		err();
		ret = -EINVAL;
		goto cleanup;
	}

	n = key_size/8 - 1;

	if (sizeof(output->key.secret.data) < (n-1)*8) {
		err();
		ret = -EINVAL;
		goto cleanup;
	}

	{
		val64_t R[n];

		memcpy(A, raw_key, 8); /* A = C[0] */
		for (i=0;i<n;i++)
			memcpy(R[i], &raw_key[(i+1)*8], 8);
		
		for (i=(6*n)-1;i>=0;i--) {
			val64_xor(&A, i+1);

			memcpy(aes_block, A, 8);
			memcpy(&aes_block[8], R[n-1], 8);

			_cryptodev_cipher_decrypt(&ctx, aes_block, sizeof(aes_block),
				aes_block, sizeof(aes_block));

			memcpy(A, aes_block, 8);
			memcpy(R[0], &aes_block[8], 8);

			for (j=1;j<n;j++)
				memcpy(R[j], R[j-1], sizeof(R[j]));
		}

		if (memcmp(A, initA, sizeof(initA))!= 0) {
			err();
			ret = -EINVAL;
			goto cleanup;
		}

		for (i=0;i<n;i++) {
			memcpy(&output->key.secret.data[i*8], R[i], sizeof(R[i]));
		}
		output->key.secret.size = n*8;

	}


	ret = 0;

cleanup:
	cryptodev_cipher_deinit(&ctx);

	return ret;
}

int ncr_key_wrap(struct list_sem_st* key_lst, struct list_sem_st* data_lst, void __user* arg)
{
struct ncr_key_wrap_st wrap;
struct key_item_st* wkey = NULL;
struct key_item_st* key = NULL;
struct data_item_st * data = NULL;
int ret;

	copy_from_user( &wrap, arg, sizeof(wrap));

	wkey = ncr_key_item_get( key_lst, wrap.keytowrap);
	if (wkey == NULL) {
		err();
		return -EINVAL;
	}

	if (!(wkey->flags & NCR_KEY_FLAG_WRAPPABLE)) {
		err();
		return -EPERM;
	}

	key = ncr_key_item_get( key_lst, wrap.key.key);
	if (key == NULL) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	data = ncr_data_item_get(data_lst, wrap.data);
	if (data == NULL) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	data->flags = key_flags_to_data(wkey->flags) | NCR_DATA_FLAG_EXPORTABLE;

	switch(wrap.algorithm) {
		case NCR_WALG_AES_RFC3394:
			ret = wrap_aes(wkey, key, data);
			break;
		default:
			err();
			ret = -EINVAL;
	}

fail:
	if (wkey != NULL) _ncr_key_item_put(wkey);
	if (key != NULL) _ncr_key_item_put(key);
	if (data != NULL) _ncr_data_item_put(data);

	return ret;
}

int ncr_key_unwrap(struct list_sem_st* key_lst, struct list_sem_st* data_lst, void __user* arg)
{
struct ncr_key_wrap_st wrap;
struct key_item_st* wkey = NULL;
struct key_item_st* key = NULL;
struct data_item_st * data = NULL;
int ret;

	copy_from_user( &wrap, arg, sizeof(wrap));

	wkey = ncr_key_item_get( key_lst, wrap.keytowrap);
	if (wkey == NULL) {
		err();
		return -EINVAL;
	}

	key = ncr_key_item_get( key_lst, wrap.key.key);
	if (key == NULL) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	data = ncr_data_item_get(data_lst, wrap.data);
	if (data == NULL) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	wkey->flags = data_flags_to_key(wkey->flags) | NCR_KEY_FLAG_WRAPPABLE;

	switch(wrap.algorithm) {
		case NCR_WALG_AES_RFC3394:
			ret = unwrap_aes(wkey, key, data);
			break;
		default:
			err();
			ret = -EINVAL;
	}

fail:
	if (wkey != NULL) _ncr_key_item_put(wkey);
	if (key != NULL) _ncr_key_item_put(key);
	if (data != NULL) _ncr_data_item_put(data);

	return ret;
}
