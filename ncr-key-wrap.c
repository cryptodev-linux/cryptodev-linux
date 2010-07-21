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


static void val64_xor( val64_t val, uint32_t x)
{
	val[7] ^= x & 0xff;
	val[6] ^= (x >> 8) & 0xff;
	val[5] ^= (x >> 16) & 0xff;
	val[4] ^= (x >> 24) & 0xff;
}

static int rfc3394_wrap(val64_t R[], unsigned int n, struct cipher_data* ctx,
	struct data_item_st* odata, const uint8_t iv[8])
{
val64_t A;
uint8_t aes_block[16];
int i,j, ret;
uint8_t * output;
size_t output_size = (n+1)*8;

	if (odata->max_data_size < output_size) {
		err();
		return -EINVAL;
	}
	
	output = kmalloc(output_size, GFP_KERNEL);
	if (output == NULL) {
		err();
		return -ENOMEM;
	}

	memcpy(A, iv, 8);

	for (i=0;i<6*n;i++) {
		memcpy(aes_block, A, 8);
		memcpy(&aes_block[8], R[0], 8);

		_cryptodev_cipher_encrypt(ctx, aes_block, sizeof(aes_block),
			aes_block, sizeof(aes_block));

		memcpy(A, aes_block, 8); /* A = MSB64(AES(A^{t-1}|R_{1}^{t-1})) */
		val64_xor(A, i+1); /* A ^= t */

		for (j=0;j<n-1;j++)
			memcpy(R[j], R[j+1], sizeof(R[j]));
		memcpy(R[n-1], &aes_block[8], 8); /* R[n-1] = LSB64(AES(A^{t-1}|R_{1}^{t-1})) */
	}

	memcpy(output, A, sizeof(A));
	for (j=0;j<n;j++)
		memcpy(&output[(j+1)*8], R[j], 8);
	
	ret = ncr_data_item_setd( odata, output, output_size, odata->flags);
	kfree(output);
	
	return ret;
}

static int rfc3394_unwrap(uint8_t *wrapped_key, val64_t R[], unsigned int n, val64_t A, struct cipher_data *ctx)
{
	int i, j;
	uint8_t aes_block[16];

	memcpy(A, wrapped_key, 8); /* A = C[0] */
	for (i=0;i<n;i++)
		memcpy(R[i], &wrapped_key[(i+1)*8], 8);

	for (i=(6*n)-1;i>=0;i--) {
		val64_xor(A, i+1);

		memcpy(aes_block, A, 8);
		memcpy(&aes_block[8], R[n-1], 8);

		_cryptodev_cipher_decrypt(ctx, aes_block, sizeof(aes_block),
			aes_block, sizeof(aes_block));

		memcpy(A, aes_block, 8);

		for (j=n-1;j>=1;j--)
			memcpy(R[j], R[j-1], sizeof(R[j]));

		memcpy(R[0], &aes_block[8], 8);
	}

	return 0;
}

#define RFC5649_IV "\xA6\x59\x59\xA6"
static int _wrap_aes_rfc5649(void* kdata, size_t kdata_size, struct key_item_st* kek,
	struct data_item_st* output, const void* _iv, size_t iv_size)
{
size_t n;
int i, ret;
struct cipher_data ctx;
uint8_t iv[8];

	if (iv_size != 4) {
		memcpy(iv, RFC5649_IV, 4);
	} else {
		memcpy(iv, _iv, 4);
	}
	iv_size = 8;
	iv[4] = (kdata_size >> 24) & 0xff;
	iv[5] = (kdata_size >> 16) & 0xff;
	iv[6] = (kdata_size >> 8) & 0xff;
	iv[7] = (kdata_size) & 0xff;

	n = (kdata_size+7)/8;
	if (n==1) { /* unimplemented */
		err();
		return -EINVAL;
	}

	ret = cryptodev_cipher_init(&ctx, "ecb(aes)", kek->key.secret.data, kek->key.secret.size);
	if (ret < 0) {
		err();
		return ret;
	}

	{
		val64_t *R;

		R = kmalloc(n * sizeof (*R), GFP_KERNEL);
		if (R == NULL) {
			err();
			ret = -ENOMEM;
			goto cleanup;
		}
		/* R = P */
		for (i=0;i<kdata_size;i++) {
			R[i/8][i%8] = ((uint8_t*)kdata)[i];
		}
		for (;i<n*8;i++) {
			R[i/8][i%8] = 0;
		}
		ret = rfc3394_wrap( R, n, &ctx, output, iv);
		kfree(R);
		if (ret < 0) {
			err();
			goto cleanup;
		}
	}

	ret = 0;

cleanup:
	cryptodev_cipher_deinit(&ctx);

	return ret;
}

static int _unwrap_aes_rfc5649(void* kdata, size_t *kdata_size, struct key_item_st* kek,
	struct data_item_st *wrapped, const void* _iv, size_t iv_size)
{
size_t wrapped_key_size, n;
uint8_t *wrapped_key = NULL;
int i, ret;
struct cipher_data ctx;
uint8_t iv[4];
size_t size;

	if (iv_size != 4) {
		memcpy(iv, RFC5649_IV, 4);
	} else {
		memcpy(iv, _iv, 4);
	}
	iv_size = 4;

	ret = cryptodev_cipher_init(&ctx, "ecb(aes)", kek->key.secret.data, kek->key.secret.size);
	if (ret < 0) {
		err();
		return ret;
	}

	wrapped_key = kmalloc(wrapped->data_size, GFP_KERNEL);
	if (wrapped_key == NULL) {
		err();
		ret = -ENOMEM;
		goto cleanup;
	}

	wrapped_key_size = wrapped->data_size;
	
	ret =  ncr_data_item_getd( wrapped, wrapped_key, wrapped->data_size, wrapped->flags);
	if (ret < 0) {
		err();
		goto cleanup;
	}

	if (wrapped_key_size % 8 != 0) {
		err();
		ret = -EINVAL;
		goto cleanup;
	}

	n = wrapped_key_size/8 - 1;

	if (*kdata_size < (n-1)*8) {
		err();
		ret = -EINVAL;
		goto cleanup;
	}

	{
		val64_t *R, A;

		R = kmalloc(n * sizeof (*R), GFP_KERNEL);
		if (R == NULL) {
			err();
			ret = -ENOMEM;
			goto cleanup;
		}
		ret = rfc3394_unwrap(wrapped_key, R, n, A, &ctx);
		if (ret < 0) {
			err();
			kfree(R);
			return ret;
		}

		if (memcmp(A, iv, 4)!= 0) {
			err();
			kfree(R);
			ret = -EINVAL;
			goto cleanup;
		}

		size = (A[4] << 24) | (A[5] << 16) | (A[6] << 8) | A[7];
		if (size > n*8 || size < (n-1)*8 || *kdata_size < size) {
			err();
			kfree(R);
			ret = -EINVAL;
			goto cleanup;
		}

		memset(kdata, 0, size);
		*kdata_size = size;
		for (i=0;i<size;i++) {
			((uint8_t*)kdata)[i] = R[i/8][i%8];
		}
		kfree(R);
	}


	ret = 0;

cleanup:
	kfree(wrapped_key);
	cryptodev_cipher_deinit(&ctx);

	return ret;
}


static int wrap_aes_rfc5649(struct key_item_st* tobewrapped, struct key_item_st *kek,
	struct data_item_st* output, const void* iv, size_t iv_size)
{
	if (tobewrapped->type != NCR_KEY_TYPE_SECRET) {
		err();
		return -EINVAL;
	}

	return _wrap_aes_rfc5649(tobewrapped->key.secret.data, tobewrapped->key.secret.size,
		kek, output, iv, iv_size);
	
}

static int unwrap_aes_rfc5649(struct key_item_st* output, struct key_item_st *kek,
	struct data_item_st* wrapped, const void* iv, size_t iv_size)
{
	output->type = NCR_KEY_TYPE_SECRET;

	return _unwrap_aes_rfc5649(output->key.secret.data, &output->key.secret.size, kek, wrapped, iv, iv_size);
}
		

/* Wraps using the RFC3394 way.
 */
static int wrap_aes(struct key_item_st* tobewrapped, struct key_item_st *kek,
	struct data_item_st* output, const void* iv, size_t iv_size)
{
size_t key_size, n;
uint8_t *raw_key;
int i, ret;
struct cipher_data ctx;

	if (tobewrapped->type != NCR_KEY_TYPE_SECRET) {
		err();
		return -EINVAL;
	}
	
	if (iv_size < sizeof(initA)) {
		iv_size = sizeof(initA);
		iv = initA;
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


	{
		val64_t R[(NCR_CIPHER_MAX_KEY_LEN + 7) / 8];

		/* R = P */
		for (i=0;i<n;i++) {
			memcpy(R[i], &raw_key[i*8], 8);
		}

		ret = rfc3394_wrap( R, n, &ctx, output, iv);
		if (ret < 0) {
			err();
			goto cleanup;
		}
	}

	ret = 0;

cleanup:
	cryptodev_cipher_deinit(&ctx);

	return ret;
}

#if 0
/* for debugging */
void print_val64(char* str, val64_t val)
{
	int i;
	printk("%s: ",str);
	for (i=0;i<8;i++)
	  printk("%.2x", val[i]);
	printk("\n");
	
}
#endif

static int unwrap_aes(struct key_item_st* output, struct key_item_st *kek,
	struct data_item_st* wrapped, const void* iv, size_t iv_size)
{
size_t wrapped_key_size, n;
uint8_t *wrapped_key = NULL;
val64_t A;
int i, ret;
struct cipher_data ctx;

	if (iv_size < sizeof(initA)) {
		iv_size = sizeof(initA);
		iv = initA;
	}

	ret = cryptodev_cipher_init(&ctx, "ecb(aes)", kek->key.secret.data, kek->key.secret.size);
	if (ret < 0) {
		err();
		return ret;
	}

	output->type = NCR_KEY_TYPE_SECRET;

	wrapped_key = kmalloc(wrapped->data_size, GFP_KERNEL);
	if (wrapped_key == NULL) {
		err();
		ret = -ENOMEM;
		goto cleanup;
	}

	wrapped_key_size = wrapped->data_size;
	
	ret =  ncr_data_item_getd( wrapped, wrapped_key, wrapped_key_size, wrapped->flags);
	if (ret < 0) {
		err();
		goto cleanup;
	}

	if (wrapped_key_size % 8 != 0) {
		err();
		ret = -EINVAL;
		goto cleanup;
	}

	n = wrapped_key_size/8 - 1;

	if (sizeof(output->key.secret.data) < (n-1)*8) {
		err();
		ret = -EINVAL;
		goto cleanup;
	}

	{
		val64_t R[sizeof(output->key.secret.data)/8 + 1];

		ret = rfc3394_unwrap(wrapped_key, R, n, A, &ctx);
		if (ret < 0) {
			err();
			return ret;
		}

		if (memcmp(A, iv, 8)!= 0) {
			err();
			ret = -EINVAL;
			goto cleanup;
		}

		memset(&output->key, 0, sizeof(output->key));
		for (i=0;i<n;i++) {
			memcpy(&output->key.secret.data[i*8], R[i], sizeof(R[i]));
		}
		output->key.secret.size = n*8;
		output->flags = NCR_KEY_FLAG_WRAPPABLE;
		output->type = NCR_KEY_TYPE_SECRET;
	}


	ret = 0;

cleanup:
	kfree(wrapped_key);
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

	if (unlikely(copy_from_user(&wrap, arg, sizeof(wrap)))) {
		err();
		return -EFAULT;
	}

	ret = ncr_key_item_get_read( &wkey, key_lst, wrap.keytowrap);
	if (ret < 0) {
		err();
		return ret;
	}

	if (!(wkey->flags & NCR_KEY_FLAG_WRAPPABLE)) {
		err();
		ret = -EPERM;
		goto fail;
	}

	ret = ncr_key_item_get_read( &key, key_lst, wrap.key.key);
	if (ret < 0) {
		err();
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
			ret = wrap_aes(wkey, key, data, wrap.key.params.cipher.iv, wrap.key.params.cipher.iv_size);
			break;
		case NCR_WALG_AES_RFC5649:
			ret = wrap_aes_rfc5649(wkey, key, data, wrap.key.params.cipher.iv, wrap.key.params.cipher.iv_size);
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

/* Unwraps keys. All keys unwrapped are not accessible by 
 * userspace.
 */
int ncr_key_unwrap(struct list_sem_st* key_lst, struct list_sem_st* data_lst, void __user* arg)
{
struct ncr_key_wrap_st wrap;
struct key_item_st* wkey = NULL;
struct key_item_st* key = NULL;
struct data_item_st * data = NULL;
int ret;

	if (unlikely(copy_from_user(&wrap, arg, sizeof(wrap)))) {
		err();
		return -EFAULT;
	}

	ret = ncr_key_item_get_write( &wkey, key_lst, wrap.keytowrap);
	if (ret < 0) {
		err();
		return ret;
	}

	ret = ncr_key_item_get_read( &key, key_lst, wrap.key.key);
	if (ret < 0) {
		err();
		goto fail;
	}

	data = ncr_data_item_get(data_lst, wrap.data);
	if (data == NULL) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	wkey->flags = data_flags_to_key(data->flags) | NCR_KEY_FLAG_WRAPPABLE;

	switch(wrap.algorithm) {
		case NCR_WALG_AES_RFC3394:
			ret = unwrap_aes(wkey, key, data, wrap.key.params.cipher.iv, wrap.key.params.cipher.iv_size);
			break;
		case NCR_WALG_AES_RFC5649:
			ret = unwrap_aes_rfc5649(wkey, key, data, wrap.key.params.cipher.iv, wrap.key.params.cipher.iv_size);
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

int ncr_key_storage_wrap(struct list_sem_st* key_lst, struct list_sem_st* data_lst, void __user* arg)
{
struct ncr_key_storage_wrap_st wrap;
struct key_item_st* wkey = NULL;
struct data_item_st * data = NULL;
uint8_t * sdata = NULL;
size_t sdata_size = 0;
int ret;

	if (master_key.type != NCR_KEY_TYPE_SECRET) {
		err();
		return -ENOKEY;
	}

	if (unlikely(copy_from_user(&wrap, arg, sizeof(wrap)))) {
		err();
		return -EFAULT;
	}

	ret = ncr_key_item_get_read( &wkey, key_lst, wrap.keytowrap);
	if (ret < 0) {
		err();
		return ret;
	}

	if (!(wkey->flags & NCR_KEY_FLAG_WRAPPABLE)) {
		err();
		ret = -EPERM;
		goto fail;
	}

	data = ncr_data_item_get(data_lst, wrap.data);
	if (data == NULL) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	data->flags = key_flags_to_data(wkey->flags) | NCR_DATA_FLAG_EXPORTABLE;

	ret = key_to_storage_data(&sdata, &sdata_size, wkey);
	if (ret < 0) {
		err();
		goto fail;
	}

	ret = _wrap_aes_rfc5649(sdata, sdata_size, &master_key, data, NULL, 0);

fail:
	if (wkey != NULL) _ncr_key_item_put(wkey);
	if (data != NULL) _ncr_data_item_put(data);
	if (sdata != NULL) kfree(sdata);

	return ret;
}

/* Unwraps keys. All keys unwrapped are not accessible by 
 * userspace.
 */
int ncr_key_storage_unwrap(struct list_sem_st* key_lst, struct list_sem_st* data_lst, void __user* arg)
{
struct ncr_key_storage_wrap_st wrap;
struct key_item_st* wkey = NULL;
struct data_item_st * data = NULL;
uint8_t * sdata = NULL;
size_t sdata_size = 0;
int ret;

	if (master_key.type != NCR_KEY_TYPE_SECRET) {
		err();
		return -ENOKEY;
	}

	if (unlikely(copy_from_user(&wrap, arg, sizeof(wrap)))) {
		err();
		return -EFAULT;
	}

	ret = ncr_key_item_get_write( &wkey, key_lst, wrap.keytowrap);
	if (ret < 0) {
		err();
		return ret;
	}

	data = ncr_data_item_get(data_lst, wrap.data);
	if (data == NULL) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	sdata_size = data->data_size;
	sdata = kmalloc(sdata_size, GFP_KERNEL);
	if (sdata == NULL) {
		err();
		ret = -ENOMEM;
		goto fail;
	}

	wkey->flags = data_flags_to_key(data->flags) | NCR_KEY_FLAG_WRAPPABLE;

	ret = _unwrap_aes_rfc5649(sdata, &sdata_size, &master_key, data, NULL, 0);
	if (ret < 0) {
		err();
		goto fail;
	}

	ret = key_from_storage_data(wkey, sdata, sdata_size);
	if (ret < 0) {
		err();
		goto fail;
	}
	

fail:
	if (wkey != NULL) _ncr_key_item_put(wkey);
	if (data != NULL) _ncr_data_item_put(data);
	if (sdata != NULL) kfree(sdata);

	return ret;
}
