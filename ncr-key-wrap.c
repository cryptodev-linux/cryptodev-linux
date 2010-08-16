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

#include <linux/ioctl.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/random.h>
#include <linux/uaccess.h>
#include <linux/scatterlist.h>
#include <net/netlink.h>
#include "ncr.h"
#include "ncr-int.h"
#include "cryptodev_int.h"

typedef uint8_t val64_t[8];

static const val64_t initA = "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6";

static int key_to_packed_data( uint8_t** sdata, size_t * sdata_size, const struct key_item_st *key);
static int key_from_packed_data(ncr_algorithm_t algorithm, unsigned int flags,
	struct key_item_st* key, const void* data, size_t data_size);


static void val64_xor( val64_t val, uint32_t x)
{
	val[7] ^= x & 0xff;
	val[6] ^= (x >> 8) & 0xff;
	val[5] ^= (x >> 16) & 0xff;
	val[4] ^= (x >> 24) & 0xff;
}

static int rfc3394_wrap(val64_t *R, unsigned int n, struct cipher_data* ctx,
	uint8_t* output, size_t *output_size, const uint8_t iv[8])
{
val64_t A;
uint8_t aes_block[16];
int i,j;

	if (*output_size < (n+1)*8) {
		err();
		return -ERANGE;
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
	*output_size = (n+1)*8;

	return 0;
}

static int rfc3394_unwrap(const uint8_t *wrapped_key, val64_t R[], unsigned int n, val64_t A, struct cipher_data *ctx)
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
	void* output, size_t* output_size, const void* _iv, size_t iv_size)
{
size_t n;
int i, ret;
struct cipher_data ctx;
uint8_t iv[8];
val64_t *R = NULL;

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

	ret = rfc3394_wrap( R, n, &ctx, output, output_size, iv);
	if (ret < 0) {
		err();
		goto cleanup;
	}

	ret = 0;

cleanup:
	kfree(R);
	cryptodev_cipher_deinit(&ctx);

	return ret;
}

static int _unwrap_aes_rfc5649(void* kdata, size_t *kdata_size, struct key_item_st* kek,
	const void *wrapped_key, size_t wrapped_key_size, const void* _iv, size_t iv_size)
{
size_t n;
int i, ret;
struct cipher_data ctx;
uint8_t iv[4];
size_t size;
val64_t *R = NULL, A;

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

	R = kmalloc(n * sizeof (*R), GFP_KERNEL);
	if (R == NULL) {
		err();
		ret = -ENOMEM;
		goto cleanup;
	}

	ret = rfc3394_unwrap(wrapped_key, R, n, A, &ctx);
	if (ret < 0) {
		err();
		goto cleanup;
	}

	if (memcmp(A, iv, 4)!= 0) {
		err();
		ret = -EINVAL;
		goto cleanup;
	}

	size = (A[4] << 24) | (A[5] << 16) | (A[6] << 8) | A[7];
	if (size > n*8 || size < (n-1)*8 || *kdata_size < size) {
		err();
		ret = -EINVAL;
		goto cleanup;
	}

	memset(kdata, 0, size);
	*kdata_size = size;
	for (i=0;i<size;i++) {
		((uint8_t*)kdata)[i] = R[i/8][i%8];
	}

	ret = 0;

cleanup:
	kfree(R);
	cryptodev_cipher_deinit(&ctx);

	return ret;
}


static int wrap_aes_rfc5649(struct key_item_st* tobewrapped, struct key_item_st *kek,
	void* output, size_t* output_size, const void* iv, size_t iv_size)
{
int ret;
uint8_t* sdata;
size_t sdata_size = 0;

	ret = key_to_packed_data(&sdata, &sdata_size, tobewrapped);
	if (ret < 0) {
		err();
		return ret;
	}

	ret = _wrap_aes_rfc5649(sdata, sdata_size,
		kek, output, output_size, iv, iv_size);

	kfree(sdata);
	
	return ret;
}

static int unwrap_aes_rfc5649(struct key_item_st* output, struct key_item_st *kek,
	void* wrapped, size_t wrapped_size, 
	struct ncr_key_wrap_st* wrap_st)
{
int ret;
void * sdata;
size_t sdata_size = KEY_DATA_MAX_SIZE;

	sdata = kmalloc(sdata_size, GFP_KERNEL);
	if (sdata == NULL) { 
		err();
		return -ENOMEM;
	}

	ret = _unwrap_aes_rfc5649(sdata, &sdata_size, kek, 
		wrapped, wrapped_size, 
		wrap_st->params.params.cipher.iv, wrap_st->params.params.cipher.iv_size);
	if (ret < 0) {
		err();
		goto fail;
	}

	ret = key_from_packed_data(wrap_st->wrapped_key_algorithm, wrap_st->wrapped_key_flags, 
		output, sdata, sdata_size);
	if (ret < 0) {
		err();
		goto fail;
	}
	
	ret = 0;
	
fail:
	kfree(sdata);
	return ret;

}
		

/* Wraps using the RFC3394 way.
 */
static int wrap_aes(struct key_item_st* tobewrapped, struct key_item_st *kek,
	void* output, size_t *output_size, const void* iv, size_t iv_size)
{
size_t key_size, n;
uint8_t *raw_key;
int i, ret;
struct cipher_data ctx;
val64_t *R = NULL;

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


	R = kmalloc(sizeof(*R)*n, GFP_KERNEL);
	if (R == NULL) {
		err();
		ret = -ENOMEM;
		goto cleanup;
	}

	/* R = P */
	for (i=0;i<n;i++) {
		memcpy(R[i], &raw_key[i*8], 8);
	}

	ret = rfc3394_wrap( R, n, &ctx, output, output_size, iv);
	if (ret < 0) {
		err();
		goto cleanup;
	}

	ret = 0;

cleanup:
	kfree(R);
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

static int unwrap_aes_rfc3394(struct key_item_st* output, struct key_item_st *kek,
	void* wrapped_key, size_t wrapped_key_size, struct ncr_key_wrap_st *wrap_st)
{
size_t n;
val64_t A;
int i, ret;
struct cipher_data ctx;
val64_t * R = NULL;
int iv_size = wrap_st->params.params.cipher.iv_size;
const uint8_t * iv = wrap_st->params.params.cipher.iv;

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

	if (wrapped_key_size % 8 != 0) {
		err();
		ret = -EINVAL;
		goto cleanup;
	}

	n = wrapped_key_size/8 - 1;

	if (NCR_CIPHER_MAX_KEY_LEN < (n-1)*8) {
		err();
		ret = -EINVAL;
		goto cleanup;
	}

	R = kmalloc(sizeof(*R)*n, GFP_KERNEL);
	if (R == NULL) {
		err();
		ret = -ENOMEM;
		goto cleanup;
	}

	ret = rfc3394_unwrap(wrapped_key, R, n, A, &ctx);
	if (ret < 0) {
		err();
		goto cleanup;
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
	ncr_key_assign_flags(output, wrap_st->wrapped_key_flags);
	output->type = NCR_KEY_TYPE_SECRET;

	ret = 0;

cleanup:
	kfree(R);
	cryptodev_cipher_deinit(&ctx);

	return ret;
}

/* will check if the kek is of equal or higher security level than
 * wkey. To prevent encrypting a 256 bit key with an 128 bit one.
 */
int check_key_level(struct key_item_st* kek, struct key_item_st* wkey)
{
int kek_level, wkey_level;

	/* allow wrapping of public keys with any key */
	if (wkey->type == NCR_KEY_TYPE_PUBLIC)
		return 0;

	kek_level = _ncr_key_get_sec_level(kek);
	if (kek_level < 0) {
		err();
		return kek_level;
	}

	wkey_level = _ncr_key_get_sec_level(wkey);
	if (wkey_level < 0) {
		err();
		return wkey_level;
	}
	
	if (wkey_level > kek_level) {
		err();
		return -EPERM;
	}
	
	return 0;
}

int ncr_key_wrap(struct ncr_lists *lst, const struct ncr_key_wrap *wrap,
		 struct nlattr *tb[])
{
const struct nlattr *nla;
struct key_item_st* wkey = NULL;
struct key_item_st* key = NULL;
void* data = NULL;
const void *iv;
size_t data_size, iv_size;
int ret;

	if (wrap->buffer_size < 0) {
		err();
		return -EINVAL;
	}

	ret = ncr_key_item_get_read(&wkey, lst, wrap->source_key);
	if (ret < 0) {
		err();
		return ret;
	}

	if (!(wkey->flags & NCR_KEY_FLAG_WRAPPABLE)) {
		err();
		ret = -EPERM;
		goto fail;
	}

	ret = ncr_key_item_get_read(&key, lst, wrap->wrapping_key);
	if (ret < 0) {
		err();
		goto fail;
	}

	if (!(key->flags & NCR_KEY_FLAG_WRAPPING)) {
		err();
		ret = -EPERM;
		goto fail;
	}
	
	ret = check_key_level(key, wkey);
	if (ret < 0) {
		err();
		goto fail;
	}

	data_size = wrap->buffer_size;
	data = kmalloc(data_size, GFP_KERNEL);
	if (data == NULL) {
		err();
		ret = -ENOMEM;
		goto fail;
	}
	
	nla = tb[NCR_ATTR_IV];
	if (nla != NULL) {
		iv = nla_data(nla);
		iv_size = nla_len(nla);
	} else {
		iv = NULL;
		iv_size = 0;
	}

	nla = tb[NCR_ATTR_WRAPPING_ALGORITHM];
	if (nla == NULL) {
		err();
		ret = -EINVAL;
		goto fail;
	}
	switch (nla_get_u32(nla)) {
		case NCR_WALG_AES_RFC3394:
			ret = wrap_aes(wkey, key, data, &data_size, iv,
				       iv_size);
			break;
		case NCR_WALG_AES_RFC5649:
			ret = wrap_aes_rfc5649(wkey, key, data, &data_size, iv,
					       iv_size);
			break;
		default:
			err();
			ret = -EINVAL;
	}
	
	if (ret < 0) {
		err();
		goto fail;
	}

	ret = copy_to_user(wrap->buffer, data, data_size);
	if (unlikely(ret)) {
		ret = -EFAULT;
		goto fail;
	}

	ret = data_size;

fail:
	if (wkey != NULL) _ncr_key_item_put(wkey);
	if (key != NULL) _ncr_key_item_put(key);
	kfree(data);

	return ret;
}

/* Unwraps keys. All keys unwrapped are not accessible by 
 * userspace.
 */
int ncr_key_unwrap(struct ncr_lists *lst, void __user* arg)
{
struct ncr_key_wrap_st wrap;
struct key_item_st* wkey = NULL;
struct key_item_st* key = NULL;
void* data = NULL;
size_t data_size;
int ret;

	if (unlikely(copy_from_user(&wrap, arg, sizeof(wrap)))) {
		err();
		return -EFAULT;
	}

	ret = ncr_key_item_get_write( &wkey, lst, wrap.keytowrap);
	if (ret < 0) {
		err();
		return ret;
	}

	ret = ncr_key_item_get_read( &key, lst, wrap.key);
	if (ret < 0) {
		err();
		goto fail;
	}

	if (!(key->flags & NCR_KEY_FLAG_WRAPPING)) {
		err();
		ret = -EPERM;
		goto fail;
	}

	data_size = wrap.io_size;
	data = kmalloc(data_size, GFP_KERNEL);
	if (data == NULL) {
		err();
		ret = -ENOMEM;
		goto fail;
	}

	if (unlikely(copy_from_user(data, wrap.io, data_size))) {
		err();
		ret = -EFAULT;
		goto fail;
	}
	
	ncr_key_clear(wkey);

	switch(wrap.algorithm) {
		case NCR_WALG_AES_RFC3394:
			ret = unwrap_aes_rfc3394(wkey, key, data, data_size, 
				&wrap);
			break;
		case NCR_WALG_AES_RFC5649:
			ret = unwrap_aes_rfc5649(wkey, key, 
				data, data_size, &wrap);
			break;
		default:
			err();
			ret = -EINVAL;
	}
	
fail:
	if (wkey != NULL) _ncr_key_item_put(wkey);
	if (key != NULL) _ncr_key_item_put(key);
	if (data != NULL) kfree(data);

	return ret;
}

int ncr_key_storage_wrap(struct ncr_lists *lst, void __user* arg)
{
struct ncr_key_storage_wrap_st wrap;
struct key_item_st* wkey = NULL;
void* data = NULL;
size_t data_size;
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

	ret = ncr_key_item_get_read( &wkey, lst, wrap.keytowrap);
	if (ret < 0) {
		err();
		return ret;
	}

	data_size = wrap.io_size;
	data = kmalloc(data_size, GFP_KERNEL);
	if (data == NULL) {
		err();
		ret = -ENOMEM;
		goto fail;
	}
	
	ret = key_to_storage_data(&sdata, &sdata_size, wkey);
	if (ret < 0) {
		err();
		goto fail;
	}

	ret = _wrap_aes_rfc5649(sdata, sdata_size, &master_key, data, &data_size, NULL, 0);
	if (ret < 0) {
		err();
		goto fail;
	}

	ret = copy_to_user(wrap.io, data, data_size);
	if (unlikely(ret)) {
		ret = -EFAULT;
		goto fail;
	}

	wrap.io_size = data_size;

	ret = copy_to_user(arg, &wrap, sizeof(wrap));
	if (unlikely(ret)) {
		ret = -EFAULT;
	}

fail:
	if (wkey != NULL) _ncr_key_item_put(wkey);
	if (data != NULL) kfree(data);
	if (sdata != NULL) kfree(sdata);

	return ret;
}

/* Unwraps keys. All keys unwrapped are not accessible by 
 * userspace.
 */
int ncr_key_storage_unwrap(struct ncr_lists *lst, void __user* arg)
{
struct ncr_key_storage_wrap_st wrap;
struct key_item_st* wkey = NULL;
void* data = NULL;
uint8_t * sdata = NULL;
size_t sdata_size = 0, data_size;
int ret;

	if (master_key.type != NCR_KEY_TYPE_SECRET) {
		err();
		return -ENOKEY;
	}

	if (unlikely(copy_from_user(&wrap, arg, sizeof(wrap)))) {
		err();
		return -EFAULT;
	}

	ret = ncr_key_item_get_write( &wkey, lst, wrap.keytowrap);
	if (ret < 0) {
		err();
		return ret;
	}

	data_size = wrap.io_size;
	data = kmalloc(data_size, GFP_KERNEL);
	if (data == NULL) {
		err();
		ret = -ENOMEM;
		goto fail;
	}

	if (unlikely(copy_from_user(data, wrap.io, data_size))) {
		err();
		ret = -EFAULT;
		goto fail;
	}

	sdata_size = data_size;
	sdata = kmalloc(sdata_size, GFP_KERNEL);
	if (sdata == NULL) {
		err();
		ret = -ENOMEM;
		goto fail;
	}

	ret = _unwrap_aes_rfc5649(sdata, &sdata_size, &master_key, data, data_size, NULL, 0);
	if (ret < 0) {
		err();
		goto fail;
	}

	ncr_key_clear(wkey);

	ret = key_from_storage_data(wkey, sdata, sdata_size);
	if (ret < 0) {
		err();
		goto fail;
	}
	

fail:
	if (wkey != NULL) _ncr_key_item_put(wkey);
	if (data != NULL) kfree(data);
	if (sdata != NULL) kfree(sdata);

	return ret;
}

static int key_to_packed_data( uint8_t** sdata, size_t * sdata_size, const struct key_item_st *key)
{
	uint8_t * pkey;
	uint32_t usize;
	int ret;
	
	*sdata_size = KEY_DATA_MAX_SIZE;
	pkey = kmalloc(*sdata_size, GFP_KERNEL);
	if (pkey == NULL) {
		err();
		return -ENOMEM;
	}

	if (key->type == NCR_KEY_TYPE_SECRET) {
		memcpy(pkey, key->key.secret.data, key->key.secret.size);
		*sdata_size = key->key.secret.size;
	} else if (key->type == NCR_KEY_TYPE_PRIVATE || key->type == NCR_KEY_TYPE_PUBLIC) {
		usize = *sdata_size;
		ret = ncr_pk_pack( key, pkey, &usize);
		if (ret < 0) {
			err();
			goto fail;
		}
		*sdata_size = usize;
	} else {
		err();
		ret = -EINVAL;
		goto fail;
	}

	*sdata = (void*)pkey;

	return 0;
fail:
	kfree(pkey);

	return ret;
}

static int key_from_packed_data(ncr_algorithm_t algorithm, unsigned int flags,
	struct key_item_st* key, const void* data, size_t data_size)
{
	int ret;

	if (data_size > KEY_DATA_MAX_SIZE) {
		err();
		return -EINVAL;
	}

	key->algorithm = _ncr_algo_to_properties(algorithm);
	if (key->algorithm == NULL) {
		err();
		return -EINVAL;
	}

	key->type = key->algorithm->key_type;
	ncr_key_assign_flags(key, flags);

	if (key->type == NCR_KEY_TYPE_SECRET) {
		if (data_size > NCR_CIPHER_MAX_KEY_LEN) {
			err();
			return -EINVAL;
		}
		key->key.secret.size = data_size;
		memcpy(key->key.secret.data, data, data_size);
	} else if (key->type == NCR_KEY_TYPE_PUBLIC 
		|| key->type == NCR_KEY_TYPE_PRIVATE) {

		ret = ncr_pk_unpack( key, data, data_size);
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
