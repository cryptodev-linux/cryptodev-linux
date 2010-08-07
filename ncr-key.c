/*
 * New driver for /dev/crypto device (aka CryptoDev)
 *
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
#include <linux/random.h>
#include <linux/uaccess.h>
#include "cryptodev.h"
#include <linux/scatterlist.h>
#include "ncr.h"
#include "ncr-int.h"

static void ncr_key_clear(struct key_item_st* item);

static int key_list_deinit_fn(int id, void *item, void *unused)
{
	(void)unused;
	_ncr_key_item_put(item);
	return 0;
}

void ncr_key_list_deinit(struct ncr_lists *lst)
{
	/* The mutex is not necessary, but doesn't hurt and makes it easier to
	   verify locking correctness. */
	mutex_lock(&lst->key_idr_mutex);
	idr_for_each(&lst->key_idr, key_list_deinit_fn, NULL);
	idr_remove_all(&lst->key_idr);
	idr_destroy(&lst->key_idr);
	mutex_unlock(&lst->key_idr_mutex);
}

/* returns the data item corresponding to desc */
int ncr_key_item_get_read(struct key_item_st**st, struct ncr_lists *lst,
	ncr_key_t desc)
{
struct key_item_st* item;
int ret;
	
	*st = NULL;
	
	mutex_lock(&lst->key_idr_mutex);
	item = idr_find(&lst->key_idr, desc);
	if (item == NULL) {
		err();
		ret = -EINVAL;
		goto exit;
	}
	atomic_inc(&item->refcnt);

	if (atomic_read(&item->writer) != 0) {
		/* writer in place busy */
		atomic_dec(&item->refcnt);
		ret = -EBUSY;
		goto exit;
	}

	*st = item;
	ret = 0;

exit:
	mutex_unlock(&lst->key_idr_mutex);
	return ret;
}

/* as above but will never return anything that
 * is in use.
 */
int ncr_key_item_get_write( struct key_item_st** st, 
	struct ncr_lists *lst, ncr_key_t desc)
{
struct key_item_st* item;
int ret;

	*st = NULL;

	mutex_lock(&lst->key_idr_mutex);
	item = idr_find(&lst->key_idr, desc);
	if (item == NULL) {
		err();
		ret = -EINVAL;
		goto exit;
	}
	/* do not return items that are in use already */

	if (atomic_add_unless(&item->writer, 1, 1)==0) {
		/* another writer so busy */
		ret = -EBUSY;
		goto exit;
	}

	if (atomic_add_unless(&item->refcnt, 1, 2)==0) {
		/* some reader is active so busy */
		atomic_dec(&item->writer);
		ret = -EBUSY;
		goto exit;
	}

	*st = item;
	ret = 0;

exit:
	mutex_unlock(&lst->key_idr_mutex);
	return ret;
}

void _ncr_key_item_put( struct key_item_st* item)
{
	if (atomic_read(&item->writer) > 0)
		atomic_dec(&item->writer);
	if (atomic_dec_and_test(&item->refcnt)) {
			ncr_limits_remove(item->uid, item->pid, LIMIT_TYPE_KEY);
			ncr_key_clear(item);
			kfree(item);
	}
}

static void _ncr_key_remove(struct ncr_lists *lst, ncr_key_t desc)
{
	struct key_item_st * item;

	mutex_lock(&lst->key_idr_mutex);
	item = idr_find(&lst->key_idr, desc);
	if (item != NULL)
		idr_remove(&lst->key_idr, desc); /* Steal the reference */
	mutex_unlock(&lst->key_idr_mutex);

	if (item != NULL)
		_ncr_key_item_put(item);
}

int ncr_key_init(struct ncr_lists *lst, void __user* arg)
{
	ncr_key_t desc;
	struct key_item_st* key;
	int ret;

	ret = ncr_limits_add_and_check(current_euid(), task_pid_nr(current), LIMIT_TYPE_KEY);
	if (ret < 0) {
		err();
		return ret;
	}

	key = kmalloc(sizeof(*key), GFP_KERNEL);
	if (key == NULL) {
		err();
		ret = -ENOMEM;
		goto err_limits;
	}

	memset(key, 0, sizeof(*key));

	atomic_set(&key->refcnt, 1);
	atomic_set(&key->writer, 0);
	key->uid = current_euid();
	key->pid = task_pid_nr(current);

	mutex_lock(&lst->key_idr_mutex);
	/* idr_pre_get() should preallocate enough, and, due to key_idr_mutex,
	   nobody else can use the preallocated data.  Therefore the loop
	   recommended in idr_get_new() documentation is not necessary. */
	if (idr_pre_get(&lst->key_idr, GFP_KERNEL) == 0 ||
	    idr_get_new(&lst->key_idr, key, &key->desc) != 0) {
		mutex_unlock(&lst->key_idr_mutex);
		_ncr_key_item_put(key);
		return -ENOMEM;
	}
	desc = key->desc;
	mutex_unlock(&lst->key_idr_mutex);

	ret = copy_to_user(arg, &desc, sizeof(desc));
	if (unlikely(ret)) {
		_ncr_key_remove(lst, desc);
		return -EFAULT;
	}
	return ret;

err_limits:
	ncr_limits_remove(current_euid(), task_pid_nr(current), LIMIT_TYPE_KEY);
	return ret;
}

int ncr_key_deinit(struct ncr_lists *lst, void __user* arg)
{
	ncr_key_t desc;

	if (unlikely(copy_from_user(&desc, arg, sizeof(desc)))) {
		err();
		return -EFAULT;
	}

	_ncr_key_remove(lst, desc);

	return 0;
}

/* "exports" a key to a data item. If the key is not exportable
 * to userspace then the data item will also not be.
 */
int ncr_key_export(struct ncr_lists *lst, void __user* arg)
{
struct ncr_key_data_st data;
struct key_item_st* item = NULL;
void* tmp = NULL;
uint32_t tmp_size;
int ret;

	if (unlikely(copy_from_user(&data, arg, sizeof(data)))) {
		err();
		return -EFAULT;
	}

	ret = ncr_key_item_get_read( &item, lst, data.key);
	if (ret < 0) {
		err();
		return ret;
	}

	if (!(item->flags & NCR_KEY_FLAG_EXPORTABLE)) {
		err();
		ret = -EPERM;
		goto fail;
	}

	switch (item->type) {
		case NCR_KEY_TYPE_SECRET:
			if (item->key.secret.size > data.idata_size) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			/* found */
			if (item->key.secret.size > 0) {
				ret = copy_to_user(data.idata, item->key.secret.data, item->key.secret.size);
				if (unlikely(ret)) {
					err();
					ret = -EFAULT;
					goto fail;
				}
			}

			data.idata_size = item->key.secret.size;
			break;
		case NCR_KEY_TYPE_PUBLIC:
		case NCR_KEY_TYPE_PRIVATE:
			tmp_size = data.idata_size;
			
			tmp = kmalloc(tmp_size, GFP_KERNEL);
			if (tmp == NULL) {
				err();
				ret = -ENOMEM;
				goto fail;
			}

			ret = ncr_pk_pack(item, tmp, &tmp_size);
			data.idata_size = tmp_size;
			
			if (ret < 0) {
				err();
				goto fail;
			}

			ret = copy_to_user(data.idata, tmp, tmp_size);
			if (unlikely(ret)) {
				err();
				ret = -EFAULT;
				goto fail;
			}
			
			break;
		default:
			err();
			ret = -EINVAL;
			goto fail;
	}

	if (unlikely(copy_to_user(arg, &data, sizeof(data)))) {
		err();
		ret = -EFAULT;
	} else
		ret = 0;

fail:
	kfree(tmp);
	if (item)
		_ncr_key_item_put(item);
	return ret;
	
}

/* "imports" a key from a data item. If the key is not exportable
 * to userspace then the key item will also not be.
 */
int ncr_key_import(struct ncr_lists *lst, void __user* arg)
{
struct ncr_key_data_st data;
struct key_item_st* item = NULL;
int ret;
void* tmp = NULL;
size_t tmp_size;

	if (unlikely(copy_from_user(&data, arg, sizeof(data)))) {
		err();
		return -EFAULT;
	}

	ret = ncr_key_item_get_write( &item, lst, data.key);
	if (ret < 0) {
		err();
		return ret;
	}

	ncr_key_clear(item);

	tmp = kmalloc(data.idata_size, GFP_KERNEL);
	if (tmp == NULL) {
		err();
		ret = -ENOMEM;
		goto fail;
	}
	
	if (unlikely(copy_from_user(tmp, data.idata, data.idata_size))) {
		err();
		ret = -EFAULT;
		goto fail;
	}
	tmp_size = data.idata_size;
	
	item->type = data.type;
	item->algorithm = _ncr_algo_to_properties(data.algorithm);
	if (item->algorithm == NULL) {
		err();
		ret = -EINVAL;
		goto fail;
	}
	item->flags = data.flags;

	if (data.key_id_size > MAX_KEY_ID_SIZE) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	item->key_id_size = data.key_id_size;
	if (data.key_id_size > 0)
		memcpy(item->key_id, data.key_id, data.key_id_size);

	switch(item->type) {
		case NCR_KEY_TYPE_SECRET:

			if (tmp_size > NCR_CIPHER_MAX_KEY_LEN) {
				err();
				ret = -EINVAL;
				goto fail;
			}
			
			memcpy(item->key.secret.data, tmp, tmp_size);
			item->key.secret.size = tmp_size;
			break;
		case NCR_KEY_TYPE_PRIVATE:
		case NCR_KEY_TYPE_PUBLIC:
			ret = ncr_pk_unpack( item, tmp, tmp_size);
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
	if (item)
		_ncr_key_item_put(item);
	kfree(tmp);

	return ret;
}

static void ncr_key_clear(struct key_item_st* item)
{
	/* clears any previously allocated parameters */
	if (item->type == NCR_KEY_TYPE_PRIVATE ||
		item->type == NCR_KEY_TYPE_PUBLIC) {
		
		ncr_pk_clear(item);
	}
	memset(&item->key, 0, sizeof(item->key));
	memset(item->key_id, 0, sizeof(item->key_id));
	item->key_id_size = 0;
	item->flags = 0;
	
	return;
}

/* Generate a secret key
 */
int ncr_key_generate(struct ncr_lists *lst, void __user* arg)
{
struct ncr_key_generate_st gen;
struct key_item_st* item = NULL;
const struct algo_properties_st *algo;
int ret;
size_t size;

	if (unlikely(copy_from_user(&gen, arg, sizeof(gen)))) {
		err();
		return -EFAULT;
	}

	ret = ncr_key_item_get_write( &item, lst, gen.desc);
	if (ret < 0) {
		err();
		return ret;
	}

	ncr_key_clear(item);

	/* we generate only secret keys */
	item->flags = gen.params.keyflags;
	algo = _ncr_algo_to_properties(gen.params.algorithm);
	if (algo == NULL) {
		err();
		ret = -EINVAL;
		goto fail;
	}
	item->type = algo->key_type;
	if (item->type == NCR_KEY_TYPE_SECRET) {
		item->algorithm = algo;

		size = gen.params.params.secret.bits/8;
		if ((gen.params.params.secret.bits % 8 != 0) ||
				(size > NCR_CIPHER_MAX_KEY_LEN)) {
			err();
			ret = -EINVAL;
			goto fail;
		}

		get_random_bytes(item->key.secret.data, size);
		item->key.secret.size = size;

		/* generate random key id */
		item->key_id_size = 5;
		get_random_bytes(item->key_id, item->key_id_size);
	} else {
		err();
		ret = -EINVAL;
		goto fail;
	}
	
	ret = 0;

fail:
	if (item) {
		if (ret < 0) item->type = NCR_KEY_TYPE_INVALID;
		_ncr_key_item_put(item);
	}
	return ret;
}

int ncr_key_info(struct ncr_lists *lst, void __user* arg)
{
struct ncr_key_info_st info;
struct key_item_st* item = NULL;
int ret;

	if (unlikely(copy_from_user(&info, arg, sizeof(info)))) {
		err();
		return -EFAULT;
	}

	ret = ncr_key_item_get_read(&item, lst, info.key);
	if (ret < 0) {
		err();
		return ret;
	}
	
	if (item->type == NCR_KEY_TYPE_INVALID) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	info.flags = item->flags;
	info.type = item->type;
	info.algorithm = item->algorithm->algo;
	
	ret = 0;

fail:
	_ncr_key_item_put( item);

	return ret;
}

int ncr_key_generate_pair(struct ncr_lists *lst, void __user* arg)
{
struct ncr_key_generate_st gen;
struct key_item_st* private = NULL;
struct key_item_st* public = NULL;
int ret;

	if (unlikely(copy_from_user(&gen, arg, sizeof(gen)))) {
		err();
		return -EFAULT;
	}

	ret = ncr_key_item_get_write( &private, lst, gen.desc);
	if (ret < 0) {
		err();
		goto fail;
	}

	ret = ncr_key_item_get_write( &public, lst, gen.desc2);
	if (ret < 0) {
		err();
		goto fail;
	}

	ncr_key_clear(public);
	ncr_key_clear(private);

	/* we generate only secret keys */
	private->flags = public->flags = gen.params.keyflags;
	private->algorithm = public->algorithm = _ncr_algo_to_properties(gen.params.algorithm);
	if (private->algorithm == NULL) {
		err();
		ret = -EINVAL;
		goto fail;
	}
	public->type = public->algorithm->key_type;
	private->type = NCR_KEY_TYPE_PRIVATE;
	public->flags |= (NCR_KEY_FLAG_EXPORTABLE|NCR_KEY_FLAG_WRAPPABLE);
	
	if (public->type == NCR_KEY_TYPE_PUBLIC) {
		ret = ncr_pk_generate(public->algorithm, &gen.params, private, public);
		if (ret < 0) {
			err();
			goto fail;
		}
	} else {
		err();
		ret = -EINVAL;
		goto fail;
	}
	
	ret = 0;
fail:
	if (public) {
		if (ret < 0) public->type = NCR_KEY_TYPE_INVALID;
		_ncr_key_item_put(public);
	}
	if (private) {
		if (ret < 0) private->type = NCR_KEY_TYPE_INVALID;
		_ncr_key_item_put(private);
	}
	return ret;
}

/* "exports" a key to a data item. If the key is not exportable
 * to userspace then the data item will also not be.
 */
int ncr_key_derive(struct ncr_lists *lst, void __user* arg)
{
struct ncr_key_derivation_params_st data;
int ret;
struct key_item_st* key = NULL;
struct key_item_st* newkey = NULL;

	if (unlikely(copy_from_user(&data, arg, sizeof(data)))) {
		err();
		return -EFAULT;
	}

	ret = ncr_key_item_get_read( &key, lst, data.key);
	if (ret < 0) {
		err();
		return ret;
	}

	ret = ncr_key_item_get_write( &newkey, lst, data.newkey);
	if (ret < 0) {
		err();
		goto fail;
	}

	ncr_key_clear(newkey);

	newkey->flags = data.keyflags;

	switch (key->type) {
		case NCR_KEY_TYPE_PUBLIC:
		case NCR_KEY_TYPE_PRIVATE:
			ret = ncr_pk_derive(newkey, key, &data);
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

	if (unlikely(copy_to_user(arg, &data, sizeof(data)))) {
		err();
		ret = -EFAULT;
	} else
		ret = 0;

fail:
	if (key)
		_ncr_key_item_put(key);
	if (newkey)
		_ncr_key_item_put(newkey);
	return ret;
	
}

