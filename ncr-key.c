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

/* must be called with data semaphore down */
static void _ncr_key_unlink_item(struct key_item_st *item)
{
	list_del(&item->list);
	_ncr_key_item_put( item); /* decrement ref count */
}

void ncr_key_list_deinit(struct list_sem_st* lst)
{
	if(lst) {
		struct key_item_st * item, *tmp;

		down(&lst->sem);

		list_for_each_entry_safe(item, tmp, &lst->list, list) {
			_ncr_key_unlink_item(item);
		}
		up(&lst->sem);
	}
}

/* must be called with data semaphore down
 */
static ncr_key_t _ncr_key_get_new_desc( struct list_sem_st* lst)
{
struct key_item_st* item;
int mx = 1;

	list_for_each_entry(item, &lst->list, list) {
		mx = max(mx, item->desc);
	}
	mx++;

	return mx;
}

/* returns the data item corresponding to desc */
int ncr_key_item_get_read(struct key_item_st**st, struct list_sem_st* lst, 
	ncr_key_t desc)
{
struct key_item_st* item;
int ret;
	
	*st = NULL;
	
	down(&lst->sem);
	list_for_each_entry(item, &lst->list, list) {
		if (item->desc == desc) {
			atomic_inc(&item->refcnt);
			
			if (atomic_read(&item->writer) != 0) {
				/* writer in place busy */
				atomic_dec(&item->refcnt);
				ret = -EBUSY;
				goto exit;
			}
			
			*st = item;
			ret = 0;
			goto exit;
		}
	}

	err();
	ret = -EINVAL;
exit:
	up(&lst->sem);
	return ret;
}

/* as above but will never return anything that
 * is in use.
 */
int ncr_key_item_get_write( struct key_item_st** st, 
	struct list_sem_st* lst, ncr_key_t desc)
{
struct key_item_st* item;
int ret;

	*st = NULL;

	down(&lst->sem);
	list_for_each_entry(item, &lst->list, list) {
		if (item->desc == desc) {
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
			goto exit;
		}
	}

	err();
	ret = -EINVAL;

exit:
	up(&lst->sem);
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

int ncr_key_init(struct list_sem_st* lst, void __user* arg)
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

	down(&lst->sem);

	key->desc = _ncr_key_get_new_desc(lst);
	key->uid = current_euid();
	key->pid = task_pid_nr(current);

	list_add(&key->list, &lst->list);
	
	desc = key->desc;
	up(&lst->sem);

	ret = copy_to_user(arg, &desc, sizeof(desc));
	if (unlikely(ret)) {
		down(&lst->sem);
		_ncr_key_unlink_item(key);
		up(&lst->sem);
		return -EFAULT;
	}
	return ret;

err_limits:
	ncr_limits_remove(current_euid(), task_pid_nr(current), LIMIT_TYPE_KEY);
	return ret;
}


int ncr_key_deinit(struct list_sem_st* lst, void __user* arg)
{
	ncr_key_t desc;
	struct key_item_st * item, *tmp;

	if (unlikely(copy_from_user(&desc, arg, sizeof(desc)))) {
		err();
		return -EFAULT;
	}

	down(&lst->sem);
	
	list_for_each_entry_safe(item, tmp, &lst->list, list) {
		if(item->desc == desc) {
			_ncr_key_unlink_item(item);
			break;
		}
	}
	
	up(&lst->sem);

	return 0;
}

/* "exports" a key to a data item. If the key is not exportable
 * to userspace then the data item will also not be.
 */
int ncr_key_export(struct list_sem_st* key_lst, void __user* arg)
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

	ret = ncr_key_item_get_read( &item, key_lst, data.key);
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
int ncr_key_import(struct list_sem_st* key_lst, void __user* arg)
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

	ret = ncr_key_item_get_write( &item, key_lst, data.key);
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
int ncr_key_generate(struct list_sem_st* lst, void __user* arg)
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

int ncr_key_info(struct list_sem_st* lst, void __user* arg)
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

int ncr_key_generate_pair(struct list_sem_st* lst, void __user* arg)
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
int ncr_key_derive(struct list_sem_st* key_lst, void __user* arg)
{
struct ncr_key_derivation_params_st data;
int ret;
struct key_item_st* key = NULL;
struct key_item_st* newkey = NULL;

	if (unlikely(copy_from_user(&data, arg, sizeof(data)))) {
		err();
		return -EFAULT;
	}

	ret = ncr_key_item_get_read( &key, key_lst, data.key);
	if (ret < 0) {
		err();
		return ret;
	}

	ret = ncr_key_item_get_write( &newkey, key_lst, data.newkey);
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

