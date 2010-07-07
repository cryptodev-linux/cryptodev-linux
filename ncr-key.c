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
#include <linux/random.h>
#include "cryptodev.h"
#include <asm/uaccess.h>
#include <asm/ioctl.h>
#include <linux/scatterlist.h>
#include "ncr.h"
#include "ncr_int.h"

static void ncr_key_clear(struct key_item_st* item);

void ncr_key_list_deinit(struct list_sem_st* lst)
{
	if(lst) {
		struct key_item_st * item, *tmp;

		down(&lst->sem);

		list_for_each_entry_safe(item, tmp, &lst->list, list) {
			list_del(&item->list);
			_ncr_key_item_put( item); /* decrement ref count */
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
struct key_item_st* ncr_key_item_get( struct list_sem_st* lst, ncr_key_t desc)
{
struct key_item_st* item;
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

void _ncr_key_item_put( struct key_item_st* item)
{
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
		return -ENOMEM;
	}

	memset(key, 0, sizeof(*key));

	atomic_set(&key->refcnt, 1);

	down(&lst->sem);

	key->desc = _ncr_key_get_new_desc(lst);
	key->uid = current_euid();
	key->pid = task_pid_nr(current);

	list_add(&key->list, &lst->list);
	
	up(&lst->sem);

	desc = key->desc;
	return copy_to_user(arg, &desc, sizeof(desc));
}


int ncr_key_deinit(struct list_sem_st* lst, void __user* arg)
{
	ncr_key_t desc;
	struct key_item_st * item, *tmp;
	int ret;

	ret = copy_from_user( &desc, arg, sizeof(desc));
	if (unlikely(ret)) {
		err();
		return ret;
	}

	down(&lst->sem);
	
	list_for_each_entry_safe(item, tmp, &lst->list, list) {
		if(item->desc == desc) {
			list_del(&item->list);
			_ncr_key_item_put( item); /* decrement ref count */
			break;
		}
	}
	
	up(&lst->sem);

	return 0;
}

/* "exports" a key to a data item. If the key is not exportable
 * to userspace then the data item will also not be.
 */
int ncr_key_export(struct list_sem_st* data_lst,
	struct list_sem_st* key_lst, void __user* arg)
{
struct ncr_key_data_st data;
struct key_item_st* item = NULL;
struct data_item_st* ditem = NULL;
int ret;

	ret = copy_from_user( &data, arg, sizeof(data));
	if (unlikely(ret)) {
		err();
		return ret;
	}

	item = ncr_key_item_get( key_lst, data.key);
	if (item == NULL) {
		err();
		return -EINVAL;
	}

	ditem = ncr_data_item_get( data_lst, data.data);
	if (ditem == NULL) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	switch (item->type) {
		case NCR_KEY_TYPE_SECRET:
			if (item->key.secret.size > ditem->max_data_size) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			/* found */
			ditem->flags = key_flags_to_data(item->flags);

			if (item->key.secret.size > 0) {
				memcpy(ditem->data, item->key.secret.data, item->key.secret.size);
			}
			ditem->data_size = item->key.secret.size;
			break;
		case NCR_KEY_TYPE_PUBLIC: /* FIXME: export in a blob -ASN.1? */
		case NCR_KEY_TYPE_PRIVATE: /* FIXME export in a blob -ASN.1? */
		default:
			err();
			ret = -EINVAL;
			goto fail;
	}

	_ncr_key_item_put( item);
	_ncr_data_item_put( ditem);

	return 0;

fail:
	if (item)
		_ncr_key_item_put(item);
	if (ditem)
		_ncr_data_item_put(ditem);
	return ret;
	
}

/* "imports" a key from a data item. If the key is not exportable
 * to userspace then the key item will also not be.
 */
int ncr_key_import(struct list_sem_st* data_lst,
	struct list_sem_st* key_lst, void __user* arg)
{
struct ncr_key_data_st data;
struct key_item_st* item = NULL;
struct data_item_st* ditem = NULL;
int ret;

	ret = copy_from_user( &data, arg, sizeof(data));
	if (unlikely(ret)) {
		err();
		return ret;
	}

	item = ncr_key_item_get( key_lst, data.key);
	if (item == NULL) {
		err();
		return -EINVAL;
	}

	ditem = ncr_data_item_get( data_lst, data.data);
	if (ditem == NULL) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	item->type = data.type;
	item->algorithm = data.algorithm;
	item->flags = data.flags;
	/* if data cannot be exported then the flags above
	 * should be overriden */
	if (!(ditem->flags & NCR_DATA_FLAG_EXPORTABLE)) {
		item->flags &= ~NCR_KEY_FLAG_EXPORTABLE;
	}

	switch(item->type) {
		case NCR_KEY_TYPE_SECRET:

			if (data.key_id_size > MAX_KEY_ID_SIZE) {
				err();
				ret = -EINVAL;
				goto fail;
			}
			item->key_id_size = data.key_id_size;
			if (data.key_id_size > 0)
				memcpy(item->key_id, data.key_id, data.key_id_size);


			if (ditem->data_size > NCR_CIPHER_MAX_KEY_LEN) {
				err();
				ret = -EINVAL;
				goto fail;
			}
			
			memcpy(item->key.secret.data, ditem->data, ditem->data_size);
			item->key.secret.size = ditem->data_size;
			break;
		case NCR_KEY_TYPE_PRIVATE: /* FIXME */
		case NCR_KEY_TYPE_PUBLIC: /* FIXME */
		default:
			err();
			ret = -EINVAL;
			goto fail;
	}

	_ncr_key_item_put( item);
	_ncr_data_item_put( ditem);

	return 0;

fail:
	if (item)
		_ncr_key_item_put(item);
	if (ditem)
		_ncr_data_item_put(ditem);
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
}

/* Generate a secret key
 */
int ncr_key_generate(struct list_sem_st* lst, void __user* arg)
{
struct ncr_key_generate_st gen;
struct key_item_st* item = NULL;
int ret;
size_t size;

	ret = copy_from_user( &gen, arg, sizeof(gen));
	if (unlikely(ret)) {
		err();
		return ret;
	}

	item = ncr_key_item_get( lst, gen.desc);
	if (item == NULL) {
		err();
		return -EINVAL;
	}

	ncr_key_clear(item);

	/* we generate only secret keys */
	item->flags = gen.params.keyflags;
	item->type = ncr_algorithm_to_key_type(gen.params.algorithm);
	if (item->type == NCR_KEY_TYPE_SECRET) {
		item->algorithm = /* arbitrary */ NCR_ALG_AES_CBC;

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
	
	_ncr_key_item_put( item);

	return 0;

fail:
	if (item)
		_ncr_key_item_put(item);
	return ret;
}

int ncr_key_info(struct list_sem_st* lst, void __user* arg)
{
struct ncr_key_info_st info;
struct key_item_st* item = NULL;
int ret;

	ret = copy_from_user( &info, arg, sizeof(info));
	if (unlikely(ret)) {
		err();
		return ret;
	}

	item = ncr_key_item_get( lst, info.key);
	if (item == NULL) {
		err();
		return -EINVAL;
	}

	info.flags = item->flags;
	info.type = item->type;
	info.algorithm = item->algorithm;

	_ncr_key_item_put( item);

	return 0;
}

int ncr_key_generate_pair(struct list_sem_st* lst, void __user* arg)
{
struct ncr_key_generate_st gen;
struct key_item_st* private = NULL;
struct key_item_st* public = NULL;
int ret;

	ret = copy_from_user( &gen, arg, sizeof(gen));
	if (unlikely(ret)) {
		err();
		return ret;
	}

	private = ncr_key_item_get( lst, gen.desc);
	if (private == NULL) {
		err();
		return -EINVAL;
	}

	public = ncr_key_item_get( lst, gen.desc2);
	if (public == NULL) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	ncr_key_clear(public);
	ncr_key_clear(private);

	/* we generate only secret keys */
	private->flags = public->flags = gen.params.keyflags;
	public->type = ncr_algorithm_to_key_type(gen.params.algorithm);
	private->type = NCR_KEY_TYPE_PRIVATE;
	private->algorithm = public->algorithm = gen.params.algorithm;
	public->flags |= (NCR_KEY_FLAG_EXPORTABLE|NCR_KEY_FLAG_WRAPPABLE);
	
	if (public->type == NCR_KEY_TYPE_PUBLIC) {
		ret = ncr_pk_generate(gen.params.algorithm, &gen.params, private, public);

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
	if (public)
		_ncr_key_item_put(public);
	if (private)
		_ncr_key_item_put(private);
	return ret;
}

int ncr_key_derive(struct list_sem_st* lst, void __user* arg)
{
	return -EINVAL;
}

int ncr_key_get_public(struct list_sem_st* lst, void __user* arg)
{
	return -EINVAL;
}

