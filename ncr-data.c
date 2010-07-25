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

#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include "cryptodev.h"
#include <asm/uaccess.h>
#include <asm/ioctl.h>
#include <linux/scatterlist.h>
#include "ncr.h"
#include "ncr-int.h"

/* must be called with data semaphore down */
static void _ncr_data_unlink_item(struct data_item_st *item)
{
	list_del(&item->list);
	_ncr_data_item_put( item); /* decrement ref count */
}

void ncr_data_list_deinit(struct list_sem_st* lst)
{
	if(lst) {
		struct data_item_st * item, *tmp;

		down(&lst->sem);
		
		list_for_each_entry_safe(item, tmp, &lst->list, list) {
			_ncr_data_unlink_item(item);
		}
		up(&lst->sem);

	}
}

/* must be called with data semaphore down
 */
static ncr_data_t _ncr_data_get_new_desc( struct list_sem_st* lst)
{
struct data_item_st* item;
int mx = 1;

	list_for_each_entry(item, &lst->list, list) {
		mx = max(mx, item->desc);
	}
	mx++;

	return mx;
}

/* returns the data item corresponding to desc */
struct data_item_st* ncr_data_item_get( struct list_sem_st* lst, ncr_data_t desc)
{
struct data_item_st* item;

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

static void* data_alloc(size_t size)
{
	/* FIXME: enforce a maximum memory limit per process and per user */
	/* ncr_data_set() relies this function enforcing a reasonable upper
	   limit. */
	if (size > 64*1024) {
		err();
		return NULL;
	}
	return kmalloc(size, GFP_KERNEL);
}

void _ncr_data_item_put( struct data_item_st* item)
{
	if (atomic_dec_and_test(&item->refcnt)) {
			ncr_limits_remove(item->uid, item->pid, LIMIT_TYPE_DATA);
			kfree(item->data);
			kfree(item);
	}
}

int ncr_data_init(struct list_sem_st* lst, void __user* arg)
{
	struct ncr_data_init_st init;
	struct data_item_st* data;
	int ret;

	ret = ncr_limits_add_and_check(current_euid(), task_pid_nr(current), LIMIT_TYPE_DATA);
	if (ret < 0) {
		err();
		return ret;
	}

	if (unlikely(copy_from_user(&init, arg, sizeof(init)))) {
		err();
		ret = -EFAULT;
		goto err_limits;
	}

	data = kmalloc(sizeof(*data), GFP_KERNEL);
	if (data == NULL) {
		err();
		ret = -ENOMEM;
		goto err_limits;
	}

	memset(data, 0, sizeof(*data));

	data->flags = init.flags;
	data->uid = current_euid();
	data->pid = task_pid_nr(current);

	atomic_set(&data->refcnt, 1);

	data->data = data_alloc(init.max_object_size);
	if (data->data == NULL) {
		err();
		ret = -ENOMEM;
		goto err_data;
	}
	data->max_data_size = init.max_object_size;
	
	sg_init_one(&data->sg, data->data, data->max_data_size);

	if (init.initial_data != NULL) {
		if (unlikely(copy_from_user(data->data, init.initial_data,
					    init.initial_data_size))) {
			err();
			_ncr_data_item_put(data);
			return -EFAULT;
		}
		data->data_size = init.initial_data_size;
	}

	down(&lst->sem);

	data->desc = _ncr_data_get_new_desc(lst);

	list_add(&data->list, &lst->list);
	
	up(&lst->sem);

	init.desc = data->desc;
	ret = copy_to_user(arg, &init, sizeof(init));
	if (unlikely(ret)) {
		down(&lst->sem);
		_ncr_data_unlink_item(data);
		up(&lst->sem);
		return -EFAULT;
	}
	return ret;

 err_data:
	kfree(data);
 err_limits:
	ncr_limits_remove(current_euid(), task_pid_nr(current),
			  LIMIT_TYPE_DATA);
	return ret;
}


int ncr_data_deinit(struct list_sem_st* lst, void __user* arg)
{
	ncr_data_t desc;
	struct data_item_st * item, *tmp;

	if (unlikely(copy_from_user(&desc, arg, sizeof(desc)))) {
		err();
		return -EFAULT;
	}
	down(&lst->sem);
	
	list_for_each_entry_safe(item, tmp, &lst->list, list) {
		if(item->desc == desc) {
			_ncr_data_unlink_item(item);
			break;
		}
	}
	
	up(&lst->sem);

	return 0;
}

int ncr_data_get(struct list_sem_st* lst, void __user* arg)
{
	struct ncr_data_st get;
	struct data_item_st * data;
	size_t len;
	int ret;
	
	if (unlikely(copy_from_user(&get, arg, sizeof(get)))) {
		err();
		return -EFAULT;
	}

	data = ncr_data_item_get( lst, get.desc);

	if (data == NULL) {
		err();
		return -EINVAL;
	}

	if (!(data->flags & NCR_DATA_FLAG_EXPORTABLE)) {
		err();
		ret = -EPERM;
		goto cleanup;
	}

	len = min(get.data_size, data->data_size);

	/* update length */
	get.data_size = len;
	
	ret = copy_to_user(arg, &get, sizeof(get));
	if (unlikely(ret)) {
		err();
		ret = -EFAULT;
	}

	if (ret == 0 && len > 0) {
		ret = copy_to_user(get.data, data->data, len);
		if (unlikely(ret)) {
			err();
			ret = -EFAULT;
		}
	}

cleanup:
	_ncr_data_item_put( data);

	return ret;
}

int ncr_data_set(struct list_sem_st* lst, void __user* arg)
{
	struct ncr_data_st get;
	struct data_item_st * data;
	int ret;
	
	if (unlikely(copy_from_user(&get, arg, sizeof(get)))) {
		err();
		return -EFAULT;
	}

	data = ncr_data_item_get( lst, get.desc);

	if (data == NULL) {
		err();
		return -EINVAL;
	}

	if ((get.data_size > data->max_data_size) ||
		(get.data == NULL && get.data_size != 0)) {
		err();
		ret = -EINVAL;
		goto cleanup;
	}

	if (get.data != NULL) {
		if (unlikely(copy_from_user(data->data, get.data,
					    get.data_size))) {
			err();
			ret = -EFAULT;
			goto cleanup;
		}
	}
	data->data_size = get.data_size;

	ret = 0;

cleanup:
	_ncr_data_item_put( data);

	return ret;
}
