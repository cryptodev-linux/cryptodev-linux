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
#include "ncr_int.h"

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
			if (item->type == NCR_DATA_KERNEL)
				kfree(item->data.kernel);
			else if (item->type == NCR_DATA_USER)
				ncr_data_item_put_sg(item); /* just in case */
			kfree(item);
	}
}

int ncr_data_item_get_sg( struct data_item_st* item, struct scatterlist** sg, 
	unsigned int *sg_cnt, size_t *data_size, size_t* max_data_size, unsigned int data_flags, int write)
{
	if (item->type == NCR_DATA_KERNEL) {
		item->flags = data_flags;

		sg_init_one(item->_sg, item->data.kernel, item->max_data_size);

		if (data_size) *data_size = item->data_size;
		if (max_data_size) *max_data_size = item->max_data_size;
		*sg_cnt = 1;
		*sg = item->_sg;
		
	} else if (item->type == NCR_DATA_USER) {
		int ret;
		size_t pagecount = PAGECOUNT(item->data.user.ptr, item->data_size);
		
		if (atomic_add_unless(&item->data.user.pg_used, 1, 1) == 0) {
			err();
			return -EBUSY;
		}
		
		if (!(data_flags & NCR_DATA_FLAG_EXPORTABLE)) {
			err();
			return -EPERM;
		}
		
		if (pagecount > MAX_DATA_PAGES) {
			err();
			return -EOVERFLOW;
		}

		ret = __get_userbuf(item->data.user.ptr, item->data_size, write,
			pagecount, item->data.user.pg, item->_sg);
		if (ret < 0) {
			err();
			return ret;
		}

		if (max_data_size) *max_data_size = item->data_size;
		if (data_size) *data_size = item->data_size;
		*sg = item->_sg;
		*sg_cnt = item->data.user.pg_cnt = pagecount;
	} else {
		err();
		return -EINVAL;
	}

	return 0;
}

void ncr_data_item_put_sg( struct data_item_st* item)
{
	if (item->type == NCR_DATA_USER && atomic_read(&item->data.user.pg_used) > 0) {
		if (item->data.user.pg_cnt > 0) {
			release_user_pages(item->data.user.pg, item->data.user.pg_cnt);
			item->data.user.pg_cnt = 0;
		}
		atomic_dec(&item->data.user.pg_used);
	}

	return;
}

int ncr_data_item_setd( struct data_item_st* item, const void* data, size_t data_size, unsigned int data_flags)
{
struct scatterlist* sg;
size_t sg_max_size;
unsigned int sg_cnt;
int ret;

	ret = ncr_data_item_get_sg(item, &sg, &sg_cnt, NULL, &sg_max_size, data_flags, 1);
	if (ret < 0) {
		err();
		return ret;
	}
	
	if (data_size > sg_max_size) {
		err();
		ret = -EOVERFLOW;
		goto fail;
	}

	ret = sg_copy_from_buffer(sg, sg_cnt, (void*)data, data_size);
	if (ret != data_size) {
		err();
		ret = -EINVAL;
		goto fail;
	}
	item->data_size = data_size;

	ret = 0;
fail:
	ncr_data_item_put_sg(item);
	return ret;
}

int ncr_data_item_getd( struct data_item_st* item, void* data, size_t data_size, unsigned int data_flags)
{
struct scatterlist* sg;
size_t sg_size;
unsigned int sg_cnt;
int ret;

	ret = ncr_data_item_get_sg(item, &sg, &sg_cnt, &sg_size, NULL, data_flags, 0);
	if (ret < 0) {
		err();
		return ret;
	}

	if (data_size < sg_size) {
		err();
		ret = -EOVERFLOW;
		goto fail;
	}
	
	ret = sg_copy_to_buffer(sg, sg_cnt, data, data_size);
	if (ret != data_size) {
		err();
		ret = -EINVAL;
		goto fail;
	}

	ret = 0;
fail:
	ncr_data_item_put_sg(item);
	return ret;
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

	data->type = init.type;

	if (init.type == NCR_DATA_KERNEL) {
		data->data.kernel = data_alloc(init.max_object_size);
		if (data->data.kernel == NULL) {
			err();
			ret = -ENOMEM;
			goto err_data;
		}
		data->max_data_size = init.max_object_size;

		if (init.initial_data != NULL) {
			if (unlikely(copy_from_user(data->data.kernel, init.initial_data,
						    init.initial_data_size))) {
				err();
				_ncr_data_item_put(data);
				return -EFAULT;
			}
			data->data_size = init.initial_data_size;
		}
	} else if (init.type == NCR_DATA_USER) {
		data->data.user.ptr = init.initial_data;
		data->max_data_size = data->data_size = init.initial_data_size;
		atomic_set(&data->data.user.pg_used, 0);
	} else {
		err();
		goto err_data;
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

	if (data->type == NCR_DATA_USER) {
		err();
		ret = -EINVAL;
		goto cleanup;
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
		ret = copy_to_user(get.data, data->data.kernel, len);
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

	if (data->type == NCR_DATA_USER) {
		err();
		ret = -EINVAL;
		goto cleanup;
	}

	if ((get.data_size > data->max_data_size) ||
		(get.data == NULL && get.data_size != 0)) {
		err();
		ret = -EINVAL;
		goto cleanup;
	}

	if (get.data != NULL) {
		if (unlikely(copy_from_user(data->data.kernel, get.data,
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
