/*
 * New driver for /dev/crypto device (aka CryptoDev)

 * Copyright (c) 2009,2010 Nikos Mavrogiannopoulos <nmav@gnutls.org>
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
#include "cryptodev.h"
#include <asm/uaccess.h>
#include <asm/ioctl.h>
#include <linux/scatterlist.h>
#include "ncr.h"
#include "ncr_int.h"



void* ncr_init_lists(void)
{
	struct ncr_lists *lst;
	int ret;

	lst = kmalloc(sizeof(*lst), GFP_KERNEL);
	if(!lst)
		return NULL;

	memset(lst, 0, sizeof(*lst));

	init_MUTEX(&lst->data_sem);
	INIT_LIST_HEAD(&lst->data_list);

	return lst;
}

void ncr_deinit_lists(struct ncr_lists *lst)
{
	if(lst) {
		//data_clear_all(list->data);
		kfree(lst);
	}
	
}

/* must be called with data semaphore down
 */
static ncr_data_t _ncr_data_get_new_desc( struct ncr_lists* lst)
{
struct data_item* item;
int mx = 0;

	list_for_each(item, &lst->data_list) {
		mx = max(mx, item->desc);
	}
	mx++;

	return mx;
}

void* data_alloc(unsigned int uid, size_t size)
{
	/* FIXME: implement a maximum memory limit per user */
	if (size > 64*1024) {
		return NULL;
	}
	return kmalloc(GPF_KERNEL, size);
}

int ncr_data_new(unsigned int uid, struct ncr_lists* lst, void __user* arg)
{
	struct ncr_data_init_st init;
	struct data_item* data;
	
	copy_from_user( &init, arg, sizeof(init));

	data = kmalloc(GPF_KERNEL, sizeof(*data));
	if (data == NULL) {
		return -ENOMEM;
	}

	memset(data, 0, sizeof(*data));
	init_MUTEX(&data->sem);

	data->flags = init.flags;

	data->data = data_alloc(uid, init.max_data_size);
	if (data->data == NULL) {
		kfree(data);
		return -ENOMEM;
	}
	data->max_data_size = init.max_data_size;

	down(lst->data_sem);

	data->desc = _ncr_data_get_new_desc(lst);

	list_add(data, &list->data_list);
	
	up(lst->data_sem);

	init.desc = data->desc;
	
}

int
ncr_ioctl(unsigned int uid, struct ncr_lists* lst,
		unsigned int cmd, unsigned long arg)
{

	if (unlikely(!lst))
		BUG();

	switch (cmd) {
		case NCRIO_DATA_INIT:
			return ncr_data_new(uid, lst, arg);
		case NCRIO_DATA_GET:
		case NCRIO_DATA_SET:
		case NCRIO_DATA_DEINIT:
		default:
			return -EINVAL;
	}
}



