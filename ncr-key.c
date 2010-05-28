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
#include <linux/random.h>
#include "cryptodev.h"
#include <asm/uaccess.h>
#include <asm/ioctl.h>
#include <linux/scatterlist.h>
#include "ncr.h"
#include "ncr_int.h"

#define err() printk(KERN_DEBUG"ncr: %s: %d\n", __func__, __LINE__)

static void _ncr_key_item_put( struct key_item* item);

void ncr_key_list_deinit(struct list_sem_st* lst)
{
	if(lst) {
		struct key_item * item, *tmp;

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
struct key_item* item;
int mx = 0;

	list_for_each_entry(item, &lst->list, list) {
		mx = max(mx, item->desc);
	}
	mx++;

	return mx;
}

/* returns the data item corresponding to desc */
static struct key_item* ncr_key_item_get( struct list_sem_st* lst, ncr_key_t desc)
{
struct key_item* item;

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

static void _ncr_key_item_put( struct key_item* item)
{
	if (atomic_dec_and_test(&item->refcnt)) {
			ncr_limits_remove(item->filp, LIMIT_TYPE_KEY);
			kfree(item);
	}
}

int ncr_key_init(struct file *filp, struct list_sem_st* lst, void __user* arg)
{
	ncr_key_t desc;
	struct key_item* key;
	int ret;

	ret = ncr_limits_add_and_check(filp, LIMIT_TYPE_KEY);
	if (ret < 0) {
		err();
		return ret;
	}

	copy_from_user( &desc, arg, sizeof(desc));

	key = kmalloc(sizeof(*key), GFP_KERNEL);
	if (key == NULL) {
		err();
		return -ENOMEM;
	}

	memset(key, 0, sizeof(*key));

	atomic_set(&key->refcnt, 1);

	down(&lst->sem);

	key->desc = _ncr_key_get_new_desc(lst);
	key->filp = filp;

	list_add(&key->list, &lst->list);
	
	up(&lst->sem);

	desc = key->desc;
	copy_to_user(arg, &desc, sizeof(desc));

	return 0;
}


int ncr_key_deinit(struct list_sem_st* lst, void __user* arg)
{
	ncr_key_t desc;
	struct key_item * item, *tmp;

	copy_from_user( &desc, arg, sizeof(desc));

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
