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
#include "cryptodev.h"
#include "ncr.h"
#include "ncr_int.h"

void ncr_sessions_list_deinit(struct list_sem_st* lst)
{
	if(lst) {
		struct session_item_st * item, *tmp;

		down(&lst->sem);
		
		list_for_each_entry_safe(item, tmp, &lst->list, list) {
			list_del(&item->list);
			_ncr_sessions_item_put( item); /* decrement ref count */
		}
		up(&lst->sem);

	}
}

/* must be called with data semaphore down
 */
static ncr_session_t _ncr_sessions_get_new_desc( struct list_sem_st* lst)
{
struct session_item_st* item;
int mx = 0;

	list_for_each_entry(item, &lst->list, list) {
		mx = max(mx, item->desc);
	}
	mx++;

	return mx;
}

/* returns the data item corresponding to desc */
struct session_item_st* ncr_sessions_item_get( struct list_sem_st* lst, ncr_session_t desc)
{
struct session_item_st* item;

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

void _ncr_sessions_item_put( struct session_item_st* item)
{
	if (atomic_dec_and_test(&item->refcnt)) {
			kfree(item);
	}
}

struct session_item_st* ncr_session_new(struct list_sem_st* lst)
{
	struct session_item_st* sess;

	sess = kmalloc(sizeof(*sess), GFP_KERNEL);
	if (sess == NULL) {
		err();
		return NULL;
	}

	memset(sess, 0, sizeof(*sess));

	atomic_set(&sess->refcnt, 1);

	down(&lst->sem);

	sess->desc = _ncr_sessions_get_new_desc(lst);
	list_add(&sess->list, &lst->list);
	
	up(&lst->sem);

	return sess;
}

void ncr_session_deinit(struct list_sem_st* lst, ncr_session_t desc)
{
	struct session_item_st * item, *tmp;

	down(&lst->sem);
	
	list_for_each_entry_safe(item, tmp, &lst->list, list) {
		if(item->desc == desc) {
			list_del(&item->list);
			_ncr_sessions_item_put( item); /* decrement ref count */
			break;
		}
	}
	
	up(&lst->sem);

	return;
}
