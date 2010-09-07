/*
 * New driver for /dev/ncr device (aka NCR)

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

#include <linux/hash.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/random.h>
#include <asm/atomic.h>
#include <linux/version.h>
#include <linux/file.h>
#include <linux/cred.h>
#include "ncr.h"
#include "ncr-int.h"

/* arbitrary now */
static unsigned int max_per_user[] = {
	[LIMIT_TYPE_KEY] = 128,
};

static unsigned int max_per_process[] = {
	[LIMIT_TYPE_KEY] = 64,
};

struct limit_user_item_st {
	struct hlist_node hlist;
	uid_t uid;
	atomic_t cnt[NUM_LIMIT_TYPES];
};

struct limit_process_item_st {
	struct hlist_node hlist;
	pid_t pid;
	atomic_t cnt[NUM_LIMIT_TYPES];
};

static struct mutex user_limit_mutex;
#define USER_LIMIT_HASH_BITS 7
#define USER_LIMIT_TABLE_SIZE (1 << USER_LIMIT_HASH_BITS)
static struct hlist_head user_limit_table[USER_LIMIT_TABLE_SIZE];

static struct hlist_head *user_limit_hash(uid_t uid)
{
	return &user_limit_table[hash_long(uid, USER_LIMIT_HASH_BITS)];
}

static struct mutex process_limit_mutex;
#define PROCESS_LIMIT_HASH_BITS 9
#define PROCESS_LIMIT_TABLE_SIZE (1 << PROCESS_LIMIT_HASH_BITS)
static struct hlist_head process_limit_table[PROCESS_LIMIT_TABLE_SIZE];

static struct hlist_head *process_limit_hash(pid_t pid)
{
	return &process_limit_table[hash_long(pid, PROCESS_LIMIT_HASH_BITS)];
}

void ncr_limits_init(void)
{
	size_t i;

	mutex_init(&user_limit_mutex);
	for (i = 0; i < USER_LIMIT_TABLE_SIZE; i++)
		INIT_HLIST_HEAD(&user_limit_table[i]);

	mutex_init(&process_limit_mutex);
	for (i = 0; i < PROCESS_LIMIT_TABLE_SIZE; i++)
		INIT_HLIST_HEAD(&process_limit_table[i]);
}

void ncr_limits_deinit(void)
{
	struct limit_process_item_st *pitem;
	struct limit_user_item_st *uitem;
	struct hlist_node *pos, *tmp;
	size_t i;

	mutex_lock(&user_limit_mutex);
	for (i = 0; i < USER_LIMIT_TABLE_SIZE; i++) {
		hlist_for_each_entry_safe(uitem, pos, tmp, &user_limit_table[i],
					  hlist) {
			hlist_del(&uitem->hlist);
			kfree(uitem);
		}
	}
	mutex_unlock(&user_limit_mutex);

	mutex_lock(&process_limit_mutex);
	for (i = 0; i < PROCESS_LIMIT_TABLE_SIZE; i++) {
		hlist_for_each_entry_safe(pitem, pos, tmp,
					  &process_limit_table[i], hlist) {
			hlist_del(&pitem->hlist);
			kfree(pitem);
		}
	}
	mutex_unlock(&process_limit_mutex);

}

int ncr_limits_add_and_check(uid_t uid, pid_t pid, limits_type_t type)
{
	struct limit_process_item_st *pitem;
	struct limit_user_item_st *uitem;
	struct hlist_head *user_head, *process_head;
	struct hlist_node *pos;
	int add = 1;
	int ret;
	BUG_ON(type >= NUM_LIMIT_TYPES);

	user_head = user_limit_hash(uid);
	mutex_lock(&user_limit_mutex);
	hlist_for_each_entry(uitem, pos, user_head, hlist) {
		if (uitem->uid == uid) {
			add = 0;

			if (atomic_add_unless
			    (&uitem->cnt[type], 1, max_per_user[type]) == 0) {
				err();
				mutex_unlock(&user_limit_mutex);
				return -EPERM;
			}
			break;
		}
	}

	if (add) {
		size_t i;

		uitem = kmalloc(sizeof(*uitem), GFP_KERNEL);
		if (uitem == NULL) {
			err();
			mutex_unlock(&user_limit_mutex);
			return -ENOMEM;
		}
		uitem->uid = uid;
		for (i = 0; i < NUM_LIMIT_TYPES; i++)
			atomic_set(&uitem->cnt[i], 0);
		atomic_set(&uitem->cnt[type], 1);

		hlist_add_head(&uitem->hlist, user_head);
	}
	mutex_unlock(&user_limit_mutex);

	add = 1;
	/* check process limits */
	process_head = process_limit_hash(uid);
	mutex_lock(&process_limit_mutex);
	hlist_for_each_entry(pitem, pos, process_head, hlist) {
		if (pitem->pid == pid) {
			add = 0;
			if (atomic_add_unless
			    (&pitem->cnt[type], 1,
			     max_per_process[type]) == 0) {
				err();
				mutex_unlock(&process_limit_mutex);

				ret = -EPERM;
				goto restore_user;
			}
			break;
		}
	}

	if (add) {
		size_t i;

		pitem = kmalloc(sizeof(*pitem), GFP_KERNEL);
		if (pitem == NULL) {
			err();
			mutex_unlock(&process_limit_mutex);
			ret = -ENOMEM;
			goto restore_user;
		}
		pitem->pid = pid;
		for (i = 0; i < NUM_LIMIT_TYPES; i++)
			atomic_set(&pitem->cnt[i], 0);
		atomic_set(&pitem->cnt[type], 1);

		hlist_add_head(&pitem->hlist, process_head);
	}
	mutex_unlock(&process_limit_mutex);

	return 0;

restore_user:
	mutex_lock(&user_limit_mutex);
	hlist_for_each_entry(uitem, pos, user_head, hlist) {
		if (uitem->uid == uid) {
			atomic_dec(&uitem->cnt[type]);
			break;
		}
	}
	mutex_unlock(&user_limit_mutex);
	return ret;
}

void ncr_limits_remove(uid_t uid, pid_t pid, limits_type_t type)
{
	struct limit_process_item_st *pitem;
	struct limit_user_item_st *uitem;
	struct hlist_head *hhead;
	struct hlist_node *pos;

	BUG_ON(type >= NUM_LIMIT_TYPES);
	hhead = user_limit_hash(uid);
	mutex_lock(&user_limit_mutex);
	hlist_for_each_entry(uitem, pos, hhead, hlist) {
		if (uitem->uid == uid) {
			atomic_dec(&uitem->cnt[type]);
			break;
		}
	}
	mutex_unlock(&user_limit_mutex);

	/* check process limits */
	hhead = process_limit_hash(uid);
	mutex_lock(&process_limit_mutex);
	hlist_for_each_entry(pitem, pos, hhead, hlist) {
		if (pitem->pid == pid) {
			atomic_dec(&pitem->cnt[type]);
			break;
		}
	}
	mutex_unlock(&process_limit_mutex);

	return;
}
