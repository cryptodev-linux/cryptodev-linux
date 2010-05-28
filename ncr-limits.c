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

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/random.h>
#include "cryptodev.h"
#include <asm/atomic.h>
#include <linux/version.h>
#include <linux/file.h>
#include <linux/cred.h>
#include "ncr.h"
#include "ncr_int.h"

/* arbitrary now */
unsigned int max_per_user[] = {
	[LIMIT_TYPE_KEY] = 128,
	[LIMIT_TYPE_DATA] = 128,
};

unsigned int max_per_process[] = {
	[LIMIT_TYPE_KEY] = 64,
	[LIMIT_TYPE_DATA] = 64,
};

struct limit_user_item_st {
	struct list_head list;
	uid_t uid;
	limits_type_t type;
	atomic_t cnt;
};

struct limit_process_item_st {
	struct list_head list;
	struct pid * pid;
	limits_type_t type;
	atomic_t cnt;
};

struct limit_st {
	struct list_sem_st users;
	struct list_sem_st processes;
};

static struct limit_st limits;

void ncr_limits_init(void)
{
	init_MUTEX(&limits.users.sem);
	INIT_LIST_HEAD(&limits.users.list);

	init_MUTEX(&limits.processes.sem);
	INIT_LIST_HEAD(&limits.processes.list);
}

int ncr_limits_add_and_check(struct file *filp, limits_type_t type)
{
struct limit_process_item_st* pitem;
struct limit_user_item_st* uitem;
uid_t uid;
int add = 1;

/* FIXME: is this uid ok?
 */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,27)
	uid = filp->f_uid;
#else
	uid = filp->f_cred->fsuid;
#endif

	down(&limits.users.sem);
	list_for_each_entry(uitem, &limits.users.list, list) {
		if (uitem->uid == uid && uitem->type == type) {
			add = 0;
printk("user: %d max: %d, count: %d\n", (int)uid, max_per_user[type], atomic_read(&uitem->cnt));
			if (atomic_add_unless(&uitem->cnt, 1, max_per_user[type])==0) {
				err();
				up(&limits.users.sem);
				return -EPERM;
			}
		}
	}

	if (add) {
		uitem = kmalloc( sizeof(*uitem), GFP_KERNEL);
		if (uitem == NULL) {
			err();
			return -ENOMEM;
		}
		uitem->uid = uid;
		uitem->type = type;
		atomic_set(&uitem->cnt, 1);

		list_add(&uitem->list, &limits.users.list);
	}
	up(&limits.users.sem);

	add = 1;
	/* check process limits */
	down(&limits.processes.sem);
	list_for_each_entry(pitem, &limits.processes.list, list) {
		if (pitem->pid == filp->f_owner.pid && pitem->type == type) {
			add = 0;
			if (atomic_add_unless(&pitem->cnt, 1, max_per_process[type])==0) {
				err();
				up(&limits.processes.sem);
				return -EPERM;
			}
		}
	}
	

	if (add) {
		pitem = kmalloc(sizeof(*pitem), GFP_KERNEL);
		if (uitem == NULL) {
			err();
			return -ENOMEM;
		}
		pitem->pid = filp->f_owner.pid;
		pitem->type = type;
		atomic_set(&pitem->cnt, 1);

		list_add(&pitem->list, &limits.processes.list);
	}
	up(&limits.processes.sem);

	return 0;
}

void ncr_limits_remove(struct file *filp, limits_type_t type)
{
struct limit_process_item_st* pitem;
struct limit_user_item_st* uitem;
uid_t uid;

/* FIXME: is this uid ok?
 */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,27)
	uid = filp->f_uid;
#else
	uid = filp->f_cred->fsuid;
#endif

	down(&limits.users.sem);
	list_for_each_entry(uitem, &limits.users.list, list) {
		if (uitem->uid == uid && uitem->type == type) {
			atomic_dec(&uitem->cnt);
		}
	}
	up(&limits.users.sem);

	/* check process limits */
	down(&limits.processes.sem);
	list_for_each_entry(pitem, &limits.processes.list, list) {
		if (pitem->pid == filp->f_owner.pid && pitem->type == type) {
			atomic_dec(&pitem->cnt);
		}
	}
		up(&limits.processes.sem);

	return;
}
