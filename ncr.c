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

#include <linux/compat.h>
#include <linux/crypto.h>
#include <linux/ioctl.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/random.h>
#include <linux/uaccess.h>
#include <linux/scatterlist.h>
#include <linux/cred.h>  
#include <linux/capability.h>
#include "ncr.h"
#include "ncr-int.h"
#include "utils.h"
#include <linux/workqueue.h>

/* This is the master wrapping key for storage of keys
 */
struct key_item_st master_key;

void* ncr_init_lists(void)
{
	struct ncr_lists *lst;

	lst = kmalloc(sizeof(*lst), GFP_KERNEL);
	if(!lst) {
		err();
		return NULL;
	}

	memset(lst, 0, sizeof(*lst));

	mutex_init(&lst->key_idr_mutex);
	idr_init(&lst->key_idr);

	mutex_init(&lst->session_idr_mutex);
	idr_init(&lst->session_idr);

	return lst;
}

void ncr_deinit_lists(struct ncr_lists *lst)
{
	if(lst) {
		ncr_key_list_deinit(lst);
		ncr_sessions_list_deinit(lst);
		kfree(lst);
	}
}

void ncr_master_key_reset(void)
{
	memset(&master_key, 0, sizeof(master_key));
}

static int ncr_master_key_set(void __user *arg)
{
struct ncr_master_key_st st;

	if (current_euid() != 0 && !capable(CAP_SYS_ADMIN)) {
		err();
		return -EPERM;
	}

	if (unlikely(copy_from_user(&st, arg, sizeof(st)))) {
		err();
		return -EFAULT;
	}

	if (st.key_size > sizeof(master_key.key.secret.data)) {
		err();
		return -EINVAL;
	}

	if (st.key_size != 16 && st.key_size != 24 && st.key_size != 32) {
		dprintk(0, KERN_DEBUG, "Master key size must be 16,24 or 32.\n");
		return -EINVAL;
	}

	if (master_key.type != NCR_KEY_TYPE_INVALID) {
		dprintk(0, KERN_DEBUG, "Master key was previously initialized.\n");
	}

	if (unlikely(copy_from_user(master_key.key.secret.data, st.key, st.key_size))) {
		err();
		return -EFAULT;
	}

	dprintk(0, KERN_INFO, "Initializing master key.\n");

	master_key.type = NCR_KEY_TYPE_SECRET;
	master_key.key.secret.size = st.key_size;

	return 0;
}

int
ncr_ioctl(struct ncr_lists *lst, unsigned int cmd, unsigned long arg_)
{
	void __user *arg = (void __user *)arg_;
	struct nlattr *tb[NCR_ATTR_MAX + 1];
	void *attr_buf;
	int ret;

	if (unlikely(!lst))
		BUG();

	switch (cmd) {
#define CASE_NO_OUTPUT(LABEL, STRUCT, FUNCTION)				\
	case (LABEL): {							\
		struct STRUCT data;					\
									\
		attr_buf = NCR_GET_INPUT_ARGS_NO_OUTPUT(&data, tb, arg); \
		if (IS_ERR(attr_buf)) {					\
			err();						\
			return PTR_ERR(attr_buf);			\
		}							\
		ret = (FUNCTION)(lst, &data, tb);			\
		break;							\
	}

	case NCRIO_KEY_INIT:
		return ncr_key_init(lst);
	CASE_NO_OUTPUT(NCRIO_KEY_GENERATE, ncr_key_generate, ncr_key_generate);
	CASE_NO_OUTPUT(NCRIO_KEY_GENERATE_PAIR, ncr_key_generate_pair,
		       ncr_key_generate_pair);
	CASE_NO_OUTPUT(NCRIO_KEY_DERIVE, ncr_key_derive, ncr_key_derive);
	case NCRIO_KEY_GET_INFO: {
		struct ncr_key_get_info data;
		struct ncr_out out;

		attr_buf = NCR_GET_INPUT_ARGS(&data, tb, arg);
		if (IS_ERR(attr_buf)) {
			err();
			return PTR_ERR(attr_buf);
		}
		ret = NCR_OUT_INIT(&out, &data, arg);
		if (ret != 0) {
			err();
			break;
		}
		ret = ncr_key_get_info(lst, &out, &data, tb);
		ncr_out_free(&out);
		break;
	}
		case NCRIO_KEY_DEINIT:
			return ncr_key_deinit(lst, arg);
		case NCRIO_KEY_EXPORT:
			return ncr_key_export(lst, arg);
		case NCRIO_KEY_IMPORT:
			return ncr_key_import(lst, arg);
		case NCRIO_KEY_WRAP:
			return ncr_key_wrap(lst, arg);
		case NCRIO_KEY_UNWRAP:
			return ncr_key_unwrap(lst, arg);
		case NCRIO_KEY_STORAGE_WRAP:
			return ncr_key_storage_wrap(lst, arg);
		case NCRIO_KEY_STORAGE_UNWRAP:
			return ncr_key_storage_unwrap(lst, arg);
		case NCRIO_SESSION_INIT:
			return ncr_session_init(lst, arg);
		case NCRIO_SESSION_UPDATE:
			return ncr_session_update(lst, arg);
		case NCRIO_SESSION_FINAL:
			return ncr_session_final(lst, arg);
		case NCRIO_SESSION_ONCE:
			return ncr_session_once(lst, arg);

		case NCRIO_MASTER_KEY_SET:
			return ncr_master_key_set(arg);
		default:
			return -EINVAL;
#undef CASE_NO_OUTPUT
	}
	kfree(attr_buf);
	return ret;
}

#ifdef CONFIG_COMPAT
long
ncr_compat_ioctl(struct ncr_lists *lst, unsigned int cmd, unsigned long arg_)
{
	if (unlikely(!lst))
		BUG();

	switch (cmd) {
	case NCRIO_KEY_INIT:
	case NCRIO_KEY_GENERATE:
	case NCRIO_KEY_GENERATE_PAIR:
	case NCRIO_KEY_DERIVE:
	case NCRIO_KEY_GET_INFO:
		return ncr_ioctl(lst, cmd, arg_);
	default:
		return -EINVAL;
	}
}
#endif
