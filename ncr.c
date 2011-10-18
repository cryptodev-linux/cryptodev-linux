/*
 * New driver for /dev/ncr device (aka NCR)
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
#include <net/netlink.h>
#include "ncr.h"
#include "ncr-int.h"
#include "utils.h"
#include <linux/workqueue.h>

/* This is the master wrapping key for storage of keys
 */
struct key_item_st master_key;

void *ncr_init_lists(void)
{
	struct ncr_lists *lst;

	lst = kmalloc(sizeof(*lst), GFP_KERNEL);
	if (!lst) {
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
	if (lst) {
		ncr_key_list_deinit(lst);
		ncr_sessions_list_deinit(lst);
		kfree(lst);
	}
}

void ncr_master_key_reset(void)
{
	memset(&master_key, 0, sizeof(master_key));
}

static int ncr_master_key_set(const struct ncr_master_key_set *st,
			      struct nlattr *tb[])
{
	if (!capable(CAP_SYS_ADMIN)) {
		err();
		return -EPERM;
	}

	if (st->key_size > sizeof(master_key.key.secret.data)) {
		err();
		return -EINVAL;
	}

	if (st->key_size != 16 && st->key_size != 24 && st->key_size != 32) {
		dprintk(0, KERN_DEBUG,
			"Master key size must be 16,24 or 32.\n");
		return -EINVAL;
	}

	if (master_key.type != NCR_KEY_TYPE_INVALID) {
		dprintk(0, KERN_DEBUG,
			"Master key was previously initialized.\n");
	}

	if (unlikely(copy_from_user(master_key.key.secret.data, st->key,
				    st->key_size))) {
		err();
		return -EFAULT;
	}

	dprintk(0, KERN_INFO, "Initializing master key.\n");

	master_key.type = NCR_KEY_TYPE_SECRET;
	master_key.key.secret.size = st->key_size;

	return 0;
}

long ncr_ioctl(struct ncr_lists *lst, unsigned int cmd, unsigned long arg_)
{
	void __user *arg = (void __user *)arg_;
	struct nlattr *tb[NCR_ATTR_MAX + 1];
	void *attr_buf;
	int ret;

	if (unlikely(!lst))
		BUG();

	switch (cmd) {
#define CASE_(LABEL, STRUCT, FUNCTION, ARGS)				\
	case (LABEL): {							\
		struct STRUCT data;					\
									\
		attr_buf = NCR_GET_INPUT_ARGS_NO_OUTPUT(&data, tb, arg); \
		if (IS_ERR(attr_buf)) {					\
			err();						\
			return PTR_ERR(attr_buf);			\
		}							\
		ret = (FUNCTION)ARGS;					\
		break;							\
	}
#define CASE_NO_OUTPUT(LABEL, STRUCT, FUNCTION)				\
		CASE_(LABEL, STRUCT, FUNCTION, (lst, &data, tb))
#define CASE_NO_OUTPUT_COMPAT(LABEL, STRUCT, FUNCTION)			\
		CASE_(LABEL, STRUCT, FUNCTION, (lst, &data, tb, 0))

	case NCRIO_KEY_INIT:
		return ncr_key_init(lst);
	CASE_NO_OUTPUT(NCRIO_KEY_GENERATE, ncr_key_generate,
			       ncr_key_generate);
	CASE_NO_OUTPUT(NCRIO_KEY_GENERATE_PAIR, ncr_key_generate_pair,
			       ncr_key_generate_pair);
	CASE_NO_OUTPUT(NCRIO_KEY_DERIVE, ncr_key_derive,
			       ncr_key_derive);
	case NCRIO_KEY_GET_INFO:{
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
	CASE_NO_OUTPUT(NCRIO_KEY_EXPORT, ncr_key_export,
			       ncr_key_export);
	CASE_NO_OUTPUT(NCRIO_KEY_IMPORT, ncr_key_import,
			       ncr_key_import);
	case NCRIO_KEY_DEINIT:{
			ncr_key_t key;

			ret = get_user(key, (const ncr_key_t __user *)arg);
			if (unlikely(ret)) {
				err();
				return ret;
			}
			return ncr_key_deinit(lst, key);
		}
	CASE_NO_OUTPUT(NCRIO_KEY_WRAP, ncr_key_wrap, ncr_key_wrap);
	CASE_NO_OUTPUT(NCRIO_KEY_UNWRAP, ncr_key_unwrap,
			       ncr_key_unwrap);
	CASE_NO_OUTPUT(NCRIO_KEY_STORAGE_WRAP, ncr_key_storage_wrap,
			       ncr_key_storage_wrap);
	CASE_NO_OUTPUT(NCRIO_KEY_STORAGE_UNWRAP, ncr_key_storage_unwrap,
			       ncr_key_storage_unwrap);
	CASE_NO_OUTPUT(NCRIO_SESSION_INIT, ncr_session_init,
			       ncr_session_init);
	CASE_NO_OUTPUT_COMPAT(NCRIO_SESSION_UPDATE, ncr_session_update,
				      ncr_session_update);
	CASE_NO_OUTPUT_COMPAT(NCRIO_SESSION_FINAL, ncr_session_final,
				      ncr_session_final);
	CASE_NO_OUTPUT_COMPAT(NCRIO_SESSION_ONCE, ncr_session_once,
				      ncr_session_once);
	CASE_(NCRIO_MASTER_KEY_SET, ncr_master_key_set,
		      ncr_master_key_set, (&data, tb));
	default:
		return -EINVAL;
#undef CASE_
#undef CASE_NO_OUTPUT
#undef CASE_NO_OUTPUT_COMPAT
	}
	kfree(attr_buf);
	return ret;
}

#ifdef CONFIG_COMPAT
struct compat_ncr_key_export {
	__u32 input_size, output_size;
	ncr_key_t key;
	compat_uptr_t buffer;
	compat_int_t buffer_size;
	 __NL_ATTRIBUTES;
};
#define COMPAT_NCRIO_KEY_EXPORT _IOWR('c', 209, struct compat_ncr_key_export)

static void convert_ncr_key_export(struct ncr_key_export *new,
				   const struct compat_ncr_key_export *old)
{
	new->key = old->key;
	new->buffer = compat_ptr(old->buffer);
	new->buffer_size = old->buffer_size;
}

struct compat_ncr_key_import {
	__u32 input_size, output_size;
	ncr_key_t key;
	compat_uptr_t data;
	__u32 data_size;
	 __NL_ATTRIBUTES;
};
#define COMPAT_NCRIO_KEY_IMPORT _IOWR('c', 210, struct compat_ncr_key_import)

static void convert_ncr_key_import(struct ncr_key_import *new,
				   const struct compat_ncr_key_import *old)
{
	new->key = old->key;
	new->data = compat_ptr(old->data);
	new->data_size = old->data_size;
}

struct compat_ncr_key_wrap {
	__u32 input_size, output_size;
	ncr_key_t wrapping_key;
	ncr_key_t source_key;
	compat_uptr_t buffer;
	compat_int_t buffer_size;
	 __NL_ATTRIBUTES;
};
#define COMPAT_NCRIO_KEY_WRAP _IOWR('c', 250, struct compat_ncr_key_wrap)

static void convert_ncr_key_wrap(struct ncr_key_wrap *new,
				 const struct compat_ncr_key_wrap *old)
{
	new->wrapping_key = old->wrapping_key;
	new->source_key = old->source_key;
	new->buffer = compat_ptr(old->buffer);
	new->buffer_size = old->buffer_size;
}

struct compat_ncr_key_unwrap {
	__u32 input_size, output_size;
	ncr_key_t wrapping_key;
	ncr_key_t dest_key;
	compat_uptr_t data;
	__u32 data_size;
	 __NL_ATTRIBUTES;
};
#define COMPAT_NCRIO_KEY_UNWRAP _IOWR('c', 251, struct compat_ncr_key_unwrap)

static void convert_ncr_key_unwrap(struct ncr_key_unwrap *new,
				   const struct compat_ncr_key_unwrap *old)
{
	new->wrapping_key = old->wrapping_key;
	new->dest_key = old->dest_key;
	new->data = compat_ptr(old->data);
	new->data_size = old->data_size;
}

struct compat_ncr_key_storage_wrap {
	__u32 input_size, output_size;
	ncr_key_t key;
	compat_uptr_t buffer;
	compat_int_t buffer_size;
	 __NL_ATTRIBUTES;
};
#define COMPAT_NCRIO_KEY_STORAGE_WRAP				\
	_IOWR('c', 261, struct compat_ncr_key_storage_wrap)

static void convert_ncr_key_storage_wrap(struct ncr_key_storage_wrap *new,
					 const struct
					 compat_ncr_key_storage_wrap *old)
{
	new->key = old->key;
	new->buffer = compat_ptr(old->buffer);
	new->buffer_size = old->buffer_size;
}

struct compat_ncr_key_storage_unwrap {
	__u32 input_size, output_size;
	ncr_key_t key;
	compat_uptr_t data;
	__u32 data_size;
	 __NL_ATTRIBUTES;
};
#define COMPAT_NCRIO_KEY_STORAGE_UNWRAP				\
	_IOWR('c', 262, struct compat_ncr_key_storage_wrap)

static void convert_ncr_key_storage_unwrap(struct ncr_key_storage_unwrap *new,
					   const struct
					   compat_ncr_key_storage_unwrap *old)
{
	new->key = old->key;
	new->data = compat_ptr(old->data);
	new->data_size = old->data_size;
}

struct compat_ncr_master_key_set {
	__u32 input_size, output_size;
	compat_uptr_t key;
	__u32 key_size;
	 __NL_ATTRIBUTES;
};
#define COMPAT_NCRIO_MASTER_KEY_SET				\
	_IOWR('c', 260, struct compat_ncr_master_key_set)

static void convert_ncr_master_key_set(struct ncr_master_key_set *new,
				       const struct compat_ncr_master_key_set
				       *old)
{
	new->key = compat_ptr(old->key);
	new->key_size = old->key_size;
}

long
ncr_compat_ioctl(struct ncr_lists *lst, unsigned int cmd, unsigned long arg_)
{
	void __user *arg = (void __user *)arg_;
	struct nlattr *tb[NCR_ATTR_MAX + 1];
	void *attr_buf;
	int ret;

	if (unlikely(!lst))
		BUG();

	switch (cmd) {
	case NCRIO_KEY_INIT:
	case NCRIO_KEY_GENERATE:
	case NCRIO_KEY_GENERATE_PAIR:
	case NCRIO_KEY_DERIVE:
	case NCRIO_KEY_GET_INFO:
	case NCRIO_KEY_DEINIT:
	case NCRIO_SESSION_INIT:
		return ncr_ioctl(lst, cmd, arg_);

#define CASE_(LABEL, STRUCT, FUNCTION, ARGS)				\
	case (LABEL): {							\
		struct compat_##STRUCT old;				\
		struct STRUCT new;					\
									\
		attr_buf = NCR_GET_INPUT_ARGS_NO_OUTPUT(&old, tb, arg);	\
		if (IS_ERR(attr_buf)) {					\
			err();						\
			return PTR_ERR(attr_buf);			\
		}							\
		convert_##STRUCT(&new, &old);				\
		ret = (FUNCTION)ARGS;					\
		break;							\
	}
#define CASE_NO_OUTPUT(LABEL, STRUCT, FUNCTION)			\
		CASE_(LABEL, STRUCT, FUNCTION, (lst, &new, tb))

#define CASE_COMPAT_ONLY(LABEL, STRUCT, FUNCTION)			\
	case (LABEL): {							\
		struct STRUCT data;					\
									\
		attr_buf = NCR_GET_INPUT_ARGS_NO_OUTPUT(&data, tb, arg); \
		if (IS_ERR(attr_buf)) {					\
			err();						\
			return PTR_ERR(attr_buf);			\
		}							\
		ret = (FUNCTION)(lst, &data, tb, 1);			\
		break;							\
	}

		CASE_NO_OUTPUT(COMPAT_NCRIO_KEY_EXPORT, ncr_key_export,
			       ncr_key_export);
		CASE_NO_OUTPUT(COMPAT_NCRIO_KEY_IMPORT, ncr_key_import,
			       ncr_key_import);
		CASE_NO_OUTPUT(COMPAT_NCRIO_KEY_WRAP, ncr_key_wrap,
			       ncr_key_wrap);
		CASE_NO_OUTPUT(COMPAT_NCRIO_KEY_UNWRAP, ncr_key_unwrap,
			       ncr_key_unwrap);
		CASE_NO_OUTPUT(COMPAT_NCRIO_KEY_STORAGE_WRAP,
			       ncr_key_storage_wrap, ncr_key_storage_wrap);
		CASE_NO_OUTPUT(COMPAT_NCRIO_KEY_STORAGE_UNWRAP,
			       ncr_key_storage_unwrap, ncr_key_storage_unwrap);
		CASE_COMPAT_ONLY(NCRIO_SESSION_UPDATE, ncr_session_update,
				 ncr_session_update);
		CASE_COMPAT_ONLY(NCRIO_SESSION_FINAL, ncr_session_final,
				 ncr_session_final);
		CASE_COMPAT_ONLY(NCRIO_SESSION_ONCE, ncr_session_once,
				 ncr_session_once);
		CASE_(COMPAT_NCRIO_MASTER_KEY_SET, ncr_master_key_set,
		      ncr_master_key_set, (&new, tb));
	default:
		return -EINVAL;
#undef CASE_
#undef CASE_NO_OUTPUT
#undef CASE_COMPAT_ONLY
	}
	kfree(attr_buf);
	return ret;
}
#endif

int ncr_session_input_data_from_nla(struct ncr_session_input_data *dest,
				    const struct nlattr *nla, int compat)
{
	if (unlikely(nla == NULL))
		return -EINVAL;
#ifdef CONFIG_COMPAT
	if (!compat) {
#endif
		if (unlikely(nla_len(nla) < sizeof(dest)))
			return -ERANGE;	/* nla_validate would return -ERANGE. */
		memcpy(dest, nla_data(nla), sizeof(*dest));
#ifdef CONFIG_COMPAT
	} else {
		struct compat_ncr_session_input_data old;

		if (unlikely(nla_len(nla) < sizeof(old)))
			return -ERANGE;
		memcpy(&old, nla_data(nla), sizeof(old));
		dest->data = compat_ptr(old.data);
		dest->data_size = old.data_size;
	}
#endif
	return 0;
}

int ncr_session_output_buffer_from_nla(struct ncr_session_output_buffer *dest,
				       const struct nlattr *nla, int compat)
{
	if (unlikely(nla == NULL))
		return -EINVAL;
#ifdef CONFIG_COMPAT
	if (!compat) {
#endif
		if (unlikely(nla_len(nla) < sizeof(dest)))
			return -ERANGE;	/* nla_validate would return -ERANGE. */
		memcpy(dest, nla_data(nla), sizeof(*dest));
#ifdef CONFIG_COMPAT
	} else {
		struct compat_ncr_session_output_buffer old;

		if (unlikely(nla_len(nla) < sizeof(old)))
			return -ERANGE;
		memcpy(&old, nla_data(nla), sizeof(old));
		dest->buffer = compat_ptr(old.buffer);
		dest->buffer_size = old.buffer_size;
		dest->result_size_ptr = compat_ptr(old.result_size_ptr);
	}
#endif
	return 0;
}

int ncr_session_output_buffer_set_size(const struct ncr_session_output_buffer
				       *dest, size_t size, int compat)
{
#ifdef CONFIG_COMPAT
	if (!compat)
#endif
		return put_user(size, dest->result_size_ptr);
#ifdef CONFIG_COMPAT
	else {
		compat_size_t old;

		old = size;
		return put_user(old,
				(compat_size_t __user *) dest->result_size_ptr);
	}
#endif
}
