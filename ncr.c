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

void* ncr_init_lists(void)
{
	struct ncr_lists *lst;

	lst = kmalloc(sizeof(*lst), GFP_KERNEL);
	if(!lst) {
		err();
		return NULL;
	}

	memset(lst, 0, sizeof(*lst));

	init_MUTEX(&lst->data.sem);
	INIT_LIST_HEAD(&lst->data.list);

	init_MUTEX(&lst->key.sem);
	INIT_LIST_HEAD(&lst->key.list);

	init_MUTEX(&lst->sessions.sem);
	INIT_LIST_HEAD(&lst->sessions.list);

	return lst;
}

void ncr_deinit_lists(struct ncr_lists *lst)
{
	if(lst) {
		ncr_data_list_deinit(&lst->data);
		ncr_key_list_deinit(&lst->key);
		ncr_sessions_list_deinit(&lst->sessions);
		kfree(lst);
	}
}

int
ncr_ioctl(struct ncr_lists* lst, struct file *filp,
		unsigned int cmd, unsigned long arg)
{

	if (unlikely(!lst))
		BUG();

	switch (cmd) {
		case NCRIO_DATA_INIT:
			return ncr_data_init(filp, &lst->data, (void*)arg);
		case NCRIO_DATA_GET:
			return ncr_data_get(&lst->data, (void*)arg);
		case NCRIO_DATA_SET:
			return ncr_data_set(&lst->data, (void*)arg);
		case NCRIO_DATA_DEINIT:
			return ncr_data_deinit(&lst->data, (void*)arg);

		case NCRIO_KEY_INIT:
			return ncr_key_init(filp, &lst->key, (void*)arg);
		case NCRIO_KEY_DEINIT:
			return ncr_key_deinit(&lst->key, (void*)arg);
		case NCRIO_KEY_GENERATE:
			return ncr_key_generate(&lst->key, (void*)arg);
		case NCRIO_KEY_EXPORT:
			return ncr_key_export(&lst->data, &lst->key, (void*)arg);
		case NCRIO_KEY_IMPORT:
			return ncr_key_import(&lst->data, &lst->key, (void*)arg);
		case NCRIO_KEY_GET_INFO:
			return ncr_key_info(&lst->key, (void*)arg);
		case NCRIO_KEY_WRAP:
			return ncr_key_wrap(&lst->key, &lst->data, &lst->sessions, (void*)arg);
		case NCRIO_KEY_UNWRAP:
			return ncr_key_unwrap(&lst->key, &lst->data, &lst->sessions, (void*)arg);
#if 0
		case NCRIO_KEY_GENERATE_PAIR:
			return ncr_key_generate_pair(&lst->key, (void*)arg);
		case NCRIO_KEY_DERIVE:
			return ncr_key_derive(&lst->key, (void*)arg);
		case NCRIO_KEY_GET_PUBLIC:
			return ncr_key_get_public(&lst->key, (void*)arg);
		case NCRIO_KEY_SET_PUBLIC:
			return ncr_key_set_public(&lst->key, (void*)arg);
		case NCRIO_KEY_GET_PRIVATE:
			return ncr_key_get_private(&lst->key, (void*)arg);
		case NCRIO_KEY_SET_PRIVATE:
			return ncr_key_set_private(&lst->key, (void*)arg);
#endif
		default:
			return -EINVAL;
	}
}

/* Returns NCR_KEY_TYPE_SECRET if a secret key algorithm or MAC is given,
 * and NCR_KEY_TYPE_PUBLIC if a public key algorithm is given.
 */
ncr_key_type_t ncr_algorithm_to_key_type(ncr_algorithm_t algo)
{
	switch(algo) {
		case NCR_ALG_3DES_CBC:
		case NCR_ALG_AES_CBC:
		case NCR_ALG_CAMELLIA_CBC:
		case NCR_ALG_ARCFOUR:
		case NCR_ALG_HMAC_SHA1:
		case NCR_ALG_HMAC_MD5:
		case NCR_ALG_HMAC_SHA2_224:
		case NCR_ALG_HMAC_SHA2_256:
		case NCR_ALG_HMAC_SHA2_384:
		case NCR_ALG_HMAC_SHA2_512:
			return NCR_KEY_TYPE_SECRET;
		case NCR_ALG_RSA:
		case NCR_ALG_DSA:
			return NCR_KEY_TYPE_PUBLIC;
		default:
			return NCR_KEY_TYPE_INVALID;
	}
	
}


