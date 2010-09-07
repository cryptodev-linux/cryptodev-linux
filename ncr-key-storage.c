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

#include <linux/ioctl.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/scatterlist.h>
#include "ncr.h"
#include "ncr-int.h"
#include "cryptodev_int.h"

struct packed_key {
	uint32_t version;
	uint8_t type;
	uint32_t flags;
	uint32_t algorithm;
	uint8_t key_id[MAX_KEY_ID_SIZE];
	uint8_t key_id_size;

	uint8_t raw[KEY_DATA_MAX_SIZE];
	uint32_t raw_size;
} __attribute__ ((__packed__));

#define THIS_VERSION 2

int key_to_storage_data(uint8_t ** sdata, size_t * sdata_size,
			const struct key_item_st *key)
{
	struct packed_key *pkey;
	int ret;

	pkey = kmalloc(sizeof(*pkey), GFP_KERNEL);
	if (pkey == NULL) {
		err();
		return -ENOMEM;
	}

	pkey->version = THIS_VERSION;
	pkey->type = key->type;
	pkey->flags = key->flags;

	pkey->algorithm = key->algorithm->algo;

	pkey->key_id_size = key->key_id_size;
	memcpy(pkey->key_id, key->key_id, key->key_id_size);

	if (key->type == NCR_KEY_TYPE_SECRET) {
		pkey->raw_size = key->key.secret.size;
		memcpy(pkey->raw, key->key.secret.data, pkey->raw_size);
	} else if (key->type == NCR_KEY_TYPE_PRIVATE
		   || key->type == NCR_KEY_TYPE_PUBLIC) {
		pkey->raw_size = sizeof(pkey->raw);
		ret = ncr_pk_pack(key, pkey->raw, &pkey->raw_size);
		if (ret < 0) {
			err();
			goto fail;
		}
	} else {
		err();
		ret = -EINVAL;
		goto fail;
	}

	*sdata = (void *)pkey;
	*sdata_size = sizeof(*pkey);

	return 0;
fail:
	kfree(pkey);

	return ret;
}

int key_from_storage_data(struct key_item_st *key, const void *data,
			  size_t data_size)
{
	const struct packed_key *pkey = data;

	if (data_size != sizeof(*pkey) || pkey->version != THIS_VERSION
	    || pkey->key_id_size > MAX_KEY_ID_SIZE) {
		err();
		return -EINVAL;
	}

	key->type = pkey->type;
	key->flags = pkey->flags;

	key->algorithm = _ncr_algo_to_properties(pkey->algorithm);
	if (key->algorithm == NULL) {
		err();
		return -EINVAL;
	}
	key->key_id_size = pkey->key_id_size;
	memcpy(key->key_id, pkey->key_id, pkey->key_id_size);

	if (key->type == NCR_KEY_TYPE_SECRET) {
		if (pkey->raw_size > NCR_CIPHER_MAX_KEY_LEN) {
			err();
			return -EINVAL;
		}
		key->key.secret.size = pkey->raw_size;
		memcpy(key->key.secret.data, pkey->raw, pkey->raw_size);
	} else if (key->type == NCR_KEY_TYPE_PUBLIC
		   || key->type == NCR_KEY_TYPE_PRIVATE) {
		int ret;

		ret = ncr_pk_unpack(key, pkey->raw, pkey->raw_size);
		if (ret < 0) {
			err();
			return ret;
		}
	} else {
		err();
		return -EINVAL;
	}

	return 0;
}
