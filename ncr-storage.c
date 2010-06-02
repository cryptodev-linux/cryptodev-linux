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

#include <linux/mm.h>
#include <linux/highmem.h>
#include "cryptodev.h"
#include <asm/uaccess.h>
#include <asm/ioctl.h>
#include <linux/scatterlist.h>
#include <linux/version.h>
#include "ncr.h"
#include "ncr_int.h"
#include "ncr-storage.h"

/* Convert a ncr key to a raw one ready for storage.
 */
int _ncr_key_to_store(const struct key_item_st *key, const char* label,
	mode_t mode, struct storage_item_st* output)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,27)
	uid_t uid = key->filp->f_uid;
	gid_t gid = key->filp->f_gid;
#else
	gid_t gid = key->filp->f_cred->fsgid;
	gid_t gid = key->filp->f_cred->fsgid;
#endif
	/* copy metadata first */
	memcpy(output->key_id, key->key_id, sizeof(output->key_id));
	output->key_id_size = key->key_id_size;

	output->algorithm = key->algorithm;
	output->type = key->type;
	output->owner = uid;
	output->group = gid;

	strlcpy(output->label, label, sizeof(output->label));
	output->mode = mode;
	
	/* format is type (uint8_t) + ... */
	switch(key->type) {
		case NCR_KEY_TYPE_SECRET:
			/* uint16_t size + raw key */
			if (sizeof(output->raw_key) < key->key.secret.size + 2)
				BUG();

			output->raw_key[0] = (key->key.secret.size >> 8) & 0xff;
			output->raw_key[1] = (key->key.secret.size) & 0xff;
			memcpy(&output->raw_key[2], key->key.secret.data, key->key.secret.size);

			return 0;
		default:
			return -EINVAL;
	}
}

int _ncr_store_to_key(const struct storage_item_st* raw, struct key_item_st *key)
{
	/* copy metadata first */
	memcpy(key->key_id, raw->key_id, sizeof(key->key_id));
	key->key_id_size = raw->key_id_size;

	key->algorithm = raw->algorithm;
	key->type = raw->type;

	switch(key->type) {
		case NCR_KEY_TYPE_SECRET:
			/* uint16_t size + raw key */
			key->key.secret.size = (raw->raw_key[0] << 8) | raw->raw_key[1];
			if (key->key.secret.size > MAX_KEY_SIZE) {
				err();
				return -EFAULT;
			}
			memcpy(key->key.secret.data, &raw->raw_key[2], key->key.secret.size);

			return 0;
		default:
			return -EINVAL;
	}

}

int ncr_storage_store(struct list_sem_st* key_lst, void __user* arg)
{
	struct ncr_storage_st sinfo;
	struct key_item_st * key;
	struct storage_item_st tostore;
	int ret;

	copy_from_user( &sinfo, arg, sizeof(sinfo));

	key = ncr_key_item_get( key_lst, sinfo.key);
	if (key == NULL) {
		err();
		return -EINVAL;
	}

	ret = _ncr_key_to_store(key, sinfo.label, sinfo.mode, &tostore);
	if (ret < 0) {
		err();
		goto fail;
	}

	ret = _ncr_store(&tostore);
	if (ret < 0) {
		err();
		goto fail;
	}

	ret = 0;

fail:
	_ncr_key_item_put(key);

	return ret;
}


int ncr_storage_load(struct list_sem_st* key_lst, void __user* arg)
{
	gid_t gid;
	uid_t uid;
	struct ncr_storage_st sinfo;
	struct key_item_st * key;
	struct storage_item_st loaded;
	int ret;

	copy_from_user( &sinfo, arg, sizeof(sinfo));

	key = ncr_key_item_get( key_lst, sinfo.key);
	if (key == NULL) {
		err();
		return -EINVAL;
	}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,27)
	uid = key->filp->f_uid;
	gid = key->filp->f_gid;
#else
	gid = key->filp->f_cred->fsgid;
	gid = key->filp->f_cred->fsgid;
#endif

	/* we set the current user uid and gid
	 * to allow permission checking
	 */
	loaded.owner = uid;
	loaded.group = gid;

	ret = _ncr_load(&loaded);
	if (ret < 0) {
		err();
		goto fail;
	}

	ret = _ncr_store_to_key(&loaded, key);
	if (ret < 0) {
		err();
		goto fail;
	}

	ret = 0;

fail:
	_ncr_key_item_put(key);

	return ret;
}


