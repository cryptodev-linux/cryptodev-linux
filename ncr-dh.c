/*
 * New driver for /dev/crypto device (aka CryptoDev)

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

#include <linux/mm.h>
#include <linux/random.h>
#include "cryptodev.h"
#include <asm/uaccess.h>
#include <asm/ioctl.h>
#include <linux/scatterlist.h>
#include <ncr.h>
#include <ncr-int.h>
#include <tomcrypt.h>
#include <ncr-dh.h>

void dh_free(dh_key * key)
{
	mp_clear_multi(&key->p, &key->g, &key->x, NULL);
}

int dh_import_params(dh_key * key, uint8_t* p, size_t p_size, uint8_t* g, size_t g_size)
{
int ret;
int err;
	
	if ((err = mp_init_multi(&key->p, &key->g, &key->x, &key->y, NULL)) != CRYPT_OK) {
		err();
		return -ENOMEM;
	}
	
	if ((err = mp_read_unsigned_bin(&key->p, (unsigned char *)p, p_size)) != CRYPT_OK) {
		err();
		ret = _ncr_tomerr(err);
		goto fail;
	}

	if ((err = mp_read_unsigned_bin(&key->g, (unsigned char *)g, g_size)) != CRYPT_OK) {
		err();
		ret = _ncr_tomerr(err);
		goto fail;
	}

	return 0;
fail:
	mp_clear_multi(&key->p, &key->g, &key->x, &key->y, NULL);
	
	return ret;
}

int dh_generate_key(dh_key * key)
{
void* buf;
int size;
int err, ret;

	size = mp_unsigned_bin_size(&key->p);
	if (size == 0) {
	   err();
	   return -EINVAL;
	}
	
	buf = kmalloc(size, GFP_KERNEL);
	if (buf == NULL) {
		err();
		return -ENOMEM;
	}
	
	get_random_bytes( buf, size);

	if ((err = mp_read_unsigned_bin(&key->x, buf, size)) != CRYPT_OK) {
		err();
		ret = _ncr_tomerr(err);
		goto fail;
	}
	
	err = mp_mod( &key->g, &key->p, &key->x);
	if (err != CRYPT_OK) {
		err();
		ret = _ncr_tomerr(err);
		goto fail;
	}
	
	key->type = PK_PRIVATE;
	
	ret = 0;
fail:
	kfree(buf);
	
	return ret;

}

int dh_generate_public(dh_key * public, dh_key* private)
{
int err, ret;

	err = mp_copy(&private->g, &public->g);
	if (err != CRYPT_OK) {
		err();
		ret = _ncr_tomerr(err);
		goto fail;
	}
	
	err = mp_copy(&private->p, &public->p);
	if (err != CRYPT_OK) {
		err();
		ret = _ncr_tomerr(err);
		goto fail;
	}

	err = mp_exptmod(&private->g, &private->x, &private->p, &public->y);
	if (err != CRYPT_OK) {
		err();
		ret = _ncr_tomerr(err);
		goto fail;
	}
	
	public->type = PK_PUBLIC;
	
	ret = 0;
fail:
		
	return ret;

}
