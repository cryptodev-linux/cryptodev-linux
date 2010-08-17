/*
 * Driver for /dev/crypto device (aka CryptoDev)
 *
 * Copyright (c) 2004 Michal Ludvig <mludvig@logix.net.nz>, SuSE Labs
 * Copyright (c) 2009,2010 Nikos Mavrogiannopoulos <nmav@gnutls.org>
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

/*
 * Device /dev/crypto provides an interface for 
 * accessing kernel CryptoAPI algorithms (ciphers,
 * hashes) from userspace programs.
 *
 * /dev/crypto interface was originally introduced in
 * OpenBSD and this module attempts to keep the API.
 *
 */

#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/ioctl.h>
#include <linux/random.h>
#include <linux/syscalls.h>
#include <linux/pagemap.h>
#include <linux/uaccess.h>
#include <linux/scatterlist.h>
#include "cryptodev_int.h"
#include "ncr-int.h"
#include <linux/version.h>
#include "version.h"

MODULE_AUTHOR("Nikos Mavrogiannopoulos <nmav@gnutls.org>");
MODULE_DESCRIPTION("CryptoDev driver");
MODULE_LICENSE("GPL");

/* ====== Module parameters ====== */

int cryptodev_verbosity = 0;
module_param(cryptodev_verbosity, int, 0644);
MODULE_PARM_DESC(cryptodev_verbosity, "0: normal, 1: verbose, 2: debug");

/* ====== CryptoAPI ====== */

void release_user_pages(struct page **pg, int pagecount)
{
	while (pagecount--) {
		if (!PageReserved(pg[pagecount]))
			SetPageDirty(pg[pagecount]);
		page_cache_release(pg[pagecount]);
	}
}

/* offset of buf in it's first page */
#define PAGEOFFSET(buf) ((unsigned long)buf & ~PAGE_MASK)

/* fetch the pages addr resides in into pg and initialise sg with them */
int __get_userbuf(uint8_t __user *addr, uint32_t len, int write,
		int pgcount, struct page **pg, struct scatterlist *sg)
{
	int ret, pglen, i = 0;
	struct scatterlist *sgp;

	down_write(&current->mm->mmap_sem);
	ret = get_user_pages(current, current->mm,
			(unsigned long)addr, pgcount, write, 0, pg, NULL);
	up_write(&current->mm->mmap_sem);
	if (ret != pgcount)
		return -EINVAL;

	sg_init_table(sg, pgcount);

	pglen = min((ptrdiff_t)(PAGE_SIZE - PAGEOFFSET(addr)), (ptrdiff_t)len);
	sg_set_page(sg, pg[i++], pglen, PAGEOFFSET(addr));

	len -= pglen;
	for (sgp = sg_next(sg); len; sgp = sg_next(sgp)) {
		pglen = min((uint32_t)PAGE_SIZE, len);
		sg_set_page(sgp, pg[i++], pglen, 0);
		len -= pglen;
	}
	sg_mark_end(sg_last(sg, pgcount));
	return 0;
}

/* ====== /dev/crypto ====== */

static int
cryptodev_open(struct inode *inode, struct file *filp)
{
	void *ncr;

	ncr = ncr_init_lists();
	if (ncr == NULL) {
		return -ENOMEM;
	}

	filp->private_data = ncr;
	return 0;
}

static int
cryptodev_release(struct inode *inode, struct file *filp)
{
	void *ncr = filp->private_data;

	if (ncr) {
		ncr_deinit_lists(ncr);
		filp->private_data = NULL;
	}

	return 0;
}

static int
cryptodev_ioctl(struct inode *inode, struct file *filp,
		unsigned int cmd, unsigned long arg)
{
	void *ncr = filp->private_data;

	if (unlikely(!ncr))
		BUG();

	return ncr_ioctl(ncr, cmd, arg);
}

/* compatibility code for 32bit userlands */
#ifdef CONFIG_COMPAT

static long
cryptodev_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void *ncr = file->private_data;

	if (unlikely(!ncr))
		BUG();

	return ncr_compat_ioctl(ncr, cmd, arg);
}

#endif /* CONFIG_COMPAT */

static const struct file_operations cryptodev_fops = {
	.owner = THIS_MODULE,
	.open = cryptodev_open,
	.release = cryptodev_release,
	.ioctl = cryptodev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = cryptodev_compat_ioctl,
#endif /* CONFIG_COMPAT */
};

static struct miscdevice cryptodev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "crypto",
	.fops = &cryptodev_fops,
};

static int __init
cryptodev_register(void)
{
	int rc;

	ncr_limits_init();
	ncr_master_key_reset();
	
	rc = misc_register (&cryptodev);
	if (unlikely(rc)) {
		ncr_limits_deinit();
		printk(KERN_ERR PFX "registration of /dev/crypto failed\n");
		return rc;
	}

	return 0;
}

static void __exit
cryptodev_deregister(void)
{
	misc_deregister(&cryptodev);
	ncr_limits_deinit();
}

/* ====== Module init/exit ====== */
static int __init init_cryptodev(void)
{
	int rc;

	rc = cryptodev_register();
	if (unlikely(rc))
		return rc;

	printk(KERN_INFO PFX "driver %s loaded.\n", VERSION);

	return 0;
}

static void __exit exit_cryptodev(void)
{
	cryptodev_deregister();
	printk(KERN_INFO PFX "driver unloaded.\n");
}

module_init(init_cryptodev);
module_exit(exit_cryptodev);
