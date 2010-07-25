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
#include <linux/mm_types.h>
#include <linux/scatterlist.h>
#include <ncr-sessions.h>

/* Only the output buffer is given as scatterlist */
static int get_userbuf1(struct session_item_st* ses,
		struct ncr_session_op_st* op, struct scatterlist **dst_sg, unsigned *dst_cnt)
{
	int pagecount = 0;

	if (op->data.udata.output == NULL) {
		return -EINVAL;
	}

	pagecount = PAGECOUNT(op->data.udata.output, op->data.udata.output_size);


	ses->available_pages = pagecount;

	if (pagecount > ses->array_size) {
		while (ses->array_size < pagecount)
			ses->array_size *= 2;

		dprintk(2, KERN_DEBUG, "%s: reallocating to %d elements\n",
				__func__, ses->array_size);
		ses->pages = krealloc(ses->pages, ses->array_size *
				sizeof(struct page *), GFP_KERNEL);
		ses->sg = krealloc(ses->sg, ses->array_size *
				sizeof(struct scatterlist), GFP_KERNEL);

		if (ses->sg == NULL || ses->pages == NULL) {
			return -ENOMEM;
		}
	}

	if (__get_userbuf(op->data.udata.output, op->data.udata.output_size, 1,
			pagecount, ses->pages, ses->sg)) {
		dprintk(1, KERN_ERR, "failed to get user pages for data input\n");
		return -EINVAL;
	}
	(*dst_sg) = ses->sg;
	*dst_cnt = pagecount;

	return 0;
}

/* make op->data.udata.input and op->data.udata.output available in scatterlists */
static int get_userbuf2(struct session_item_st* ses,
		struct ncr_session_op_st* op, struct scatterlist **src_sg,
		unsigned *src_cnt, struct scatterlist **dst_sg, unsigned *dst_cnt)
{
	int src_pagecount, dst_pagecount = 0, pagecount, write_src = 1;

	if (op->data.udata.input == NULL) {
		return -EINVAL;
	}

	src_pagecount = PAGECOUNT(op->data.udata.input, op->data.udata.input_size);

	if (op->data.udata.input != op->data.udata.output) {	/* non-in-situ transformation */
		if (op->data.udata.output != NULL) {
			dst_pagecount = PAGECOUNT(op->data.udata.output, op->data.udata.output_size);
			write_src = 0;
		} else {
			dst_pagecount = 0;
		}
	}

	ses->available_pages = pagecount = src_pagecount + dst_pagecount;

	if (pagecount > ses->array_size) {
		while (ses->array_size < pagecount)
			ses->array_size *= 2;

		dprintk(2, KERN_DEBUG, "%s: reallocating to %d elements\n",
				__func__, ses->array_size);
		ses->pages = krealloc(ses->pages, ses->array_size *
				sizeof(struct page *), GFP_KERNEL);
		ses->sg = krealloc(ses->sg, ses->array_size *
				sizeof(struct scatterlist), GFP_KERNEL);

		if (ses->sg == NULL || ses->pages == NULL) {
			return -ENOMEM;
		}
	}

	if (__get_userbuf(op->data.udata.input, op->data.udata.input_size, write_src,
			src_pagecount, ses->pages, ses->sg)) {
		dprintk(1, KERN_ERR, "failed to get user pages for data input\n");
		return -EINVAL;
	}
	(*src_sg) = ses->sg;
	*src_cnt = src_pagecount;

	if (dst_pagecount) {
		*dst_cnt = dst_pagecount;
		(*dst_sg) = ses->sg + src_pagecount;

		if (__get_userbuf(op->data.udata.output, op->data.udata.output_size, 1, dst_pagecount,
					ses->pages + src_pagecount, *dst_sg)) {
			dprintk(1, KERN_ERR, "failed to get user pages for data output\n");
			release_user_pages(ses->pages, src_pagecount);
			return -EINVAL;
		}
	} else {
		if (op->data.udata.output != NULL) {
			*dst_cnt = src_pagecount;
			(*dst_sg) = (*src_sg);
		} else {
			*dst_cnt = 0;
			*dst_sg = NULL;
		}
	}

	return 0;
}

/* Called when userspace buffers are used */
int _ncr_session_direct_update(struct ncr_lists* lists, struct ncr_session_op_st* op)
{
	int ret;
	struct session_item_st* sess;
	struct scatterlist *isg;
	struct scatterlist *osg;
	unsigned osg_cnt=0, isg_cnt=0;
	size_t isg_size, osg_size;

	sess = ncr_sessions_item_get( &lists->sessions, op->ses);
	if (sess == NULL) {
		err();
		return -EINVAL;
	}

	if (down_interruptible(&sess->mem_mutex)) {
		err();
		_ncr_sessions_item_put(sess);
		return -ERESTARTSYS;
	}

	ret = get_userbuf2(sess, op, &isg, &isg_cnt, &osg, &osg_cnt);
	if (ret < 0) {
		err();
		goto fail;
	}
	isg_size = op->data.udata.input_size;
	osg_size = op->data.udata.output_size;

	switch(sess->op) {
		case NCR_OP_ENCRYPT:
			if (osg == NULL) {
				err();
				ret = -EINVAL;
				goto fail;
			}
			
			ret = _ncr_session_encrypt(sess, isg, isg_cnt, isg_size, 
				osg, osg_cnt, &osg_size);
			if (ret < 0) {
				err();
				goto fail;
			}
			op->data.udata.output_size = osg_size;
			
			break;
		case NCR_OP_DECRYPT:
			if (osg == NULL) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			if (osg_size < isg_size) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			ret = _ncr_session_decrypt(sess, isg, isg_cnt, isg_size, 
				osg, osg_cnt, &osg_size);
			if (ret < 0) {
				err();
				goto fail;
			}
			op->data.udata.output_size = osg_size;

			break;

		case NCR_OP_SIGN:
		case NCR_OP_VERIFY:
			ret = cryptodev_hash_update(&sess->hash, isg, isg_size);
			if (ret < 0) {
				err();
				goto fail;
			}
			break;
		default:
			err();
			ret = -EINVAL;
			goto fail;
	}

	ret = 0;

fail:
	if (sess->available_pages) {
		release_user_pages(sess->pages, sess->available_pages);
		sess->available_pages = 0;
	}
	up(&sess->mem_mutex);
	_ncr_sessions_item_put(sess);

	return ret;
}

static int try_session_direct_update(struct ncr_lists* lists, struct ncr_session_op_st* op)
{
	if (op->data.udata.input != NULL) {
		return _ncr_session_direct_update(lists, op);
	}

	return 0;
}

int _ncr_session_direct_final(struct ncr_lists* lists, struct ncr_session_op_st* op)
{
	int ret;
	struct session_item_st* sess;
	struct data_item_st* odata = NULL;
	int digest_size;
	uint8_t digest[NCR_HASH_MAX_OUTPUT_SIZE];
	uint8_t vdigest[NCR_HASH_MAX_OUTPUT_SIZE];
	struct scatterlist *osg;
	unsigned osg_cnt=0;
	size_t osg_size = 0;
	size_t orig_osg_size;

	sess = ncr_sessions_item_get( &lists->sessions, op->ses);
	if (sess == NULL) {
		err();
		return -EINVAL;
	}

	ret = try_session_direct_update(lists, op);
	if (ret < 0) {
		err();
		_ncr_sessions_item_put(sess);
		return ret;
	}

	if (down_interruptible(&sess->mem_mutex)) {
		err();
		_ncr_sessions_item_put(sess);
		return -ERESTARTSYS;
	}

	switch(sess->op) {
		case NCR_OP_ENCRYPT:
		case NCR_OP_DECRYPT:
			break;
		case NCR_OP_VERIFY:
			ret = get_userbuf1(sess, op, &osg, &osg_cnt);
			if (ret < 0) {
				err();
				goto fail;
			}
			orig_osg_size = osg_size = op->data.udata.output_size;

			digest_size = sess->hash.digestsize;
			if (digest_size == 0 || sizeof(digest) < digest_size) {
				err();
				ret = -EINVAL;
				goto fail;
			}
			ret = cryptodev_hash_final(&sess->hash, digest);
			if (ret < 0) {
				err();
				goto fail;
			}

			if (sess->algorithm->is_hmac) {
				ret = sg_copy_to_buffer(osg, osg_cnt, vdigest, digest_size);
				if (ret != digest_size) {
					err();
					ret = -EINVAL;
					goto fail;
				}
				
				if (digest_size != odata->data_size ||
					memcmp(vdigest, digest, digest_size) != 0) {
						
					op->err = NCR_VERIFICATION_FAILED;
				} else {
					op->err = NCR_SUCCESS;
				}
			} else {
				/* PK signature */
				ret = ncr_pk_cipher_verify(&sess->pk, osg, osg_cnt, osg_size,
					digest, digest_size, &op->err);
				if (ret < 0) {
					err();
					goto fail;
				}
			}
			break;

		case NCR_OP_SIGN:
			ret = get_userbuf1(sess, op, &osg, &osg_cnt);
			if (ret < 0) {
				err();
				goto fail;
			}
			orig_osg_size = osg_size = op->data.udata.output_size;

			digest_size = sess->hash.digestsize;
			if (digest_size == 0 || osg_size < digest_size) {
				err();
				ret = -EINVAL;
				goto fail;
			}

			ret = cryptodev_hash_final(&sess->hash, digest);
			if (ret < 0) {
				err();
				goto fail;
			}

			ret = sg_copy_from_buffer(osg, osg_cnt, digest, digest_size);
			if (ret != digest_size) {
				err();
				ret = -EINVAL;
				goto fail;
			}
			osg_size = digest_size;
			
			cryptodev_hash_deinit(&sess->hash);

			if (sess->algorithm->is_pk) {
				/* PK signature */
				
				ret = ncr_pk_cipher_sign(&sess->pk, osg, osg_cnt, osg_size,
					osg, osg_cnt, &orig_osg_size);
				if (ret < 0) {
					err();
					goto fail;
				}
				osg_size = orig_osg_size;
			}
			break;
		default:
			err();
			ret = -EINVAL;
			goto fail;
	}

	if (osg_size > 0)
		op->data.udata.output_size = osg_size;

	ret = 0;

fail:
	if (sess->available_pages) {
		release_user_pages(sess->pages, sess->available_pages);
		sess->available_pages = 0;
	}
	up(&sess->mem_mutex);

	cryptodev_hash_deinit(&sess->hash);
	if (sess->algorithm->is_symmetric) {
		cryptodev_cipher_deinit(&sess->cipher);
	} else {
		ncr_pk_cipher_deinit(&sess->pk);
	}

	_ncr_sessions_item_put(sess);
	_ncr_session_remove(&lists->sessions, op->ses);

	return ret;
}


