/*
 * Author: Nikos Mavrogiannopoulos
 *
 * GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

/* This file provides functions to use NCR with GnuTLS 3.1.
 */

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <crypto/ncr.h>

#include <errno.h>

struct ncr_ctx_st
{
  int cfd;
  ncr_key_t privkey;
};

static void ncr_close_session(struct ncr_ctx_st *s);
static int import_ncr_key (gnutls_privkey_t pkey,
                           const gnutls_datum_t * fdata);

static void
ncr_deinit_fn (gnutls_privkey_t key, void *_s)
{
  struct ncr_ctx_st *s = _s;
  
  close(s->cfd);
  gnutls_free (s);
}

static int
ncr_sign_fn (gnutls_privkey_t key, void *_s,
	     const gnutls_datum_t * data, gnutls_datum_t * sig)
{
  struct ncr_ctx_st *s = _s;
  NCR_STRUCT(ncr_session_once) ksign;
  struct nlattr *nla;
  size_t sig_size;
  
  sig->size = 1024;
  sig->data = gnutls_malloc(sig->size);
  
  if (sig->data == NULL)
    return GNUTLS_E_MEMORY_ERROR;
  
  nla = NCR_INIT(ksign);
  ksign.f.op = NCR_OP_SIGN;
  ncr_put_u32(&nla, NCR_ATTR_ALGORITHM, NCR_ALG_RSA);
  ncr_put_u32(&nla, NCR_ATTR_SIGNATURE_TRANSPARENT, 1);
  ncr_put_u32(&nla, NCR_ATTR_KEY, s->privkey);
  ncr_put_u32(&nla, NCR_ATTR_RSA_ENCODING_METHOD, RSA_PKCS1_V1_5);
  ncr_put_u32(&nla, NCR_ATTR_SIGNATURE_HASH_ALGORITHM, NCR_ALG_SHA1);
  ncr_put_session_input_data(&nla, NCR_ATTR_UPDATE_INPUT_DATA, data->data, data->size);
  
  ncr_put_session_output_buffer(&nla, NCR_ATTR_FINAL_OUTPUT_BUFFER, sig->data, 
                                sig->size, &sig_size);
  NCR_FINISH(ksign, nla);
  
  if (ioctl(s->cfd, NCRIO_SESSION_ONCE, &ksign))
    {
      nxweb_log_error("Error: %s:%d: %s", __func__, __LINE__, strerror(errno));
      nxweb_log_error("sign %u bytes", data->size);
      gnutls_free(sig->data);
      sig->data = NULL;
      return GNUTLS_E_INTERNAL_ERROR;
    }
  
  sig->size = sig_size;

  return 0;
}

static int ncr_open_session(struct ncr_ctx_st *s)
{
int fd;

  fd = open("/dev/ncr", O_RDWR, 0);
  if (fd < 0)
    {
      nxweb_log_error("Error: %s:%d: %s\n", __func__, __LINE__, strerror(errno));
      return GNUTLS_E_FILE_ERROR;
    }

  s->cfd = fd;
  
  return 0;
}

static void ncr_close_session(struct ncr_ctx_st *s)
{
  close(s->cfd);
}

static int load_key(struct ncr_ctx_st *s, const gnutls_datum_t * fdata)
{
ncr_key_t key;
struct ncr_key_storage_unwrap kunwrap;

  key = ioctl(s->cfd, NCRIO_KEY_INIT);
  if (key == -1)
    {
      nxweb_log_error("Error: %s:%d: %s\n", __func__, __LINE__, strerror(errno));
      return GNUTLS_E_INTERNAL_ERROR;
    }
  
  memset(&kunwrap, 0, sizeof(kunwrap));
  kunwrap.key = key;
  kunwrap.data = fdata->data;
  kunwrap.data_size = fdata->size;
  
  if (ioctl(s->cfd, NCRIO_KEY_STORAGE_UNWRAP, &kunwrap))
    {
      nxweb_log_error("Error: %s:%d: %s\n", __func__, __LINE__, strerror(errno));
      return (GNUTLS_E_INTERNAL_ERROR);
    } 

  s->privkey = key;

  return 0;
}


static int
import_ncr_key (gnutls_privkey_t pkey,
                const gnutls_datum_t * fdata)
{
  int err, ret;
  struct ncr_ctx_st *s;

  s = gnutls_malloc (sizeof (*s));
  if (s == NULL)
    {
      nxweb_log_error("Error: %s:%d: %s\n", __func__, __LINE__, strerror(errno));
      return GNUTLS_E_MEMORY_ERROR;
    }

  ret = ncr_open_session(s);
  if (ret < 0)
    {
      nxweb_log_error("Error: %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
      goto out_ctx;
    }

  ret = load_key(s, fdata);
  if (ret < 0)
    {
      nxweb_log_error("Error: %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
      goto out_session;
    }

  ret =
      gnutls_privkey_import_ext2 (pkey, GNUTLS_PK_RSA, s,
				 ncr_sign_fn, NULL, ncr_deinit_fn,  0);
  if (ret < 0)
    {
      nxweb_log_error("Error: %s:%d: %s\n", __func__, __LINE__, gnutls_strerror(ret));
      goto out_session;
    }

  return 0;
out_session:
  ncr_close_session(s);
out_ctx:
  gnutls_free (s);
  return ret;
}

/**
 * gnutls_privkey_import_ncr_raw:
 * @pkey: The private key
 * @fdata: The TPM key to be imported
 * @format: The format of the private key
 * @srk_password: The password for the SRK key (optional)
 * @key_password: A password for the key (optional)
 * @flags: should be zero
 *
 * This function will import the given private key to the abstract
 * #gnutls_privkey_t structure. 
 *
 * With respect to passwords the same as in gnutls_privkey_import_ncr_url() apply.
 *
 * Returns: On success, %GNUTLS_E_SUCCESS (0) is returned, otherwise a
 *   negative error value.
 *
 * Since: 3.1.0
 *
 **/
int
gnutls_privkey_import_ncr_raw (gnutls_privkey_t pkey,
			       const gnutls_datum_t * fdata,
			       unsigned int flags)
{
  return import_ncr_key(pkey, fdata);
}

