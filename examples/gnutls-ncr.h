/* This file provides functions to use NCR with GnuTLS 3.1.
 *
 * It provides gnutls_privkey_import_ncr_raw() to import an NCR
 * stored file as a gnutls_privkey_t.
 */

int
gnutls_privkey_import_ncr_raw (gnutls_privkey_t pkey,
			       const gnutls_datum_t * fdata,
			       unsigned int flags);
