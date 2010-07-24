/*
 * Demo on how to use /dev/crypto device for HMAC.
 *
 * Placed under public domain.
 *
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "../ncr.h"
#include <stdlib.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#if GNUTLS_VERSION_NUMBER >= 0x020b00
# include <gnutls/abstract.h>
#endif

#define DATA_SIZE 4096

static void
print_hex_datum (gnutls_datum_t * dat)
{
  unsigned int j;
#define SPACE "\t"
  fprintf (stdout, "\n" SPACE);
  for (j = 0; j < dat->size; j++)
    {
      fprintf (stdout, "%.2x:", (unsigned char) dat->data[j]);
      if ((j + 1) % 15 == 0)
	fprintf (stdout, "\n" SPACE);
    }
  fprintf (stdout, "\n");
}

static void
print_dsa_pkey (gnutls_datum_t * x, gnutls_datum_t * y, gnutls_datum_t * p,
		gnutls_datum_t * q, gnutls_datum_t * g)
{
  if (x) 
    {
      fprintf (stdout, "private key:");
      print_hex_datum (x);
    }
  fprintf (stdout, "public key:");
  print_hex_datum (y);
  fprintf (stdout, "p:");
  print_hex_datum (p);
  fprintf (stdout, "q:");
  print_hex_datum (q);
  fprintf (stdout, "g:");
  print_hex_datum (g);
}

static void
print_rsa_pkey (gnutls_datum_t * m, gnutls_datum_t * e, gnutls_datum_t * d,
		gnutls_datum_t * p, gnutls_datum_t * q, gnutls_datum_t * u,
		gnutls_datum_t * exp1, gnutls_datum_t *exp2)
{
  fprintf (stdout, "modulus:");
  print_hex_datum (m);
  fprintf (stdout, "public exponent:");
  print_hex_datum (e);
  if (d) 
    {
      fprintf (stdout, "private exponent:");
      print_hex_datum (d);
      fprintf (stdout, "prime1:");
      print_hex_datum (p);
      fprintf (stdout, "prime2:");
      print_hex_datum (q);
      fprintf (stdout, "coefficient:");
      print_hex_datum (u);
      if (exp1 && exp2)
        {
          fprintf (stdout, "exp1:");
          print_hex_datum (exp1);
          fprintf (stdout, "exp2:");
          print_hex_datum (exp2);
        }
    }
}

static const char *
raw_to_string (const unsigned char *raw, size_t raw_size)
{
	static char buf[1024];
	size_t i;
	if (raw_size == 0)
		return NULL;

	if (raw_size * 3 + 1 >= sizeof (buf))
		return NULL;

	for (i = 0; i < raw_size; i++) {
		sprintf (&(buf[i * 3]), "%02X%s", raw[i],
			(i == raw_size - 1) ? "" : ":");
	}
	buf[sizeof (buf) - 1] = '\0';

	return buf;
}

int privkey_info (void* data, int data_size, int verbose)
{
	gnutls_x509_privkey_t key;
	size_t size;
	int ret;
	gnutls_datum_t der;
	unsigned char buffer[5*1024];
	const char *cprint;

	ret = gnutls_x509_privkey_init (&key);
	if (ret < 0) {
		fprintf(stderr, "error in privkey_init\n");
		return 1;
	}

	der.data = data;
	der.size = data_size;

	ret = gnutls_x509_privkey_import (key, &der, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		fprintf(stderr, "unable to import privkey\n");
		return 1;
	}

	if (verbose > 0) {
		/* Public key algorithm
		*/
		fprintf (stdout, "Public Key Info:\n");
		ret = gnutls_x509_privkey_get_pk_algorithm (key);

		fprintf (stdout, "\tPublic Key Algorithm: ");
		cprint = gnutls_pk_algorithm_get_name (ret);
		fprintf (stdout, "%s\n", cprint ? cprint : "Unknown");

		/* Print the raw public and private keys
		*/
		if (ret == GNUTLS_PK_RSA) {
			gnutls_datum_t m, e, d, p, q, u, exp1={NULL,0}, exp2={NULL,0};

#if GNUTLS_VERSION_NUMBER >= 0x020b00
			ret = gnutls_x509_privkey_export_rsa_raw2 (key, &m, &e, &d, &p, &q, &u, &exp1, &exp2);
#else
			ret = gnutls_x509_privkey_export_rsa_raw (key, &m, &e, &d, &p, &q, &u);
#endif
			if (ret < 0)
				fprintf (stderr, "Error in key RSA data export: %s\n",
					gnutls_strerror (ret));
			else {
				print_rsa_pkey (&m, &e, &d, &p, &q, &u, &exp1, &exp2);
				gnutls_free (m.data);
				gnutls_free (e.data);
				gnutls_free (d.data);
				gnutls_free (p.data);
				gnutls_free (q.data);
				gnutls_free (u.data);
				gnutls_free (exp1.data);
				gnutls_free (exp2.data);
			}
		} else if (ret == GNUTLS_PK_DSA) {
			gnutls_datum_t p, q, g, y, x;

			ret = gnutls_x509_privkey_export_dsa_raw (key, &p, &q, &g, &y, &x);
			if (ret < 0)
				fprintf (stderr, "Error in key DSA data export: %s\n",
					gnutls_strerror (ret));
			else {
				print_dsa_pkey (&x, &y, &p, &q, &g);
				gnutls_free (x.data);
				gnutls_free (y.data);
				gnutls_free (p.data);
				gnutls_free (q.data);
				gnutls_free (g.data);
			}
		}

		fprintf (stdout, "\n");

		size = sizeof (buffer);
		if ((ret = gnutls_x509_privkey_get_key_id (key, 0, buffer, &size)) < 0) {
			fprintf (stderr, "Error in key id calculation: %s\n",
			       gnutls_strerror (ret));
		} else {
			fprintf (stdout, "Public Key ID: %s\n", raw_to_string (buffer, size));
		}

		size = sizeof (buffer);
		ret = gnutls_x509_privkey_export (key, GNUTLS_X509_FMT_PEM, buffer, &size);
		if (ret < 0) {
			fprintf(stderr, "Error in privkey_export\n");
			return 1;
		}

		fprintf (stdout, "\n%s\n", buffer);
	}

	gnutls_x509_privkey_deinit (key);
	
	return 0;
}



int pubkey_info(void* data, int data_size, int verbose)
{
#if GNUTLS_VERSION_NUMBER >= 0x020b00
	gnutls_pubkey_t key;
	size_t size;
	int ret;
	gnutls_datum_t der;
	unsigned char buffer[5*1024];
	const char *cprint;

	ret = gnutls_pubkey_init (&key);
	if (ret < 0) {
		fprintf(stderr, "error in pubkey_init\n");
		return 1;
	}

	der.data = data;
	der.size = data_size;

	ret = gnutls_pubkey_import (key, &der, GNUTLS_X509_FMT_DER);
	if (ret < 0) {
		fprintf(stderr, "unable to import pubkey\n");
		return 1;
	}

	if (verbose > 0) {
		/* Public key algorithm
		*/
		fprintf (stdout, "Public Key Info:\n");
		ret = gnutls_pubkey_get_pk_algorithm (key, NULL);

		fprintf (stdout, "\tPublic Key Algorithm: ");
		cprint = gnutls_pk_algorithm_get_name (ret);
		fprintf (stdout, "%s\n", cprint ? cprint : "Unknown");

		/* Print the raw public and private keys
		*/
		if (ret == GNUTLS_PK_RSA) {
			gnutls_datum_t m, e;

			ret = gnutls_pubkey_get_pk_rsa_raw (key, &m, &e);
			if (ret < 0)
				fprintf (stderr, "Error in key RSA data export: %s\n",
					gnutls_strerror (ret));
			else {
				print_rsa_pkey (&m, &e, NULL, NULL, NULL, NULL, NULL, NULL);
				gnutls_free (m.data);
				gnutls_free (e.data);
			}
		} else if (ret == GNUTLS_PK_DSA) {
			gnutls_datum_t p, q, g, y;

			ret = gnutls_pubkey_get_pk_dsa_raw (key, &p, &q, &g, &y);
			if (ret < 0)
				fprintf (stderr, "Error in key DSA data export: %s\n",
					gnutls_strerror (ret));
			else {
				print_dsa_pkey (NULL, &y, &p, &q, &g);
				gnutls_free (y.data);
				gnutls_free (p.data);
				gnutls_free (q.data);
				gnutls_free (g.data);
			}
		}

		fprintf (stdout, "\n");

		size = sizeof (buffer);
		if ((ret = gnutls_pubkey_get_key_id (key, 0, buffer, &size)) < 0) {
			fprintf (stderr, "Error in key id calculation: %s\n",
			       gnutls_strerror (ret));
		} else {
			fprintf (stdout, "Public Key ID: %s\n", raw_to_string (buffer, size));
		}

		size = sizeof (buffer);
		ret = gnutls_pubkey_export (key, GNUTLS_X509_FMT_PEM, buffer, &size);
		if (ret < 0) {
			fprintf(stderr, "Error in privkey_export\n");
			return 1;
		}

		fprintf (stdout, "\n%s\n", buffer);
	}

	gnutls_pubkey_deinit (key);
#endif
	return 0;
}

static int data_get(int cfd, ncr_data_t dd, void* data, size_t data_size)
{
struct ncr_data_st kdata;

	memset(&kdata, 0, sizeof(kdata));
	kdata.desc = dd;
	kdata.data = data;
	kdata.data_size = data_size;

	if (ioctl(cfd, NCRIO_DATA_GET, &kdata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_GET)");
		return -1;
	}

	return 0;
}

#define RSA_ENCRYPT_SIZE 32

static int rsa_key_encrypt(int cfd, ncr_key_t privkey, ncr_key_t pubkey, int oaep)
{
	struct ncr_data_init_st dinit;
	ncr_data_t datad;
	ncr_data_t encd;
	struct ncr_session_once_op_st nop;
	uint8_t data[DATA_SIZE];
	uint8_t vdata[RSA_ENCRYPT_SIZE];
	int ret;

	fprintf(stdout, "Tests on RSA (%s) key encryption:", (oaep!=0)?"OAEP":"PKCS V1.5");
	fflush(stdout);

	memset(data, 0x3, sizeof(data));
	memset(vdata, 0x0, sizeof(vdata));

	/* data to sign */
	memset(&dinit, 0, sizeof(dinit));
	dinit.max_object_size = DATA_SIZE;
	dinit.flags = NCR_DATA_FLAG_EXPORTABLE;
	dinit.initial_data = data;
	dinit.initial_data_size = RSA_ENCRYPT_SIZE;

	if (ioctl(cfd, NCRIO_DATA_INIT, &dinit)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_INIT)");
		return 1;
	}
	
	datad = dinit.desc;

	memset(&dinit, 0, sizeof(dinit));
	dinit.max_object_size = DATA_SIZE;
	dinit.flags = NCR_DATA_FLAG_EXPORTABLE;

	if (ioctl(cfd, NCRIO_DATA_INIT, &dinit)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_INIT)");
		return 1;
	}

	encd = dinit.desc;

	/* do encryption */
	memset(&nop, 0, sizeof(nop));
	nop.init.algorithm = NCR_ALG_RSA;
	nop.init.key = pubkey;
	if (oaep) {
		nop.init.params.params.rsa.type = RSA_PKCS1_OAEP;
		nop.init.params.params.rsa.oaep_hash = NCR_ALG_SHA1;
	} else {
		nop.init.params.params.rsa.type = RSA_PKCS1_V1_5;
	}
	nop.init.op = NCR_OP_ENCRYPT;
	nop.op.data.ndata.input = datad;
	nop.op.data.ndata.output = encd;
	nop.op.type = NCR_DATA;

	if (ioctl(cfd, NCRIO_SESSION_ONCE, &nop)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_SESSION_ONCE)");
		return 1;
	}

	/* decrypt data */
	memset(&nop, 0, sizeof(nop));
	nop.init.algorithm = NCR_ALG_RSA;
	nop.init.key = privkey;
	nop.init.op = NCR_OP_DECRYPT;
	if (oaep) {
		nop.init.params.params.rsa.type = RSA_PKCS1_OAEP;
		nop.init.params.params.rsa.oaep_hash = NCR_ALG_SHA1;
	} else {
		nop.init.params.params.rsa.type = RSA_PKCS1_V1_5;
	}
	nop.op.data.ndata.input = encd;
	nop.op.data.ndata.output = encd;
	nop.op.type = NCR_DATA;

	if (ioctl(cfd, NCRIO_SESSION_ONCE, &nop)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_SESSION_ONCE)");
		return 1;
	}
	
	ret = data_get(cfd, encd, vdata, sizeof(vdata));
	if (ret < 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}
	
	if (memcmp(vdata, data, sizeof(vdata)) != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		fprintf(stderr, "Decrypted data do not match!\n");
		return 1;
	}

	fprintf(stdout, " Success\n");

	return 0;

}

static int rsa_key_sign_verify(int cfd, ncr_key_t privkey, ncr_key_t pubkey, int pss)
{
	struct ncr_data_init_st dinit;
	ncr_data_t datad;
	ncr_data_t signd;
	struct ncr_session_once_op_st nop;
	uint8_t data[DATA_SIZE];

	fprintf(stdout, "Tests on RSA (%s) key signature:", (pss!=0)?"PSS":"PKCS V1.5");
	fflush(stdout);

	memset(data, 0x3, sizeof(data));

	/* data to sign */
	memset(&dinit, 0, sizeof(dinit));
	dinit.max_object_size = DATA_SIZE;
	dinit.flags = NCR_DATA_FLAG_EXPORTABLE;
	dinit.initial_data = data;
	dinit.initial_data_size = sizeof(data);

	if (ioctl(cfd, NCRIO_DATA_INIT, &dinit)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_INIT)");
		return 1;
	}
	
	datad = dinit.desc;

	memset(&dinit, 0, sizeof(dinit));
	dinit.max_object_size = DATA_SIZE;
	dinit.flags = NCR_DATA_FLAG_EXPORTABLE;

	if (ioctl(cfd, NCRIO_DATA_INIT, &dinit)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_INIT)");
		return 1;
	}
	
	signd = dinit.desc;

	/* sign datad */
	memset(&nop, 0, sizeof(nop));
	nop.init.algorithm = NCR_ALG_RSA;
	nop.init.key = privkey;
	nop.init.params.params.rsa.type = (pss!=0)?RSA_PKCS1_PSS:RSA_PKCS1_V1_5;
	nop.init.params.params.rsa.sign_hash = NCR_ALG_SHA1;

	nop.init.op = NCR_OP_SIGN;
	nop.op.data.ndata.input = datad;
	nop.op.data.ndata.output = signd;
	nop.op.type = NCR_DATA;

	if (ioctl(cfd, NCRIO_SESSION_ONCE, &nop)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_SESSION_ONCE)");
		return 1;
	}

	/* verify signature */
	memset(&nop, 0, sizeof(nop));
	nop.init.algorithm = NCR_ALG_RSA;
	nop.init.key = pubkey;
	nop.init.params.params.rsa.type = (pss!=0)?RSA_PKCS1_PSS:RSA_PKCS1_V1_5;
	nop.init.params.params.rsa.sign_hash = NCR_ALG_SHA1;

	nop.init.op = NCR_OP_VERIFY;
	nop.op.data.ndata.input = datad;
	nop.op.data.ndata.output = signd;
	nop.op.type = NCR_DATA;

	if (ioctl(cfd, NCRIO_SESSION_ONCE, &nop)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_SESSION_ONCE)");
		return 1;
	}

	fprintf(stdout, " Success\n");

	return 0;

}

static int dsa_key_sign_verify(int cfd, ncr_key_t privkey, ncr_key_t pubkey)
{
	struct ncr_data_init_st dinit;
	ncr_data_t datad;
	ncr_data_t signd;
	struct ncr_session_once_op_st nop;
	uint8_t data[DATA_SIZE];

	fprintf(stdout, "Tests on DSA key signature:");
	fflush(stdout);

	memset(data, 0x3, sizeof(data));

	/* data to sign */
	memset(&dinit, 0, sizeof(dinit));
	dinit.max_object_size = DATA_SIZE;
	dinit.flags = NCR_DATA_FLAG_EXPORTABLE;
	dinit.initial_data = data;
	dinit.initial_data_size = sizeof(data);

	if (ioctl(cfd, NCRIO_DATA_INIT, &dinit)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_INIT)");
		return 1;
	}
	
	datad = dinit.desc;

	memset(&dinit, 0, sizeof(dinit));
	dinit.max_object_size = DATA_SIZE;
	dinit.flags = NCR_DATA_FLAG_EXPORTABLE;

	if (ioctl(cfd, NCRIO_DATA_INIT, &dinit)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_INIT)");
		return 1;
	}
	
	signd = dinit.desc;

	/* sign datad */
	memset(&nop, 0, sizeof(nop));
	nop.init.algorithm = NCR_ALG_DSA;
	nop.init.key = privkey;
	nop.init.params.params.dsa.sign_hash = NCR_ALG_SHA1;

	nop.init.op = NCR_OP_SIGN;
	nop.op.data.ndata.input = datad;
	nop.op.data.ndata.output = signd;
	nop.op.type = NCR_DATA;

	if (ioctl(cfd, NCRIO_SESSION_ONCE, &nop)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_SESSION_ONCE)");
		return 1;
	}

	/* verify signature */
	memset(&nop, 0, sizeof(nop));
	nop.init.algorithm = NCR_ALG_DSA;
	nop.init.key = pubkey;
	nop.init.params.params.dsa.sign_hash = NCR_ALG_SHA1;

	nop.init.op = NCR_OP_VERIFY;
	nop.op.data.ndata.input = datad;
	nop.op.data.ndata.output = signd;
	nop.op.type = NCR_DATA;

	if (ioctl(cfd, NCRIO_SESSION_ONCE, &nop)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_SESSION_ONCE)");
		return 1;
	}

	fprintf(stdout, " Success\n");

	return 0;

}


static int test_ncr_rsa(int cfd)
{
	int ret;
	struct ncr_data_init_st dinit;
	struct ncr_key_generate_st kgen;
	ncr_key_t pubkey, privkey;
	struct ncr_key_data_st keydata;
	struct ncr_data_st kdata;
	uint8_t data[DATA_SIZE];

	fprintf(stdout, "Tests on RSA key generation:");
	fflush(stdout);

	/* convert it to key */
	if (ioctl(cfd, NCRIO_KEY_INIT, &privkey)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	if (ioctl(cfd, NCRIO_KEY_INIT, &pubkey)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	memset(&kgen, 0, sizeof(kgen));
	kgen.desc = privkey;
	kgen.desc2 = pubkey;
	kgen.params.algorithm = NCR_ALG_RSA;
	kgen.params.keyflags = NCR_KEY_FLAG_EXPORTABLE|NCR_KEY_FLAG_WRAPPABLE;
	kgen.params.params.rsa.bits = 1024;

	if (ioctl(cfd, NCRIO_KEY_GENERATE_PAIR, &kgen)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_GENERATE_PAIR)");
		return 1;
	}

	/* export the private key */
	dinit.max_object_size = DATA_SIZE;
	dinit.flags = NCR_DATA_FLAG_EXPORTABLE;
	dinit.initial_data = NULL;
	dinit.initial_data_size = 0;

	if (ioctl(cfd, NCRIO_DATA_INIT, &dinit)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_INIT)");
		return 1;
	}
	
	memset(&keydata, 0, sizeof(keydata));
	keydata.key = privkey;
	keydata.data = dinit.desc;

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_EXPORT)");
		return 1;
	}

	/* now read data */
	memset(data, 0, sizeof(data));

	kdata.desc = dinit.desc;
	kdata.data = data;
	kdata.data_size = sizeof(data);

	if (ioctl(cfd, NCRIO_DATA_GET, &kdata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_GET)");
		return 1;
	}

	ret = privkey_info(kdata.data, kdata.data_size, 0);
	if (ret != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}
	
	/* export the public key */

	memset(&keydata, 0, sizeof(keydata));
	keydata.key = pubkey;
	keydata.data = dinit.desc;

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

	/* now read data */
	memset(data, 0, sizeof(data));

	kdata.desc = dinit.desc;
	kdata.data = data;
	kdata.data_size = sizeof(data);

	if (ioctl(cfd, NCRIO_DATA_GET, &kdata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_GET)");
		return 1;
	}
	
	ret = pubkey_info(kdata.data, kdata.data_size, 0);
	if (ret != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}

	fprintf(stdout, " Success\n");

	ret = rsa_key_sign_verify(cfd, privkey, pubkey, 0);
	if (ret != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}

	ret = rsa_key_sign_verify(cfd, privkey, pubkey, 1);
	if (ret != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}

	ret = rsa_key_encrypt(cfd, privkey, pubkey, 0);
	if (ret != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}

	ret = rsa_key_encrypt(cfd, privkey, pubkey, 1);
	if (ret != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}

	return 0;

}

static int test_ncr_dsa(int cfd)
{
	int ret;
	struct ncr_data_init_st dinit;
	struct ncr_key_generate_st kgen;
	ncr_key_t pubkey, privkey;
	struct ncr_key_data_st keydata;
	struct ncr_data_st kdata;
	uint8_t data[DATA_SIZE];

	fprintf(stdout, "Tests on DSA key generation:");
	fflush(stdout);

	/* convert it to key */
	if (ioctl(cfd, NCRIO_KEY_INIT, &privkey)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	if (ioctl(cfd, NCRIO_KEY_INIT, &pubkey)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_INIT)");
		return 1;
	}

	memset(&kgen, 0, sizeof(kgen));
	kgen.desc = privkey;
	kgen.desc2 = pubkey;
	kgen.params.algorithm = NCR_ALG_DSA;
	kgen.params.keyflags = NCR_KEY_FLAG_EXPORTABLE|NCR_KEY_FLAG_WRAPPABLE;
	kgen.params.params.dsa.q_bits = 160;
	kgen.params.params.dsa.p_bits = 1024;

	if (ioctl(cfd, NCRIO_KEY_GENERATE_PAIR, &kgen)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_GENERATE_PAIR)");
		return 1;
	}

	/* export the private key */
	dinit.max_object_size = DATA_SIZE;
	dinit.flags = NCR_DATA_FLAG_EXPORTABLE;
	dinit.initial_data = NULL;
	dinit.initial_data_size = 0;

	if (ioctl(cfd, NCRIO_DATA_INIT, &dinit)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_INIT)");
		return 1;
	}
	
	memset(&keydata, 0, sizeof(keydata));
	keydata.key = privkey;
	keydata.data = dinit.desc;

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_EXPORT)");
		return 1;
	}

	/* now read data */
	memset(data, 0, sizeof(data));

	kdata.desc = dinit.desc;
	kdata.data = data;
	kdata.data_size = sizeof(data);

	if (ioctl(cfd, NCRIO_DATA_GET, &kdata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_GET)");
		return 1;
	}

	ret = privkey_info(kdata.data, kdata.data_size, 0);
	if (ret != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}
	
	/* export the public key */

	memset(&keydata, 0, sizeof(keydata));
	keydata.key = pubkey;
	keydata.data = dinit.desc;

	if (ioctl(cfd, NCRIO_KEY_EXPORT, &keydata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_KEY_IMPORT)");
		return 1;
	}

	/* now read data */
	memset(data, 0, sizeof(data));

	kdata.desc = dinit.desc;
	kdata.data = data;
	kdata.data_size = sizeof(data);

	if (ioctl(cfd, NCRIO_DATA_GET, &kdata)) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		perror("ioctl(NCRIO_DATA_GET)");
		return 1;
	}
	
	ret = pubkey_info(kdata.data, kdata.data_size, 0);
	if (ret != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}

	fprintf(stdout, " Success\n");

	ret = dsa_key_sign_verify(cfd, privkey, pubkey);
	if (ret != 0) {
		fprintf(stderr, "Error: %s:%d\n", __func__, __LINE__);
		return 1;
	}

	return 0;

}


int
main()
{
	int fd = -1;

	gnutls_global_init();

	/* actually test if the initial close
	 * will really delete all used lists */

	fd = open("/dev/crypto", O_RDWR, 0);
	if (fd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}

	if (test_ncr_rsa(fd))
		return 1;

	if (test_ncr_dsa(fd))
		return 1;

	/* Close the original descriptor */
	if (close(fd)) {
		perror("close(fd)");
		return 1;
	}

	return 0;
}
