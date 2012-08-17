/* ---- NUMBER THEORY ---- */

struct algo_properties_st;

enum {
	PK_PUBLIC = 0,
	PK_PRIVATE = 1
};

enum {
	PKA_RSA,
	PKA_DSA
};

typedef struct Oid {
	unsigned long OID[16];
    /** Length of DER encoding */
	unsigned long OIDlen;
} oid_st;

int pk_get_oid(const struct algo_properties_st *pk, oid_st * st);
int rand_prime(mp_int * N, long len);

/* ---- RSA ---- */
#ifdef LTC_MRSA

/* Min and Max RSA key sizes (in bits) */
#define MIN_RSA_SIZE 1024
#define MAX_RSA_SIZE 8192

/** RSA LTC_PKCS style key */
typedef struct Rsa_key {
    /** Type of key, PK_PRIVATE or PK_PUBLIC */
	int type;
    /** The public exponent */
	mp_int e;
    /** The private exponent */
	mp_int d;
    /** The modulus */
	mp_int N;
    /** The p factor of N */
	mp_int p;
    /** The q factor of N */
	mp_int q;
    /** The 1/q mod p CRT param */
	mp_int qP;
    /** The d mod (p - 1) CRT param */
	mp_int dP;
    /** The d mod (q - 1) CRT param */
	mp_int dQ;
} rsa_key;

int rsa_make_key(int size, long e, rsa_key * key);

int rsa_exptmod(const unsigned char *in, unsigned long inlen,
		unsigned char *out, unsigned long *outlen, int which,
		rsa_key * key);

void rsa_free(rsa_key * key);

/* These use LTC_PKCS #1 v2.0 padding */
#define rsa_encrypt_key(_in, _inlen, _out, _outlen, _lparam, _lparamlen, _hash, _key) \
  rsa_encrypt_key_ex(_in, _inlen, _out, _outlen, _lparam, _lparamlen, _hash, LTC_LTC_PKCS_1_OAEP, _key)

#define rsa_decrypt_key(_in, _inlen, _out, _outlen, _lparam, _lparamlen, _hash, _stat, _key) \
  rsa_decrypt_key_ex(_in, _inlen, _out, _outlen, _lparam, _lparamlen, _hash, LTC_LTC_PKCS_1_OAEP, _stat, _key)

#define rsa_sign_hash(_in, _inlen, _out, _outlen, _hash, _saltlen, _key) \
  rsa_sign_hash_ex(_in, _inlen, _out, _outlen, LTC_LTC_PKCS_1_PSS, _hash, _saltlen, _key)

int rsa_sign_raw(const unsigned char *in, unsigned long inlen,
 	         unsigned char *out, unsigned long *outlen,
		 rsa_key * key);

#define rsa_verify_hash(_sig, _siglen, _hash, _hashlen, _hash_algo, _saltlen, _stat, _key) \
  rsa_verify_hash_ex(_sig, _siglen, _hash, _hashlen, LTC_LTC_PKCS_1_PSS, _hash_algo, _saltlen, _stat, _key)

/* These can be switched between LTC_PKCS #1 v2.x and LTC_PKCS #1 v1.5 paddings */
int rsa_encrypt_key_ex(const unsigned char *in, unsigned long inlen,
		       unsigned char *out, unsigned long *outlen,
		       const unsigned char *lparam, unsigned long lparamlen,
		       const struct algo_properties_st *hash, int padding,
		       rsa_key * key);

int rsa_decrypt_key_ex(const unsigned char *in, unsigned long inlen,
		       unsigned char *out, unsigned long *outlen,
		       const unsigned char *lparam, unsigned long lparamlen,
		       const struct algo_properties_st *hash, int padding,
		       int *stat, rsa_key * key);

int rsa_sign_hash_ex(const unsigned char *in, unsigned long inlen,
		     unsigned char *out, unsigned long *outlen,
		     int padding,
		     const struct algo_properties_st *hash,
		     unsigned long saltlen, rsa_key * key);

int rsa_verify_hash_ex(const unsigned char *sig, unsigned long siglen,
		       const unsigned char *hash, unsigned long hashlen,
		       int padding,
		       const struct algo_properties_st *hash_algo,
		       unsigned long saltlen, int *stat, rsa_key * key);

/* LTC_PKCS #1 import/export */
int rsa_export(unsigned char *out, unsigned long *outlen, int type,
	       rsa_key * key);
int rsa_import(const unsigned char *in, unsigned long inlen, rsa_key * key);

#endif

#ifdef LTC_MDSA

/* Max diff between group and modulus size in bytes */
#define LTC_MDSA_DELTA     512

/* Max DSA group size in bytes (default allows 4k-bit groups) */
#define LTC_MDSA_MAX_GROUP 512

/** DSA key structure */
typedef struct {
   /** The key type, PK_PRIVATE or PK_PUBLIC */
	int type;

   /** The order of the sub-group used in octets */
	int qord;

   /** The generator  */
	mp_int g;

   /** The prime used to generate the sub-group */
	mp_int q;

   /** The large prime that generats the field the contains the sub-group */
	mp_int p;

   /** The private key */
	mp_int x;

   /** The public key */
	mp_int y;
} dsa_key;

int dsa_make_key(int group_size, int modulus_size, dsa_key * key);
void dsa_free(dsa_key * key);

int dsa_sign_hash_raw(const unsigned char *in, unsigned long inlen,
		      mp_int_t r, mp_int_t s, dsa_key * key);

int dsa_sign_hash(const unsigned char *in, unsigned long inlen,
		  unsigned char *out, unsigned long *outlen, dsa_key * key);

int dsa_verify_hash_raw(mp_int_t r, mp_int_t s,
			const unsigned char *hash, unsigned long hashlen,
			int *stat, dsa_key * key);

int dsa_verify_hash(const unsigned char *sig, unsigned long siglen,
		    const unsigned char *hash, unsigned long hashlen,
		    int *stat, dsa_key * key);

int dsa_encrypt_key(const unsigned char *in, unsigned long inlen,
		    unsigned char *out, unsigned long *outlen,
		    int hash, dsa_key * key);

int dsa_decrypt_key(const unsigned char *in, unsigned long inlen,
		    unsigned char *out, unsigned long *outlen, dsa_key * key);

int dsa_import(const unsigned char *in, unsigned long inlen, dsa_key * key);
int dsa_export(unsigned char *out, unsigned long *outlen, int type,
	       dsa_key * key);
int dsa_verify_key(dsa_key * key, int *stat);

int dsa_shared_secret(void *private_key, mp_int_t base,
		      dsa_key * public_key,
		      unsigned char *out, unsigned long *outlen);
#endif

#ifdef LTC_DER
/* DER handling */

enum {
	LTC_ASN1_EOL,
	LTC_ASN1_BOOLEAN,
	LTC_ASN1_INTEGER,
	LTC_ASN1_SHORT_INTEGER,
	LTC_ASN1_BIT_STRING,
	LTC_ASN1_OCTET_STRING,
	LTC_ASN1_NULL,
	LTC_ASN1_OBJECT_IDENTIFIER,
	LTC_ASN1_IA5_STRING,
	LTC_ASN1_PRINTABLE_STRING,
	LTC_ASN1_UTF8_STRING,
	LTC_ASN1_UTCTIME,
	LTC_ASN1_CHOICE,
	LTC_ASN1_SEQUENCE,
	LTC_ASN1_SET,
	LTC_ASN1_SETOF
};

/** A LTC ASN.1 list type */
typedef struct ltc_asn1_list_ {
   /** The LTC ASN.1 enumerated type identifier */
	int type;
   /** The data to encode or place for decoding */
	void *data;
   /** The size of the input or resulting output */
	unsigned long size;
   /** The used flag, this is used by the CHOICE ASN.1 type to indicate which choice was made */
	int used;
   /** prev/next entry in the list */
	struct ltc_asn1_list_ *prev, *next, *child, *parent;
} ltc_asn1_list;

#define LTC_SET_ASN1(list, index, Type, Data, Size)  \
   do {                                              \
      int LTC_MACRO_temp            = (index);       \
      ltc_asn1_list *LTC_MACRO_list = (list);        \
      LTC_MACRO_list[LTC_MACRO_temp].type = (Type);  \
      LTC_MACRO_list[LTC_MACRO_temp].data = (void*)(Data);  \
      LTC_MACRO_list[LTC_MACRO_temp].size = (Size);  \
      LTC_MACRO_list[LTC_MACRO_temp].used = 0;       \
   } while (0);

/* SEQUENCE */
int der_encode_sequence_ex(ltc_asn1_list * list, unsigned long inlen,
			   unsigned char *out, unsigned long *outlen,
			   int type_of);

#define der_encode_sequence(list, inlen, out, outlen) der_encode_sequence_ex(list, inlen, out, outlen, LTC_ASN1_SEQUENCE)

int der_decode_sequence_ex(const unsigned char *in, unsigned long inlen,
			   ltc_asn1_list * list, unsigned long outlen,
			   int ordered);

#define der_decode_sequence(in, inlen, list, outlen) der_decode_sequence_ex(in, inlen, list, outlen, 1)

int der_length_sequence(ltc_asn1_list * list, unsigned long inlen,
			unsigned long *outlen);

/* SUBJECT PUBLIC KEY INFO */
int der_encode_subject_public_key_info(unsigned char *out,
				       unsigned long *outlen,
				       const struct algo_properties_st *algorithm, void *public_key,
				       unsigned long public_key_len,
				       unsigned long parameters_type,
				       void *parameters,
				       unsigned long parameters_len);

int der_decode_subject_public_key_info(const unsigned char *in,
				       unsigned long inlen,
				       const struct algo_properties_st *algorithm, void *public_key,
				       unsigned long *public_key_len,
				       unsigned long parameters_type,
				       ltc_asn1_list * parameters,
				       unsigned long parameters_len);

/* SET */
#define der_decode_set(in, inlen, list, outlen) der_decode_sequence_ex(in, inlen, list, outlen, 0)
#define der_length_set der_length_sequence
int der_encode_set(ltc_asn1_list * list, unsigned long inlen,
		   unsigned char *out, unsigned long *outlen);

int der_encode_setof(ltc_asn1_list * list, unsigned long inlen,
		     unsigned char *out, unsigned long *outlen);

/* VA list handy helpers with triplets of <type, size, data> */
int der_encode_sequence_multi(unsigned char *out, unsigned long *outlen, ...);
int der_decode_sequence_multi(const unsigned char *in, unsigned long inlen,
			      ...);

/* FLEXI DECODER handle unknown list decoder */
int der_decode_sequence_flexi(const unsigned char *in, unsigned long *inlen,
			      ltc_asn1_list ** out);
void der_free_sequence_flexi(ltc_asn1_list * list);
void der_sequence_free(ltc_asn1_list * in);

/* BOOLEAN */
int der_length_boolean(unsigned long *outlen);
int der_encode_boolean(int in, unsigned char *out, unsigned long *outlen);
int der_decode_boolean(const unsigned char *in, unsigned long inlen, int *out);
/* INTEGER */
int der_encode_integer(mp_int_t num, unsigned char *out, unsigned long *outlen);
int der_decode_integer(const unsigned char *in, unsigned long inlen,
		       mp_int_t num);
int der_length_integer(mp_int_t num, unsigned long *len);

/* INTEGER -- handy for 0..2^32-1 values */
int der_decode_short_integer(const unsigned char *in, unsigned long inlen,
			     unsigned long *num);
int der_encode_short_integer(unsigned long num, unsigned char *out,
			     unsigned long *outlen);
int der_length_short_integer(unsigned long num, unsigned long *outlen);

/* BIT STRING */
int der_encode_bit_string(const unsigned char *in, unsigned long inlen,
			  unsigned char *out, unsigned long *outlen);
int der_decode_bit_string(const unsigned char *in, unsigned long inlen,
			  unsigned char *out, unsigned long *outlen);
int der_length_bit_string(unsigned long nbits, unsigned long *outlen);

/* OCTET STRING */
int der_encode_octet_string(const unsigned char *in, unsigned long inlen,
			    unsigned char *out, unsigned long *outlen);
int der_decode_octet_string(const unsigned char *in, unsigned long inlen,
			    unsigned char *out, unsigned long *outlen);
int der_length_octet_string(unsigned long noctets, unsigned long *outlen);

/* OBJECT IDENTIFIER */
int der_encode_object_identifier(unsigned long *words, unsigned long nwords,
				 unsigned char *out, unsigned long *outlen);
int der_decode_object_identifier(const unsigned char *in, unsigned long inlen,
				 unsigned long *words, unsigned long *outlen);
int der_length_object_identifier(unsigned long *words, unsigned long nwords,
				 unsigned long *outlen);
unsigned long der_object_identifier_bits(unsigned long x);

/* IA5 STRING */
int der_encode_ia5_string(const unsigned char *in, unsigned long inlen,
			  unsigned char *out, unsigned long *outlen);
int der_decode_ia5_string(const unsigned char *in, unsigned long inlen,
			  unsigned char *out, unsigned long *outlen);
int der_length_ia5_string(const unsigned char *octets, unsigned long noctets,
			  unsigned long *outlen);

int der_ia5_char_encode(int c);
int der_ia5_value_decode(int v);

/* Printable STRING */
int der_encode_printable_string(const unsigned char *in, unsigned long inlen,
				unsigned char *out, unsigned long *outlen);
int der_decode_printable_string(const unsigned char *in, unsigned long inlen,
				unsigned char *out, unsigned long *outlen);
int der_length_printable_string(const unsigned char *octets,
				unsigned long noctets, unsigned long *outlen);

int der_printable_char_encode(int c);
int der_printable_value_decode(int v);

/* UTF-8 */

int der_encode_utf8_string(const wchar_t * in, unsigned long inlen,
			   unsigned char *out, unsigned long *outlen);

int der_decode_utf8_string(const unsigned char *in, unsigned long inlen,
			   wchar_t * out, unsigned long *outlen);
unsigned long der_utf8_charsize(const wchar_t c);
int der_length_utf8_string(const wchar_t * in, unsigned long noctets,
			   unsigned long *outlen);

/* CHOICE */
int der_decode_choice(const unsigned char *in, unsigned long *inlen,
		      ltc_asn1_list * list, unsigned long outlen);

/* UTCTime */
typedef struct {
	unsigned YY,		/* year */
	 MM,			/* month */
	 DD,			/* day */
	 hh,			/* hour */
	 mm,			/* minute */
	 ss,			/* second */
	 off_dir,		/* timezone offset direction 0 == +, 1 == - */
	 off_hh,		/* timezone offset hours */
	 off_mm;		/* timezone offset minutes */
} ltc_utctime;

int der_encode_utctime(ltc_utctime * utctime,
		       unsigned char *out, unsigned long *outlen);

int der_decode_utctime(const unsigned char *in, unsigned long *inlen,
		       ltc_utctime * out);

int der_length_utctime(ltc_utctime * utctime, unsigned long *outlen);

#endif

/* $Source: /cvs/libtom/libtomcrypt/src/headers/tomcrypt_pk.h,v $ */
/* $Revision: 1.81 $ */
/* $Date: 2007/05/12 14:32:35 $ */
