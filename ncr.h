#ifndef L_NCR_H
#define L_NCR_H

#include <linux/types.h>
#ifndef __KERNEL__
#define __user
#include <netlink/netlink.h>
#include <string.h>
#include <stdint.h>
#else
#include <linux/netlink.h>
#endif

/* algorithms to be used by NCR_ATTR_ALGORITHM
 */
typedef enum {
	NCR_ALG_NONE,
	NCR_ALG_NULL,

	NCR_ALG_3DES_CBC,
	NCR_ALG_3DES_ECB,

	NCR_ALG_AES_ECB,
	NCR_ALG_AES_CBC,
	NCR_ALG_AES_CTR,

	NCR_ALG_CAMELIA_ECB,
	NCR_ALG_CAMELIA_CBC,
	NCR_ALG_CAMELIA_CTR,

	NCR_ALG_MD5 = 200,
	NCR_ALG_SHA1,
	NCR_ALG_SHA2_224,
	NCR_ALG_SHA2_256,
	NCR_ALG_SHA2_384,
	NCR_ALG_SHA2_512,

	NCR_ALG_HMAC_MD5 = 300,
	NCR_ALG_HMAC_SHA1,
	NCR_ALG_HMAC_SHA2_224,
	NCR_ALG_HMAC_SHA2_256,
	NCR_ALG_HMAC_SHA2_384,
	NCR_ALG_HMAC_SHA2_512,

	NCR_ALG_RSA = 600,
	NCR_ALG_DSA,
	NCR_ALG_DH,
} ncr_algorithm_t;

typedef enum {
       NCR_WALG_AES_RFC3394, /* for secret keys only */
       NCR_WALG_AES_RFC5649, /* can wrap arbitrary key */
} ncr_wrap_algorithm_t;

typedef enum {
       NCR_DERIVE_DH=1,
} ncr_derive_t;

/* Serves to make sure the structure is suitably aligned to continue with
   a struct nlattr without external padding.

   4 is NLA_ALIGNTO from <linux/netlink.h>, but if we
   included <linux/netlink.h>, the user would have to include <sys/socket.h>
   as well for no obvious reason.  "4" is fixed by ABI. */
#define __NL_ATTRIBUTES char __align[] __attribute__((aligned(4)))

/* In all ioctls, input_size specifies size of the ncr_* structure and the
   following attributes.

   output_size specifies space available for returning output, including the
   initial ncr_* structure, and is updated by the ioctl() with the space
   actually used.

   There are two special cases: input_size 0 means not attributes are supplied,
   and is treated equivalent to sizeof(struct ncr_*).  output_size 0 means no
   space for output attributes is available, and is not updated. */

/* FIXME: better names for algorithm parameters? */
/* FIXME: Split key generation/derivation attributes to decrease the number
   of attributes used for the frequent operations? */
enum {
	NCR_ATTR_UNSPEC,	/* 0 is special in lib/nlattr.c. */
	NCR_ATTR_ALGORITHM,	/* NLA_U32 <- ncr_algorithm_t */
	NCR_ATTR_DERIVATION_ALGORITHM,	/* NLA_U32 <- ncr_derive_t */
	NCR_ATTR_SIGNATURE_HASH_ALGORITHM,	/* NLA_U32 */
	NCR_ATTR_WRAPPING_ALGORITHM,	/* NLA_U32 <- ncr_wrap_algorithm_t  */
	NCR_ATTR_UPDATE_INPUT_DATA,	/* NLA_BINARY - ncr_session_input_data */
	/* NLA_BINARY - ncr_session_output_buffer */
	NCR_ATTR_UPDATE_OUTPUT_BUFFER,
	NCR_ATTR_UPDATE_INPUT_KEY_AS_DATA,	/* NLA_U32 - ncr_key_t */
	NCR_ATTR_FINAL_INPUT_DATA,	/* NLA_BINARY - ncr_session_input_data */
	/* NLA_BINARY - ncr_session_output_buffer */
	NCR_ATTR_FINAL_OUTPUT_BUFFER,
	NCR_ATTR_KEY,		/* NLA_U32 - ncr_key_t */
	NCR_ATTR_KEY_FLAGS,	/* NLA_U32 - NCR_KEY_FLAG_* */
	NCR_ATTR_KEY_ID,	/* NLA_BINARY */
	NCR_ATTR_KEY_TYPE,	/* NLA_U32 - ncr_key_type_t */
	NCR_ATTR_IV,		/* NLA_BINARY */
	NCR_ATTR_SECRET_KEY_BITS,	/* NLA_U32 */
	NCR_ATTR_RSA_MODULUS_BITS,	/* NLA_U32 */
	NCR_ATTR_RSA_E,		/* NLA_BINARY */
	NCR_ATTR_RSA_ENCODING_METHOD,	/* NLA_U32 - ncr_rsa_type_t */
	NCR_ATTR_RSA_OAEP_HASH_ALGORITHM,	/* NLA_NUL_STRING */
	NCR_ATTR_RSA_PSS_SALT_LENGTH,	/* NLA_U32 */
	NCR_ATTR_DSA_P_BITS,	/* NLA_U32 */
	NCR_ATTR_DSA_Q_BITS,	/* NLA_U32 */
	NCR_ATTR_SIGNATURE_TRANSPARENT,	/* NLA_U32 */
	NCR_ATTR_DH_PRIME,	/* NLA_BINARY */
	NCR_ATTR_DH_BASE,	/* NLA_BINARY */
	NCR_ATTR_DH_PUBLIC,	/* NLA_BINARY */
	NCR_ATTR_WANTED_ATTRS,	/* NLA_BINARY - array of u16 IDs */
	NCR_ATTR_SESSION_CLONE_FROM,	/* NLA_U32 - ncr_session_t */

	/* Add new attributes here */

	NCR_ATTR_END__,
	NCR_ATTR_MAX = NCR_ATTR_END__ - 1
};

#define NCR_CIPHER_MAX_BLOCK_LEN 32
#define NCR_HASH_MAX_OUTPUT_SIZE  64

typedef enum {
	NCR_KEY_TYPE_INVALID,
	NCR_KEY_TYPE_SECRET = 1,
	NCR_KEY_TYPE_PUBLIC = 2,
	NCR_KEY_TYPE_PRIVATE = 3,
} ncr_key_type_t;

/* Key handling
 */

typedef __s32 ncr_key_t;

#define NCR_KEY_INVALID ((ncr_key_t)-1)

#define NCR_KEY_FLAG_EXPORTABLE 1
#define NCR_KEY_FLAG_WRAPPABLE (1<<1)
/* when generating a pair the flags correspond to private
 * and public key usage is implicit. For example when private
 * key can decrypt then public key can encrypt. If private key
 * can sign then public key can verify.
 */
#define NCR_KEY_FLAG_DECRYPT (1<<2)
#define NCR_KEY_FLAG_SIGN (1<<3)
#define NCR_KEY_FLAG_ENCRYPT (1<<4)
#define NCR_KEY_FLAG_VERIFY (1<<5)
/* These flags can only be set by administrator, to prevent
 * adversaries exporting wrappable keys with random ones.
 */
#define NCR_KEY_FLAG_WRAPPING (1<<6)
#define NCR_KEY_FLAG_UNWRAPPING (1<<7)
#define NCR_KEY_FLAG_HASHABLE (1<<8)
#define NCR_KEY_FLAG_ALLOW_TRANSPARENT_HASH (1<<9)

struct ncr_key_generate {
	__u32 input_size, output_size;
	ncr_key_t key;
	 __NL_ATTRIBUTES;
};

struct ncr_key_generate_pair {
	__u32 input_size, output_size;
	ncr_key_t private_key;
	ncr_key_t public_key;
	 __NL_ATTRIBUTES;
};

typedef enum {
	RSA_PKCS1_V1_5,		/* both signatures and encryption */
	RSA_PKCS1_OAEP,		/* for encryption only */
	RSA_PKCS1_PSS,		/* for signatures only */
} ncr_rsa_type_t;

struct ncr_key_derive {
	__u32 input_size, output_size;
	ncr_key_t input_key;
	ncr_key_t new_key;
	 __NL_ATTRIBUTES;
};

#define MAX_KEY_ID_SIZE 20

struct ncr_key_get_info {
	__u32 input_size, output_size;
	ncr_key_t key;
	 __NL_ATTRIBUTES;
};

struct ncr_key_import {
	__u32 input_size, output_size;
	ncr_key_t key;
	const void __user *data;
	__u32 data_size;
	 __NL_ATTRIBUTES;
};

struct ncr_key_export {
	__u32 input_size, output_size;
	ncr_key_t key;
	void __user *buffer;
	int buffer_size;
	 __NL_ATTRIBUTES;
};

#define NCRIO_KEY_INIT _IO('c', 0xC0)
/* generate a secret key */
#define NCRIO_KEY_GENERATE _IOWR('c', 0xC1, struct ncr_key_generate)
/* generate a public key pair */
#define NCRIO_KEY_GENERATE_PAIR _IOWR('c', 0xC2, struct ncr_key_generate_pair)
/* derive a new key from an old one */
#define NCRIO_KEY_DERIVE _IOWR('c', 0xC3, struct ncr_key_derive)
/* return information on a key */
#define NCRIO_KEY_GET_INFO _IOWR('c', 0xC4, struct ncr_key_get_info)
/* export a secret key */
#define NCRIO_KEY_EXPORT _IOWR('c', 0xC5, struct ncr_key_export)
/* import a secret key */
#define NCRIO_KEY_IMPORT _IOWR('c', 0xC6, struct ncr_key_import)

#define NCRIO_KEY_DEINIT _IOW('c', 0xC7, ncr_key_t)

/* Key wrap ioctls
 */
struct ncr_key_wrap {
	__u32 input_size, output_size;
	ncr_key_t wrapping_key;
	ncr_key_t source_key;
	void __user *buffer;
	int buffer_size;
	 __NL_ATTRIBUTES;
};

struct ncr_key_unwrap {
	__u32 input_size, output_size;
	ncr_key_t wrapping_key;
	ncr_key_t dest_key;
	const void __user *data;
	__u32 data_size;
	 __NL_ATTRIBUTES;
};

#define NCRIO_KEY_WRAP _IOWR('c', 0xC8, struct ncr_key_wrap)
#define NCRIO_KEY_UNWRAP _IOWR('c', 0xC9, struct ncr_key_unwrap)

/* Internal ops  */
struct ncr_master_key_set {
	__u32 input_size, output_size;
	const void __user *key;
	__u32 key_size;
	 __NL_ATTRIBUTES;
};

#define NCRIO_MASTER_KEY_SET _IOWR('c', 0xCA, struct ncr_master_key_set)

/* These are similar to key_wrap and unwrap except that will store some extra
 * fields to be able to recover a key */
struct ncr_key_storage_wrap {
	__u32 input_size, output_size;
	ncr_key_t key;
	void __user *buffer;
	int buffer_size;
	 __NL_ATTRIBUTES;
};

struct ncr_key_storage_unwrap {
	__u32 input_size, output_size;
	ncr_key_t key;
	const void __user *data;
	__u32 data_size;
	 __NL_ATTRIBUTES;
};

#define NCRIO_KEY_STORAGE_WRAP _IOWR('c', 0xCB, struct ncr_key_storage_wrap)
#define NCRIO_KEY_STORAGE_UNWRAP _IOWR('c', 0xCC, struct ncr_key_storage_wrap)

/* Crypto Operations ioctls
 */

typedef enum {
	NCR_OP_ENCRYPT = 1,
	NCR_OP_DECRYPT,
	NCR_OP_SIGN,
	NCR_OP_VERIFY,
} ncr_crypto_op_t;

typedef __s32 ncr_session_t;
#define NCR_SESSION_INVALID ((ncr_session_t)-1)

struct ncr_session_input_data {
	const void __user *data;
	__kernel_size_t data_size;
};

struct ncr_session_output_buffer {
	void __user *buffer;
	__kernel_size_t buffer_size;
	__kernel_size_t __user *result_size_ptr;
};

struct ncr_session_init {
	__u32 input_size, output_size;
	__u32 op;		/* ncr_crypto_op_t */
	 __NL_ATTRIBUTES;
};

struct ncr_session_update {
	__u32 input_size, output_size;
	ncr_session_t ses;
	 __NL_ATTRIBUTES;
};

struct ncr_session_final {
	__u32 input_size, output_size;
	ncr_session_t ses;
	 __NL_ATTRIBUTES;
};

struct ncr_session_once {
	__u32 input_size, output_size;
	ncr_crypto_op_t op;
	 __NL_ATTRIBUTES;
};

#define NCRIO_SESSION_INIT _IOWR('c', 0xD0, struct ncr_session_init)
#define NCRIO_SESSION_UPDATE _IOWR('c', 0xD1, struct ncr_session_update)
#define NCRIO_SESSION_FINAL _IOWR('c', 0xD2, struct ncr_session_final)

/* everything in one call */
#define NCRIO_SESSION_ONCE _IOWR('c', 0xD3, struct ncr_session_once)

/* Several utility macros and functions
 */
#ifndef __KERNEL__

#define NCR_MAX_REQUEST 4096

#define NCR_STRUCT(NAME) union {			\
		struct NAME f;				\
		unsigned char space[NCR_MAX_REQUEST];	\
	}

#define NCR_INIT(STRUCT)						\
	({								\
		memset(&(STRUCT).f, 0, sizeof((STRUCT).f));		\
		(struct nlattr *)((STRUCT).space + sizeof((STRUCT).f)); \
	})

static inline void *
ncr_reserve(struct nlattr **nla_p, uint16_t type, size_t size)
{
	struct nlattr *nla, x;
	void *ptr;
	size_t total_size;

	total_size = NLA_HDRLEN + size;
	x.nla_len = total_size;
	x.nla_type = type;
	nla = *nla_p;
	memcpy(nla, &x, sizeof(x));
	ptr = nla + 1;
	*nla_p = (struct nlattr *)((char *)nla + NLA_ALIGN(total_size));
	return ptr;
}

static inline void
ncr_put(struct nlattr **nla_p, uint16_t type, const void *value, size_t size)
{
	void *ptr;

	ptr = ncr_reserve(nla_p, type, size);
	memcpy(ptr, value, size);
}

static inline void
ncr_put_u32(struct nlattr **nla_p, uint16_t type, uint32_t value)
{
	return ncr_put(nla_p, type, &value, sizeof(value));
}

static inline void
ncr_put_string(struct nlattr **nla_p, uint16_t type, const char *value)
{
	return ncr_put(nla_p, type, value, strlen(value) + 1);
}

static inline void
ncr_put_session_input_data(struct nlattr **nla_p, uint16_t type,
			   const void *data, size_t data_size)
{
	struct ncr_session_input_data *in, x;

	in = ncr_reserve(nla_p, type, sizeof(*in));
	x.data = data;
	x.data_size = data_size;
	memcpy(in, &x, sizeof(x));
}

static inline void
ncr_put_session_output_buffer(struct nlattr **nla_p, uint16_t type,
			      void *buffer, size_t buffer_size,
			      size_t *result_size_ptr)
{
	struct ncr_session_output_buffer *out, x;

	out = ncr_reserve(nla_p, type, sizeof(*out));
	x.buffer = buffer;
	x.buffer_size = buffer_size;
	x.result_size_ptr = result_size_ptr;
	memcpy(out, &x, sizeof(x));
}

#define NCR_FINISH(STRUCT, NLA) do {					\
		(STRUCT).f.input_size = (char *)nla - (char *)&(STRUCT); \
	} while (0)

#endif /* KERNEL */
#endif
