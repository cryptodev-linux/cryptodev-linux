#ifndef L_NCR_H
#define L_NCR_H

#ifndef __KERNEL__
#include <inttypes.h>
#endif

typedef enum {
	NCR_ALG_3DES_CBC=2,
	NCR_ALG_AES_CBC,
	NCR_ALG_CAMELLIA_CBC,
	NCR_ALG_ARCFOUR,

	NCR_ALG_SHA1=40,
	NCR_ALG_MD5,
	NCR_ALG_SHA2_224,
	NCR_ALG_SHA2_256,
	NCR_ALG_SHA2_384,
	NCR_ALG_SHA2_512,

	NCR_ALG_HMAC_SHA1=80,
	NCR_ALG_HMAC_MD5,
	NCR_ALG_HMAC_SHA2_224,
	NCR_ALG_HMAC_SHA2_256,
	NCR_ALG_HMAC_SHA2_384,
	NCR_ALG_HMAC_SHA2_512,
} ncr_algorithm_t;


typedef enum {
	NCR_KEY_TYPE_SECRET=1,
	NCR_KEY_TYPE_PUBLIC=2,
	NCR_KEY_TYPE_PRIVATE=3,
} ncr_key_type_t;

/* Data Handling
 */
#define NCR_DATA_FLAG_EXPORTABLE 1
#define NCR_DATA_FLAG_SIGN_ONLY 2 /* this object can only be used with hash/sign operations */

typedef int ncr_data_t;
#define NCR_DATA_INVALID (ncr_data_t)(-1)

struct ncr_data_init_st {
	ncr_data_t desc;
	size_t max_object_size;
	unsigned int flags;
	void* initial_data; /* can be null */
	size_t initial_data_size;
};

struct ncr_data_st {
	ncr_data_t desc;
	void* data;
	size_t data_size; /* rw in get */
	unsigned int append_flag; /* only when used with NCRIO_DATA_SET */
};

#define NCRIO_DATA_INIT         _IOWR('c', 200, struct ncr_data_init_st)
#define NCRIO_DATA_GET         _IOWR('c', 201, struct ncr_data_st)
#define NCRIO_DATA_SET         _IOR('c', 202, struct ncr_data_st)
#define NCRIO_DATA_DEINIT         _IOR('c', 203, ncr_data_t)

/* Key handling
 */

typedef int ncr_key_t;

#define NCR_KEY_INVALID (ncr_key_t)(-1)

#define NCR_KEY_FLAG_EXPORTABLE 1
#define NCR_KEY_FLAG_WRAPPABLE (1<<1)
/* when generating a pair the flags correspond to private
 * and public key usage is implicit. For example when private
 * key can decrypt then public key can encrypt. If private key
 * can sign then public key can verify.
 */
#define NCR_KEY_FLAG_DECRYPT (1<<2)
#define NCR_KEY_FLAG_SIGN (1<<3)

struct ncr_key_generate_params_st {
	ncr_algorithm_t algorithm;
	unsigned int keyflags;
	union {
		struct {
			unsigned int bits;
		} cipher;
		struct {
			unsigned int bits;
			void* e;
			size_t e_size;
		} rsa;		
		struct {
			unsigned int bits;
		} dsa;
		struct {
			unsigned int bits;
		} dh;
	} params;
};

/* used in generation
 */
struct ncr_key_generate_st {
	ncr_key_t desc;
	ncr_key_t desc2; /* when called with GENERATE_PAIR */
	struct ncr_key_generate_params_st params;
};

/* used in derivation/encryption
 */
struct ncr_key_params_st {
	ncr_key_t oldkey;
	ncr_key_t newkey;

	unsigned int keyflags; /* for new key */

	union {
		struct {
			void* iv;
			size_t iv_size;
		} cipher;
		struct {
			void * peer_public;
			size_t peer_public_size;
		} dh;
	} params;
};

#define MAX_KEY_ID_SIZE 20

struct ncr_key_info_st {
	ncr_key_t key; /* input */

	unsigned int flags;
	ncr_key_type_t type;
	ncr_algorithm_t algorithm; /* valid for public/private keys */

	uint8_t key_id[MAX_KEY_ID_SIZE];
	size_t key_id_size;
};

struct ncr_key_data_st {
	ncr_key_t key;
	ncr_data_t data;
};

struct ncr_public_key_params_st
{
	ncr_key_t key;
	ncr_key_type_t type;
	union {
		struct {
			void* m;
			size_t m_size;
			void* e;
			size_t e_size;
			void* p;
			size_t p_size;
			void* q;
			size_t q_size;
			void* c;
			size_t c_size;
		} rsa;		
		struct {
			void* y;
			size_t y_size;
			void* p;
			size_t p_size;
			void* q;
			size_t q_size;
			void* g;
			size_t g_size;
		} dsa;
		struct {
			void* public;
			size_t public_size;
		} dh;
	} params;
};

#define NCRIO_KEY_INIT			_IOW ('c', 204, ncr_key_t)
#define NCRIO_KEY_GENERATE     	_IOR ('c', 205, struct ncr_key_generate_st)
#define NCRIO_KEY_GENERATE_PAIR _IOR ('c', 206, struct ncr_key_generate_st)
#define NCRIO_KEY_DERIVE        _IOR ('c', 207, struct ncr_key_params_st)
#define NCRIO_KEY_GET_INFO      _IOWR('c', 208, struct ncr_key_info_st)
#define NCRIO_KEY_EXPORT       	_IOWR('c', 209, struct ncr_key_data_st)
#define NCRIO_KEY_IMPORT       	_IOWR('c', 210, struct ncr_key_data_st)
#define NCRIO_KEY_GET_PUBLIC   	_IOWR('c', 211, struct ncr_public_key_params_st)
#define NCRIO_KEY_DEINIT       _IOR ('c', 212, ncr_key_t)


/* Storage ioctls
 */
#define MAX_LABEL_SIZE 128

struct ncr_storage_st {
	ncr_key_t key;
	char label[MAX_LABEL_SIZE]; /* or template */
	mode_t mode;
};

struct ncr_storage_metadata_st {
	char label[MAX_LABEL_SIZE];
	uid_t uid;
	gid_t gid;
	mode_t mode;

	ncr_algorithm_t algorithm;
	ncr_key_type_t type;

	uint8_t key_id[MAX_KEY_ID_SIZE];
	size_t key_id_size;
};

struct ncr_storage_chown_st {
	char label[MAX_LABEL_SIZE];
	uid_t uid;
	gid_t gid;
};

struct ncr_storage_chmod_st {
	char label[MAX_LABEL_SIZE];
	mode_t mode;
};

struct ncr_storage_remove_st {
	char label[MAX_LABEL_SIZE];
};


#define NCRIO_STORAGE_STORE			_IOW ('c', 220, struct ncr_storage_st)
#define NCRIO_STORAGE_MKSTEMP     	_IOR ('c', 221, struct ncr_storage_st)
#define NCRIO_STORAGE_LOAD			_IOR ('c', 222, struct ncr_storage_st)
#define NCRIO_STORAGE_CHMOD        _IOR ('c', 223, struct ncr_storage_chmod_st)
#define NCRIO_STORAGE_CHOWN        _IOR ('c', 224, struct ncr_storage_chown_st)
#define NCRIO_STORAGE_REMOVE      _IOR('c', 225, struct ncr_storage_remove_st)
#define NCRIO_STORAGE_LOAD_METADATA			_IOWR ('c', 226, struct ncr_storage_metadata_st)

struct ncr_storage_traverse_st {
	int traverse_id;
	struct ncr_storage_metadata_st metadata;
};


#define NCRIO_STORAGE_TRAVERSE_INIT     	_IOW('c', 227, int)
#define NCRIO_STORAGE_TRAVERSE_NEXT     	_IOWR('c', 228, struct ncr_storage_traverse_st)
#define NCRIO_STORAGE_TRAVERSE_DEINIT     	_IOWR('c', 229, int)


/* FIXME key wrap ioctls
 */


/* Crypto Operations ioctls
 */

typedef enum {
	NCR_OP_ENCRYPT=1,
	NCR_OP_DECRYPT,
	NCR_OP_DIGEST,
	NCR_OP_MAC,
	NCR_OP_SIGN,
	NCR_OP_VERIFY,
} ncr_crypto_op_t;

typedef int ncr_session_t;
#define NCR_SESSION_INVALID (ncr_session_t)-1

/* input of CIOCGSESSION */
struct ncr_session_st {
	/* input */
	ncr_algorithm_t algorithm;
	struct ncr_key_params_st params;
	ncr_key_t key;
	ncr_crypto_op_t op;

	/* output */
	ncr_session_t	ses;		/* session identifier */
};

typedef enum {
	NCR_SUCCESS = 0,
	NCR_ERROR_GENERIC = -1,
} ncr_error_t;

struct ncr_session_op_st {
	/* input */
	ncr_session_t ses;

	union {
		struct {
			ncr_data_t plaintext;
			ncr_data_t ciphertext;
		} cipher;
		struct {
			ncr_data_t text;
			ncr_data_t output;
		} digest; /* mac/hash/sign */
		struct {
			ncr_data_t text;
			ncr_data_t signature;
		} verify; /* mac/hash/sign */
	} data;

	/* output */
	ncr_error_t err;
};


#endif
