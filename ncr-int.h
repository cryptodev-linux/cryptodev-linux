#ifndef NCR_INT_H
# define NCR_INT_H

#include <linux/idr.h>
#include <linux/mutex.h>
#include "ncr.h"
#include <asm/atomic.h>
#include "cryptodev_int.h"
#include <ncr-pk.h>
#include <ncr-dh.h>

#define KEY_DATA_MAX_SIZE 3*1024
#define NCR_CIPHER_MAX_KEY_LEN 1024

#define err() printk(KERN_DEBUG"ncr: %s: %s: %d\n", __FILE__, __func__, __LINE__)

struct nlattr;
struct ncr_out;

struct algo_properties_st {
	ncr_algorithm_t algo;
	const char *kstr;
	unsigned needs_iv:1;
	unsigned is_hmac:1;
	unsigned can_sign:1;
	unsigned can_digest:1;
	unsigned can_encrypt:1;
	unsigned can_kx:1; /* key exchange */
	unsigned is_symmetric:1;
	unsigned is_pk:1;
	int digest_size;
	/* NCR_KEY_TYPE_SECRET if for a secret key algorithm or MAC,
	 * NCR_KEY_TYPE_PUBLIC for a public key algorithm.
	 */
	ncr_key_type_t key_type;
};

struct session_item_st {
	const struct algo_properties_st *algorithm;
	ncr_crypto_op_t op;

	/* contexts for various options.
	 * simpler to have them like that than
	 * in a union.
	 */
	struct cipher_data cipher;
	struct ncr_pk_ctx pk;
	struct hash_data hash;

	struct scatterlist *sg;
	struct page **pages;
	unsigned array_size;
	unsigned available_pages;
	struct mutex mem_mutex; /* down when the
		* values above are changed.
		*/

	struct key_item_st* key;

	atomic_t refcnt;
	ncr_session_t desc;
};

struct key_item_st {
	/* This object is also not protected from concurrent access.
	 */
	ncr_key_type_t type;
	unsigned int flags;
	const struct algo_properties_st *algorithm; /* non-NULL for public/private keys */
	uint8_t key_id[MAX_KEY_ID_SIZE];
	size_t key_id_size;

	union {
		struct {
			uint8_t data[NCR_CIPHER_MAX_KEY_LEN];
			size_t size;
		} secret;
		union {
			rsa_key rsa;
			dsa_key dsa;
			dh_key dh;
		} pk;
	} key;

	atomic_t refcnt;
	atomic_t writer;

	/* owner. The one charged with this */
	uid_t uid;
	pid_t pid;

	ncr_key_t desc;
};

/* all the data associated with the open descriptor
 * are here.
 */
struct ncr_lists {
	struct mutex key_idr_mutex;
	struct idr key_idr;

	/* sessions */
	struct mutex session_idr_mutex;
	struct idr session_idr;
};

void* ncr_init_lists(void);
void ncr_deinit_lists(struct ncr_lists *lst);

int ncr_ioctl(struct ncr_lists *lst, unsigned int cmd, unsigned long arg);
long ncr_compat_ioctl(struct ncr_lists *lst, unsigned int cmd,
		      unsigned long arg);

/* key derivation */
int ncr_key_derive(struct ncr_lists *lst, const struct ncr_key_derive *data,
		   struct nlattr *tb[]);

void ncr_key_clear(struct key_item_st* item);
void ncr_key_assign_flags(struct key_item_st* item, unsigned int flags);

/* key handling */
int ncr_key_init(struct ncr_lists *lst);
int ncr_key_deinit(struct ncr_lists *lst, ncr_key_t desc);
int ncr_key_export(struct ncr_lists *lst, const struct ncr_key_export *data,
		   struct nlattr *tb[]);
int ncr_key_import(struct ncr_lists *lst, const struct ncr_key_import *data,
		   struct nlattr *tb[]);
void ncr_key_list_deinit(struct ncr_lists *lst);
int ncr_key_generate(struct ncr_lists *lst, const struct ncr_key_generate *gen,
		     struct nlattr *tb[]);
int ncr_key_get_info(struct ncr_lists *lst, struct ncr_out *out,
		     const struct ncr_key_get_info *info, struct nlattr *tb[]);

int ncr_key_generate_pair(struct ncr_lists *lst,
			  const struct ncr_key_generate_pair *gen,
			  struct nlattr *tb[]);
int ncr_key_get_public(struct ncr_lists *lst, void __user* arg);

int ncr_key_item_get_read(struct key_item_st**st, struct ncr_lists *lst,
	ncr_key_t desc);
/* get key item for writing */
int ncr_key_item_get_write( struct key_item_st** st,
	struct ncr_lists *lst, ncr_key_t desc);
void _ncr_key_item_put( struct key_item_st* item);

typedef enum {
	LIMIT_TYPE_KEY,
	NUM_LIMIT_TYPES
} limits_type_t;

void ncr_limits_remove(uid_t uid, pid_t pid, limits_type_t type);
int ncr_limits_add_and_check(uid_t uid, pid_t pid, limits_type_t type);
void ncr_limits_init(void);
void ncr_limits_deinit(void);

int ncr_key_wrap(struct ncr_lists *lst, void __user* arg);
int ncr_key_unwrap(struct ncr_lists *lst, void __user* arg);
int ncr_key_storage_wrap(struct ncr_lists *lst, void __user* arg);
int ncr_key_storage_unwrap(struct ncr_lists *lst, void __user* arg);

/* sessions */
struct session_item_st* ncr_session_new(struct ncr_lists *lst);
void _ncr_sessions_item_put( struct session_item_st* item);
struct session_item_st* ncr_sessions_item_get(struct ncr_lists *lst, ncr_session_t desc);
void ncr_sessions_list_deinit(struct ncr_lists *lst);

int ncr_session_init(struct ncr_lists* lists, void __user* arg);
int ncr_session_update(struct ncr_lists* lists, void __user* arg);
int ncr_session_final(struct ncr_lists* lists, void __user* arg);
int ncr_session_once(struct ncr_lists* lists, void __user* arg);

/* master key */
extern struct key_item_st master_key;

void ncr_master_key_reset(void);

/* storage */
int key_from_storage_data(struct key_item_st* key, const void* data, size_t data_size);
int key_to_storage_data( uint8_t** data, size_t * data_size, const struct key_item_st *key);


/* misc helper macros */

const struct algo_properties_st *_ncr_algo_to_properties(ncr_algorithm_t algo);
const struct algo_properties_st *_ncr_nla_to_properties(const struct nlattr *nla);
const struct algo_properties_st *ncr_key_params_get_sign_hash(const struct algo_properties_st *algo, struct ncr_key_params_st * params);
int _ncr_key_get_sec_level(struct key_item_st* item);

#endif
