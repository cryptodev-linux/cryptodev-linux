#ifndef NCR_INT_H
# define NCR_INT_H

#include <linux/compat.h>
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

struct algo_oid_st {
	oid_st oid;
	int key_size;
};

struct algo_properties_st {
	ncr_algorithm_t algo;
	const char *kstr;
	size_t kstr_len;
	unsigned needs_iv:1;
	unsigned is_hmac:1;
	unsigned can_sign:1;
	unsigned can_digest:1;
	unsigned can_encrypt:1;
	unsigned can_kx:1;	/* key exchange */
	unsigned is_symmetric:1;
	unsigned is_pk:1;
	int digest_size;
	/* NCR_KEY_TYPE_SECRET if for a secret key algorithm or MAC,
	 * NCR_KEY_TYPE_PUBLIC for a public key algorithm.
	 */
	ncr_key_type_t key_type;
	const struct algo_oid_st *oids;
};

struct key_item_st {
	/* This object is also not protected from concurrent access.
	 */
	ncr_key_type_t type;
	unsigned int flags;
	const struct algo_properties_st *algorithm;	/* non-NULL for public/private keys */
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

void *ncr_init_lists(void);
void ncr_deinit_lists(struct ncr_lists *lst);

long ncr_ioctl(struct ncr_lists *lst, unsigned int cmd, unsigned long arg);
long ncr_compat_ioctl(struct ncr_lists *lst, unsigned int cmd,
		      unsigned long arg);

/* key derivation */
int ncr_key_derive(struct ncr_lists *lst, const struct ncr_key_derive *data,
		   struct nlattr *tb[]);

void ncr_key_clear(struct key_item_st *item);
int ncr_key_update_flags(struct key_item_st *item, const struct nlattr *nla);

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

#ifdef CONFIG_CRYPTO_USERSPACE_ASYMMETRIC
int ncr_key_generate_pair(struct ncr_lists *lst,
			  const struct ncr_key_generate_pair *gen,
			  struct nlattr *tb[]);
#else
static inline int ncr_key_generate_pair(struct ncr_lists *lst,
					const struct ncr_key_generate_pair *gen,
					struct nlattr *tb[])
{
	return -EOPNOTSUPP;
}
#endif
int ncr_key_get_public(struct ncr_lists *lst, void __user * arg);

int ncr_key_item_get_read(struct key_item_st **st, struct ncr_lists *lst,
			  ncr_key_t desc);
/* get key item for writing */
int ncr_key_item_get_write(struct key_item_st **st,
			   struct ncr_lists *lst, ncr_key_t desc);
void _ncr_key_item_put(struct key_item_st *item);

typedef enum {
	LIMIT_TYPE_KEY,
	NUM_LIMIT_TYPES
} limits_type_t;

void ncr_limits_remove(uid_t uid, pid_t pid, limits_type_t type);
int ncr_limits_add_and_check(uid_t uid, pid_t pid, limits_type_t type);
void ncr_limits_init(void);
void ncr_limits_deinit(void);

#ifdef CONFIG_CRYPTO_USERSPACE_ASYMMETRIC
int ncr_key_wrap(struct ncr_lists *lst, const struct ncr_key_wrap *wrap,
		 struct nlattr *tb[]);
int ncr_key_unwrap(struct ncr_lists *lst, const struct ncr_key_unwrap *wrap,
		   struct nlattr *tb[]);
#else
static inline int ncr_key_wrap(struct ncr_lists *lst,
			       const struct ncr_key_wrap *wrap,
			       struct nlattr *tb[])
{
	return -EOPNOTSUPP;
}
static inline int ncr_key_unwrap(struct ncr_lists *lst,
				 const struct ncr_key_unwrap *wrap,
				 struct nlattr *tb[])
{
	return -EOPNOTSUPP;
}
#endif
int ncr_key_storage_wrap(struct ncr_lists *lst,
			 const struct ncr_key_storage_wrap *wrap,
			 struct nlattr *tb[]);
int ncr_key_storage_unwrap(struct ncr_lists *lst,
			   const struct ncr_key_storage_unwrap *wrap,
			   struct nlattr *tb[]);

/* sessions */
void ncr_sessions_list_deinit(struct ncr_lists *lst);

int ncr_session_init(struct ncr_lists *lists,
		     const struct ncr_session_init *session,
		     struct nlattr *tb[]);
int ncr_session_update(struct ncr_lists *lists,
		       const struct ncr_session_update *op, struct nlattr *tb[],
		       int compat);
int ncr_session_final(struct ncr_lists *lists,
		      const struct ncr_session_final *op, struct nlattr *tb[],
		      int compat);
int ncr_session_once(struct ncr_lists *lists,
		     const struct ncr_session_once *once, struct nlattr *tb[],
		     int compat);

/* master key */
extern struct key_item_st master_key;

void ncr_master_key_reset(void);

/* storage */
int key_from_storage_data(struct key_item_st *key, const void *data,
			  size_t data_size);
int key_to_storage_data(uint8_t ** data, size_t * data_size,
			const struct key_item_st *key);

/* misc helper macros */

const struct algo_properties_st *_ncr_algo_to_properties(ncr_algorithm_t algo);
const struct algo_properties_st *_ncr_nla_to_properties(const struct nlattr
							*nla);
int _ncr_key_get_sec_level(struct key_item_st *item);
const struct algo_properties_st *_ncr_oid_to_properties(const oid_st * oid);
const oid_st *_ncr_properties_to_oid(const struct algo_properties_st *prop,
				     int key_size);

/* CONFIG_COMPAT handling */

#ifdef CONFIG_COMPAT
struct compat_ncr_session_input_data {
	compat_uptr_t data;
	compat_size_t data_size;
};

struct compat_ncr_session_output_buffer {
	compat_uptr_t buffer;
	compat_size_t buffer_size;
	compat_uptr_t result_size_ptr;
};
#endif

int ncr_session_input_data_from_nla(struct ncr_session_input_data *dest,
				    const struct nlattr *nla, int compat);

int ncr_session_output_buffer_from_nla(struct ncr_session_output_buffer *dest,
				       const struct nlattr *nla, int compat);

int ncr_session_output_buffer_set_size(const struct ncr_session_output_buffer
				       *dest, size_t size, int compat);

#endif
