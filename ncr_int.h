#ifndef NCR_INT_H
# define NCR_INT_H

#include "ncr.h"
#include <asm/atomic.h>
#include "cryptodev_int.h"
#include <ncr-pk.h>

#define KEY_DATA_MAX_SIZE 3*1024

#define err() printk(KERN_DEBUG"ncr: %s: %s: %d\n", __FILE__, __func__, __LINE__)

struct session_item_st {
	struct list_head list;

	ncr_algorithm_t algorithm;
	ncr_crypto_op_t op;

	/* contexts for various options.
	 * simpler to have them like that than
	 * in a union.
	 */
	struct cipher_data cipher;
	struct ncr_pk_ctx pk;
	struct hash_data hash;

	struct key_item_st* key;

	atomic_t refcnt;
	ncr_session_t desc;
};

struct data_item_st {
	struct list_head list;
	/* This object is not protected from concurrent access.
	 * I see no reason to allow concurrent writes (reads are
	 * not an issue).
	 */

	uint8_t* data;
	size_t data_size;
	size_t max_data_size;
	unsigned int flags;
	atomic_t refcnt;

	/* owner. The one charged with this */
	uid_t uid;
	pid_t pid;

	ncr_data_t desc;
};

struct key_item_st {
	struct list_head list;
	/* This object is also not protected from concurrent access.
	 */
	ncr_key_type_t type;
	unsigned int flags;
	ncr_algorithm_t algorithm; /* valid for public/private keys */
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
		} pk;
	} key;

	atomic_t refcnt;
	atomic_t writer;

	/* owner. The one charged with this */
	uid_t uid;
	pid_t pid;

	ncr_key_t desc;
};

struct list_sem_st {
	struct list_head list;
	struct semaphore sem;
};

/* all the data associated with the open descriptor
 * are here.
 */
struct ncr_lists {
	struct list_sem_st data;
	struct list_sem_st key;

	/* sessions */
	struct list_sem_st sessions;
};

void* ncr_init_lists(void);
void ncr_deinit_lists(struct ncr_lists *lst);

int ncr_ioctl(struct ncr_lists*, struct file *filp,
		unsigned int cmd, unsigned long arg);
		
int ncr_data_set(struct list_sem_st*, void __user* arg);
int ncr_data_get(struct list_sem_st*, void __user* arg);
int ncr_data_deinit(struct list_sem_st*, void __user* arg);
int ncr_data_init(struct list_sem_st*, void __user* arg);
void ncr_data_list_deinit(struct list_sem_st*);
struct data_item_st* ncr_data_item_get( struct list_sem_st* lst, ncr_data_t desc);
void _ncr_data_item_put( struct data_item_st* item);

int ncr_key_init(struct list_sem_st*, void __user* arg);
int ncr_key_deinit(struct list_sem_st*, void __user* arg);
int ncr_key_export(struct list_sem_st* data_lst,
	struct list_sem_st* key_lst,void __user* arg);
int ncr_key_import(struct list_sem_st* data_lst,
	struct list_sem_st* key_lst,void __user* arg);
void ncr_key_list_deinit(struct list_sem_st* lst);
int ncr_key_generate(struct list_sem_st* data_lst, void __user* arg);
int ncr_key_info(struct list_sem_st*, void __user* arg);

int ncr_key_generate_pair(struct list_sem_st* lst, void __user* arg);
int ncr_key_derive(struct list_sem_st*, void __user* arg);
int ncr_key_get_public(struct list_sem_st* lst, void __user* arg);

int ncr_key_item_get_read(struct key_item_st**st, struct list_sem_st* lst, 
	ncr_key_t desc);
/* get key item for writing */
int ncr_key_item_get_write( struct key_item_st** st, 
	struct list_sem_st* lst, ncr_key_t desc);
void _ncr_key_item_put( struct key_item_st* item);

typedef enum {
	LIMIT_TYPE_KEY,
	LIMIT_TYPE_DATA
} limits_type_t;

void ncr_limits_remove(uid_t uid, pid_t pid, limits_type_t type);
int ncr_limits_add_and_check(uid_t uid, pid_t pid, limits_type_t type);
void ncr_limits_init(void);
void ncr_limits_deinit(void);

ncr_key_type_t ncr_algorithm_to_key_type(ncr_algorithm_t algo);

int ncr_key_wrap(struct list_sem_st* keys, struct list_sem_st* data, void __user* arg);
int ncr_key_unwrap(struct list_sem_st*, struct list_sem_st* data, void __user* arg);
int ncr_key_storage_wrap(struct list_sem_st* key_lst, struct list_sem_st* data_lst, void __user* arg);
int ncr_key_storage_unwrap(struct list_sem_st*, struct list_sem_st* data, void __user* arg);

/* sessions */
struct session_item_st* ncr_session_new(struct list_sem_st* lst);
void _ncr_sessions_item_put( struct session_item_st* item);
struct session_item_st* ncr_sessions_item_get( struct list_sem_st* lst, ncr_session_t desc);
void ncr_sessions_list_deinit(struct list_sem_st* lst);

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
inline static unsigned int key_flags_to_data(unsigned int key_flags)
{
	unsigned int flags = 0;

	if (key_flags & NCR_KEY_FLAG_EXPORTABLE)
		flags |= NCR_DATA_FLAG_EXPORTABLE;

	return flags;
}

inline static unsigned int data_flags_to_key(unsigned int data_flags)
{
	unsigned int flags = 0;

	if (data_flags & NCR_DATA_FLAG_EXPORTABLE)
		flags |= NCR_KEY_FLAG_EXPORTABLE;

	return flags;
}

const char* _ncr_algo_to_str(ncr_algorithm_t algo);
int _ncr_algo_digest_size(ncr_algorithm_t algo);



#endif
