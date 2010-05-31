#ifndef NCR_INT_H
# define NCR_INT_H

#include "ncr.h"
#include <asm/atomic.h>

#define err() printk(KERN_DEBUG"ncr: %s: %d\n", __func__, __LINE__)

struct data_item {
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

	struct file *filp; /* who has it */
	ncr_data_t desc;
};

#define MAX_KEY_SIZE 32 /* in bytes */

struct key_item {
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
			uint8_t data[MAX_KEY_SIZE];
			size_t size;
		} secret;
	} key;

	atomic_t refcnt;

	struct file *filp; /* who has it */
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
};

void* ncr_init_lists(void);
void ncr_deinit_lists(struct ncr_lists *lst);

int ncr_ioctl(struct ncr_lists*, struct file *filp,
		unsigned int cmd, unsigned long arg);
		
int ncr_data_set(struct list_sem_st*, void __user* arg);
int ncr_data_get(struct list_sem_st*, void __user* arg);
int ncr_data_deinit(struct list_sem_st*, void __user* arg);
int ncr_data_init(struct file* filp, struct list_sem_st*, void __user* arg);
void ncr_data_list_deinit(struct list_sem_st*);
struct data_item* ncr_data_item_get( struct list_sem_st* lst, ncr_data_t desc);
void _ncr_data_item_put( struct data_item* item);

int ncr_key_init(struct file* filp, struct list_sem_st*, void __user* arg);
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

typedef enum {
	LIMIT_TYPE_KEY,
	LIMIT_TYPE_DATA
} limits_type_t;

void ncr_limits_remove(struct file *filp, limits_type_t type);
int ncr_limits_add_and_check(struct file *filp, limits_type_t type);
void ncr_limits_init(void);

ncr_key_type_t ncr_algorithm_to_key_type(ncr_algorithm_t algo);

#endif
