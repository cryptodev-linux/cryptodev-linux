#ifndef NCR_INT_H
# define NCR_INT_H

#include "ncr.h"
#include <asm/atomic.h>

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
	unsigned int uid;

	ncr_data_t desc;
};

/* all the data associated with the open descriptor
 * are here.
 */
struct ncr_lists {
	struct list_head data_list;
	struct semaphore data_sem;

	/* sessions */
	/* keys */
};

void* ncr_init_lists(void);
void ncr_deinit_lists(struct ncr_lists *lst);

int
ncr_ioctl(unsigned int uid, struct ncr_lists* lst,
		unsigned int cmd, unsigned long arg);

int ncr_data_set(struct ncr_lists* lst, void __user* arg);
int ncr_data_get(struct ncr_lists* lst, void __user* arg);
int ncr_data_deinit(struct ncr_lists* lst, void __user* arg);
int ncr_data_new(unsigned int uid, struct ncr_lists* lst, void __user* arg);
void ncr_data_list_deinit(struct ncr_lists *lst);

#endif
