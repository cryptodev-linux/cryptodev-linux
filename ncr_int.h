#ifndef NCR_INT_H
# define NCR_INT_H

#include "ncr.h"
#include <asm/atomic.h>

struct data_item {
	struct list_head list;
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

#endif
