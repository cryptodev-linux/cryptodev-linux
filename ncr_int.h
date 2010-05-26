struct data_item {
	struct list_head list;
	void* data;
	size_t data_size;
	size_t max_data_size;
	struct semaphore sem;
	unsigned int flags;

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

int ncr_ioctl(struct ncr_lists* lists,
		unsigned int cmd, unsigned long arg);
