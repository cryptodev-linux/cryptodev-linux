#ifndef NCR_STORAGE_H
# define NCR_STORAGE_H

struct storage_item_st {
	/* metadata */
	char label[MAX_LABEL_SIZE];
	uid_t owner;
	gid_t group;
	mode_t mode;

	uint16_t algorithm;
	uint8_t type;

	uint8_t key_id[MAX_KEY_ID_SIZE];
	uint8_t key_id_size;

	/* data */
	uint8_t * raw_key;
	size_t raw_key_size;
};

int ncr_storage_store(struct list_sem_st* key_lst, void __user* arg);
int ncr_storage_load(struct list_sem_st* key_lst, void __user* arg);

int ncr_storage_mkstemp(struct list_sem_st* key_lst, void __user* arg);
int ncr_storage_chmod(void __user* arg);
int ncr_storage_chown(void __user* arg);
int ncr_storage_remove(void __user* arg);
int ncr_storage_metadata_load(void __user* arg);
int ncr_storage_traverse_init(struct list_sem_st* tr_lst, void __user* arg);
int ncr_storage_traverse_next(struct list_sem_st* tr_lst, void __user* arg);
int ncr_storage_traverse_deinit(struct list_sem_st* tr_lst, void __user* arg);

int _ncr_store(const struct storage_item_st * tostore);
int _ncr_load(struct storage_item_st * loaded);

#endif /* NCR_STORAGE_H */
