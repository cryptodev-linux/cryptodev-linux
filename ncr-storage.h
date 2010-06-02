#ifndef NCR_STORAGE_H
# define NCR_STORAGE_H

#define MAX_RAW_KEY_SIZE 4096

struct storage_item_st {
	/* metadata */
	uint8_t label[MAX_LABEL_SIZE];
	uint32_t owner;
	uint32_t group;
	mode_t mode;

	uint16_t algorithm;
	uint8_t type;

	uint8_t key_id[MAX_KEY_ID_SIZE];
	uint8_t key_id_size;

	/* data */
	uint8_t raw_key[MAX_RAW_KEY_SIZE];
	uint16_t raw_key_size;
} __attribute__ ((__packed__));

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
