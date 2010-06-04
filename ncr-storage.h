#ifndef NCR_STORAGE_H
# define NCR_STORAGE_H

#include "ncr-storage-low.h" /* for struct storage_item_st */

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

/* Netlink subsystem; */
void ncr_gnl_deinit(void);
int ncr_gnl_init(void);

#endif /* NCR_STORAGE_H */
