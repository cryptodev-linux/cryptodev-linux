/* cipher stuff */

#ifndef NCR_CIPHER_H
# define NCR_CIPHER_H

ncr_session_t ncr_cipher_init(struct list_sem_st* sess_lst,
	ncr_algorithm_t algorithm, struct key_item_st *key, void* iv, size_t iv_size);
int ncr_cipher_encrypt(struct list_sem_st* sess_lst, ncr_session_t session,
	const struct data_item_st * plaintext, struct data_item_st* ciphertext);
int ncr_cipher_decrypt(struct list_sem_st* sess_lst, ncr_session_t session,
	const struct data_item_st * ciphertext, struct data_item_st* plaintext);
void ncr_cipher_deinit(struct list_sem_st* lst, ncr_session_t session);

int _ncr_cipher_encrypt(struct list_sem_st* sess_lst,
	ncr_session_t session, void* plaintext, size_t plaintext_size);

int _ncr_cipher_decrypt(struct list_sem_st* sess_lst,
	ncr_session_t session, void* plaintext, size_t plaintext_size);

#endif /* NCR_CIPHER_H */
