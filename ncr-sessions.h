#ifndef NCR_SESSIONS_H
# define NCR_SESSIONS_H

int _ncr_session_direct_final(struct ncr_lists* lists, struct ncr_session_op_st* op);
int _ncr_session_direct_update(struct ncr_lists* lists, struct ncr_session_op_st* op);

int _ncr_session_encrypt(struct session_item_st* sess, const struct scatterlist* input, unsigned input_cnt,
	size_t input_size, void *output, unsigned output_cnt, size_t *output_size);

int _ncr_session_decrypt(struct session_item_st* sess, const struct scatterlist* input, 
	unsigned input_cnt, size_t input_size,
	struct scatterlist *output, unsigned output_cnt, size_t *output_size);

void _ncr_session_remove(struct list_sem_st* lst, ncr_session_t desc);

#endif
