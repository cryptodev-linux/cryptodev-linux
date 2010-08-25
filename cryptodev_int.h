/* cipher stuff */
#ifndef CRYPTODEV_INT_H
# define CRYPTODEV_INT_H

#include <linux/init.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/scatterlist.h>
#include <ncr.h>

#define PFX "cryptodev: "
#define dprintk(level,severity,format,a...)			\
	do {						\
		if (level <= cryptodev_verbosity)				\
			printk(severity PFX "%s[%u]: " format,	\
			       current->comm, current->pid,	\
			       ##a);				\
	} while (0)

extern int cryptodev_verbosity;

/* For zero copy */
int __get_userbuf(uint8_t __user *addr, uint32_t len, int write,
		int pgcount, struct page **pg, struct scatterlist *sg);
void release_user_pages(struct page **pg, int pagecount);

/* last page - first page + 1 */
#define PAGECOUNT(buf, buflen) \
        ((((unsigned long)(buf + buflen - 1) & PAGE_MASK) >> PAGE_SHIFT) - \
         (((unsigned long) buf               & PAGE_MASK) >> PAGE_SHIFT) + 1)

#define DEFAULT_PREALLOC_PAGES 32

struct cipher_data
{
	int init; /* 0 uninitialized */
	int blocksize;
	int ivsize;
	struct {
		struct crypto_ablkcipher* s;
		struct cryptodev_result *result;
		struct ablkcipher_request *request;
		uint8_t iv[NCR_CIPHER_MAX_BLOCK_LEN];
	} async;
};

int cryptodev_cipher_init(struct cipher_data* out, const char* alg_name, uint8_t * key, size_t keylen);
void cryptodev_cipher_deinit(struct cipher_data* cdata);
ssize_t cryptodev_cipher_decrypt( struct cipher_data* cdata, const struct scatterlist *sg1, struct scatterlist *sg2, size_t len);
ssize_t cryptodev_cipher_encrypt( struct cipher_data* cdata, const struct scatterlist *sg1, struct scatterlist *sg2, size_t len);

void cryptodev_cipher_set_iv(struct cipher_data* cdata, void* iv, size_t iv_size);
int _cryptodev_cipher_decrypt(struct cipher_data* cdata, const void* ciphertext,
	size_t ciphertext_size, void* plaintext, size_t plaintext_size);
int _cryptodev_cipher_encrypt(struct cipher_data* cdata, const void* plaintext,
	size_t plaintext_size, void* ciphertext, size_t ciphertext_size);

/* hash stuff */
struct hash_data
{
	int init; /* 0 uninitialized */
	int digestsize;
	struct {
		struct crypto_ahash *s;
		struct cryptodev_result *result;
		struct ahash_request *request;
	} async;
};

int cryptodev_hash_final( struct hash_data* hdata, void* output);
ssize_t cryptodev_hash_update( struct hash_data* hdata, struct scatterlist *sg, size_t len);
ssize_t _cryptodev_hash_update( struct hash_data* hdata, const void* data, size_t len);
int cryptodev_hash_reset( struct hash_data* hdata);
void cryptodev_hash_deinit(struct hash_data* hdata);
int cryptodev_hash_init(struct hash_data *hdata, const char *alg_name, const void *mackey, size_t mackeylen);

#endif /* CRYPTODEV_INT_H */
