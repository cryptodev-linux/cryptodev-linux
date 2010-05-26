#include <crypto/ncr.h>

int ncr_global_init(unsigned int flags); /* open device */
void ncr_global_deinit(void); /* close device */


/* parameters for key generation
 */
int ncr_generate_params_init(ncr_generate_params_t*); /* userspace */
void ncr_generate_params_deinit(ncr_generate_params_t); /* userspace */

/* common for ciphers and public key algorithms */
void ncr_generate_params_set_algorithm(ncr_generate_params_t, ncr_algorithm_t); /* userspace */

/* public key algorithms */
void ncr_generate_params_set_bits(ncr_generate_params_t, unsigned int bits); /* RSA+DSA */
int ncr_generate_params_set_rsa_e(ncr_generate_params_t, void* e, unsigned int e_size); /* RSA */

/* parameters for encryption/decryption/derivation
 */
int ncr_params_init(ncr_params_t*); /* userspace */
void ncr_params_deinit(ncr_params_t); /* userspace */

int ncr_params_set_cipher_iv(ncr_params_t, void* iv, unsigned int iv_size); /* userspace */

int ncr_params_set_dh_key(ncr_params_t, ncr_key_t dh_priv); /* DH */


/* data flags are of NCR_DATA_FLAG_* type */

int ncr_data_init(ncr_data_t *, size_t max_object_size, unsigned int dataflags); /* ioctl DATA_INIT */
size_t ncr_data_get_size(ncr_data_t); /* ioctl DATA_GET */
int ncr_data_get_data(ncr_data_t, void* data_ptr, size_t *data_size); /* ioctl DATA_GET */
int ncr_data_set_data(ncr_data_t, void* data_ptr, size_t data_size); /* ioctl DATA_SET */
int ncr_data_append_data(ncr_data_t, void* data_ptr, size_t data_size); /* ioctl DATA_SET */
void ncr_data_deinit(ncr_data_t); /* ioctl DATA_DEINIT */

/* key flags are NCR_KEY_FLAG_* */

int ncr_key_init(ncr_key_t* key); /* ioctl KEY_INIT */
int ncr_key_generate(ncr_key_t key, ncr_algorithm_t algorithm, unsigned int bits, unsigned int keyflags); /* ioctl KEY_GENERATE */
int ncr_key_generate_pair(ncr_key_t public_key, ncr_key_t private_key, ncr_generate_params_t params, unsigned int keyflags); /* ioctl KEY_GENERATE_PAIR */
int ncr_key_derive(ncr_key_t newkey, ncr_params_t params, unsigned int keyflags, ncr_key_t data); /* ioctl KEY_DERIVE */
unsigned int ncr_key_get_flags(ncr_key_t key); /* ioctl KEY_GET_INFO */
ncr_key_type_t ncr_key_get_type(ncr_key_t key); /* ioctl KEY_GET_INFO */
int ncr_key_export(ncr_key_t key, ncr_data_t obj); /* ioctl KEY_EXPORT */
int ncr_key_import(ncr_key_t key, ncr_data_t obj); /* ioctl KEY_IMPORT */
int ncr_key_get_id(ncr_key_t, void* id, size_t* id_size); /* KEY_GET_INFO */
void ncr_key_deinit(ncr_key_t); /* ioctl KEY_DEINIT */

int ncr_key_get_public_param(ncr_key_t key, ncr_public_param_t, void* output, size_t* output_size);

/* store keys */
int ncr_storage_store(const char* label, mode_t mode, ncr_key_t key); /* ioctl STORE_STORE */
int ncr_storage_mkstemp(char* template, mode_t mode, ncr_key_t key);/* ioctl STORE_MKSTEMP */
ncr_key_t ncr_storage_load(const char* label); /* ioctl STORE_LOAD */

int ncr_storage_chmod(const char* label, mode_t newmode); /* ioctl STORE_CHMOD */
int ncr_storage_chown(const char* label, uid_t owner, gid_t grp); /* ioctl STORE_CHOWN */
int ncr_storage_remove(const char* label); /* ioctl STORE_REMOVE */

typedef struct {} * ncr_metadata_t;

int ncr_metadata_init(ncr_metadata_t* metadata); /* userspace */
void ncr_metadata_deinit(ncr_metadata_t metadata);/* userspace */

/* read info from metadata */
const char* ncr_metadata_get_label(ncr_metadata_t); /* userspace */
ncr_key_type_t ncr_metadata_get_type(ncr_metadata_t); /* userspace */

/* id of the key. For public/private key pairs it should be the same */
int ncr_metadata_get_id(ncr_metadata_t, void* id, size_t* id_size); /* userspace */
/* this has meaning only if type is public or private key */
ncr_algorithm_t ncr_metadata_get_algorithm(ncr_metadata_t); /* userspace */

uid_t ncr_metadata_get_uid(ncr_metadata_t); /* userspace */
gid_t ncr_metadata_get_gid(ncr_metadata_t); /* userspace */
mode_t ncr_metadata_get_mode(ncr_metadata_t); /*userspace */

/* load metadata for particular file */
int ncr_metadata_load(const char* label, ncr_metadata_t metadata);  /* ioctl STORE_METADATA_GET_INFO */

/* traverse all storage entries */
int ncr_storage_traverse_init(ncr_traverse_t* tr); /* ioctl STORE_METADATA_TRAVERSE_INIT */
int ncr_storage_traverse_next(ncr_traverse_t, ncr_metadata_t metadata); /* ioctl STORE_METADATA_TRAVERSE_NEXT */
void ncr_storage_traverse_deinit(ncr_traverse_t); /* ioctl STORE_METADATA_TRAVERSE_DEINIT */

/* wrap unwrap */
int ncr_key_wrap(ncr_key_t wrapping_key, ncr_params_t params, ncr_key_t key, void* output_data, size_t output_data_size); /* ioctl KEY_WRAP */
int ncr_key_unwrap(ncr_key_t*key, ncr_key_t wrapping_key, ncr_params_t params, unsigned int keyflags, void* input_data, size_t input_data_size); /* ioctl KEY_UNWRAP */

/* operations to objects result in objects that have the same properties as the original
 * object. I.e. encrypting a secret key under an object will not allow you to export it.
 */

int ncr_session_copy(ncr_session_t* copy, ncr_session_t source); /* ioctl SESSION_COPY */

/* encryption functions */
int ncr_encrypt_init(ncr_session_t* session, ncr_key_t key, ncr_params_t params); /* ioctl SESSION_INIT */
int ncr_encrypt_once(ncr_key_t key, ncr_params_t params, const ncr_data_t plaintext, ncr_data_t ciphertext); /*userspace */
int ncr_encrypt_update(ncr_session_t session, const ncr_data_t plaintext, ncr_data_t ciphertext); /* ioctl SESSION_UPDATE */
int ncr_encrypt_final(ncr_session_t session, ncr_data_t obj); /* ioctl SESSION_FINAL */

/* decryption functions */
int ncr_decrypt_init(ncr_session_t* session, ncr_key_t key, ncr_params_t params);
int ncr_decrypt_once(ncr_key_t key, ncr_params_t params, const ncr_data_t ciphertext, ncr_data_t plaintext);
int ncr_decrypt_update(ncr_session_t session, const ncr_data_t ciphertext, ncr_data_t plaintext);
int ncr_decrypt_final(ncr_session_t session, ncr_data_t obj);

/* PK hash functions */
int ncr_digest_init(ncr_session_t* session, ncr_params_t params);
int ncr_digest_once(ncr_key_t key, ncr_params_t params, const ncr_data_t plaintext, ncr_data_t hash);
int ncr_digest_update(ncr_session_t session, const ncr_data_t plaintext);
int ncr_digest_final(ncr_session_t session, ncr_data_t hash);

/* PK SIGN and MAC functions */
int ncr_sign_init(ncr_session_t* session, ncr_key_t key, ncr_params_t params);
int ncr_sign_once(ncr_key_t key, ncr_params_t params, const ncr_data_t plaintext, ncr_data_t signature);
int ncr_sign_update(ncr_session_t session, const ncr_data_t plaintext);
int ncr_sign_final(ncr_session_t session, ncr_data_t signature);

/* Verify PK signature or MAC signature */
int ncr_verify_init(ncr_session_t* session, ncr_key_t key, ncr_params_t params);
int ncr_verify_once(ncr_key_t key, ncr_params_t params, const ncr_data_t plaintext, const ncr_data_t signature);
int ncr_verify_update(ncr_session_t session, const ncr_data_t plaintext);
int ncr_verify_final(ncr_session_t session, const ncr_data_t signature);

/* Everything looks straight forward except for authentication
 * algorithms such as Diffie Hellman. This should be done as in PKCS #11
 * as: 
 * ncr_key_generate_pair(our_pubkey, our_privkey)
 * ncr_key_derive(shared_key, params -contain our privkey-, flags_for_new_key, peer_pubkey);
 */
