#ifndef _STORAGE_LOW
#define _STORAGE_LOW

#include "ncr.h"

#define NCR_NL_STORAGE_NAME "KEY_STORAGE"

#define NCR_NL_STORAGE_VERSION 1

/* commands: enumeration of all commands (functions), 
 * used by userspace application to identify command to be ececuted
 */
enum {
	CMD_LISTENING, /* sent by server */
	CMD_STORE, /* sent by kernel */
	CMD_LOAD, /* sent by kernel */
	CMD_STORE_ACK, /* sent by server */
	CMD_LOADED_DATA, /* sent by server */
	CMD_CLOSE, /* sent by kernel */
	__CMD_MAX,
};
#define CMD_MAX (__CMD_MAX - 1)

/* attributes (variables): the index in this enum is used as a reference for the type,
 *             userspace application has to indicate the corresponding type
 *             the policy is used for security considerations 
 */
enum {
	ATTR_UNSPEC,
	ATTR_STRUCT_LOAD,
	ATTR_STRUCT_LOADED,
	ATTR_STRUCT_STORE,
	ATTR_STORE_U8, /* u8*/
	__ATTR_MAX,
};
#define ATTR_MAX (__ATTR_MAX - 1)

#define MAX_DATA_SIZE 10*1024
#define MAX_RAW_KEY_SIZE 4096

struct storage_item_st {
	/* metadata */
	uint8_t label[MAX_LABEL_SIZE];
	uint32_t owner;
	uint32_t group;
	mode_t mode;
	
	uint16_t algorithm;
	uint8_t type;
	uint32_t flags;

	uint8_t key_id[MAX_KEY_ID_SIZE];
	uint8_t key_id_size;

	/* data */
	uint8_t raw_key[MAX_RAW_KEY_SIZE];
	uint16_t raw_key_size;
} __attribute__ ((__packed__));

struct ncr_gnl_load_cmd_st {
	uint8_t label[MAX_LABEL_SIZE];
	uint32_t owner;
	uint32_t group;
} __attribute__ ((__packed__));

struct ncr_gnl_store_ack_st {
	uint32_t id;
	uint8_t reply;
} __attribute__ ((__packed__));

struct ncr_gnl_loaded_st {
	uint32_t id;
	struct storage_item_st storage;
} __attribute__ ((__packed__));

#endif
