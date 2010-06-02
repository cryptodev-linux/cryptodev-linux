#ifndef _STORAGE_LOW
#define _STORAGE_LOW

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
