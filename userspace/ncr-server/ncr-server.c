#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include "../ncr-storage-low.h"
#include "ncr-server.h"
#include "list.h"

static int _notify_listening(int family, struct nl_handle * sock);

static struct nla_policy def_policy[ATTR_MAX+1] =
{
     [ATTR_STRUCT_STORE] = { .type = NLA_UNSPEC,
                          .minlen = sizeof(struct storage_item_st) },
     [ATTR_STRUCT_LOAD] = { .type = NLA_UNSPEC,
                          .minlen = sizeof(struct ncr_gnl_load_cmd_st) },
};

struct todo_actions {
	struct list_head list;
	int cmd; /* CMD_* */
	union {
		struct storage_item_st tostore;
		struct ncr_gnl_load_cmd_st toload;
	} data;
};

static struct todo_actions todo;

static int add_store_cmd(struct storage_item_st* tostore)
{
	struct todo_actions* item;

	item = malloc(sizeof(*item));
	if (item == NULL) {
		err();
		return -ERR_MEM;
	}
	item->cmd = CMD_STORE;
	memcpy(&item->data.tostore, tostore, sizeof(item->data.tostore));

	list_add(&item->list, &todo.list);
	return 0;
}

static int add_load_cmd(struct ncr_gnl_load_cmd_st* toload)
{
	struct todo_actions* item;

	item = malloc(sizeof(*item));
	if (item == NULL) {
		err();
		return -ERR_MEM;
	}
	item->cmd = CMD_LOAD;
	memcpy(&item->data.toload, toload, sizeof(item->data.toload));

	list_add(&item->list, &todo.list);
	return 0;
}

static int msg_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlattr *attrs[ATTR_MAX+1];

fprintf(stderr, "Received message: ");
		// Validate message and parse attributes
	genlmsg_parse(nlh, 0, attrs, ATTR_MAX, def_policy);

	if (attrs[ATTR_STRUCT_STORE]) {
		struct nl_data* data = nla_get_data(attrs[ATTR_STRUCT_STORE]);
		struct storage_item_st *item = nl_data_get(data);

fprintf(stderr, "Store!\n");
		
		if (nl_data_get_size(data) != sizeof(struct storage_item_st)) {
			err();
			fprintf(stderr, "Received incorrect structure!\n");
			return -1;
		}
		fprintf(stderr, "asked to store: %s\n", item->label);

		add_store_cmd(item);
	}

	if (attrs[ATTR_STRUCT_LOAD]) {
		struct nl_data* data = nla_get_data(attrs[ATTR_STRUCT_STORE]);
		struct ncr_gnl_load_cmd_st *load = nl_data_get(data);

fprintf(stderr, "Load!\n");
		if (nl_data_get_size(data) != sizeof(struct ncr_gnl_load_cmd_st)) {
			err();
			fprintf(stderr, "Received incorrect structure!\n");
			return -1;
		}
		fprintf(stderr, "asked to load: %s\n", load->label);

		add_load_cmd(load);
	}
fprintf(stderr, "\n");
	return NL_STOP;
}


int main()
{
struct nl_handle *sock;
int ret, family;

	memset(&todo, 0, sizeof(todo));
	INIT_LIST_HEAD(&todo.list);

	// Allocate a new netlink socket
	sock = nl_handle_alloc();
	if (sock == NULL) {
		err();
		return ERR_CONNECT;
	}

	// Connect to generic netlink socket on kernel side
	ret = genl_connect(sock);
	if (ret < 0) {
		err();
		return ERR_CONNECT;
	}
	
	// Ask kernel to resolve family name to family id
	family = genl_ctrl_resolve(sock, NCR_NL_STORAGE_NAME);
	if (family < 0) {
		err();
		return ERR_CONNECT;
	}

	/* set our callback to receive messages */
	ret = nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, msg_cb, NULL);
	if (ret < 0) {
		fprintf(stderr, "Could not set listening callback.\n");
		exit(1);
	}

	ret = _notify_listening(family, sock);
	if (ret < 0) {
		fprintf(stderr, "Could not notify kernel subsystem.\n");
		exit(1);
	}
	fprintf(stderr, "Notified kernel for being a listener...\n");

	// Wait for the answer and receive it
	do {
		fprintf(stderr, "Waiting for message...\n");
		ret = nl_recvmsgs_default(sock);

		/* we have to consume the todo list */
		if (ret == 0) {
			//store_if_needed(sock);
			//load_if_needed(sock);
		}
	} while (ret == 0);
	fprintf(stderr, "received: %d\n", ret);

	return 0;
}

static int _notify_listening(int family, struct nl_handle * sock)
{
struct nl_msg *msg;
void * hdr;
int ret;

	// Construct a generic netlink by allocating a new message, fill in
	// the header and append a simple integer attribute.
	msg = nlmsg_alloc();
	if (msg == NULL) {
		err();
		return ERR_MEM;
	}

	hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_REQUEST,
	 CMD_LISTENING, NCR_NL_STORAGE_VERSION);
	 
	if (hdr == NULL) {
		err();
		return ERR_SEND;
	}

	// Send message over netlink socket
	ret = nl_send_auto_complete(sock, msg);
	nlmsg_free(msg);

	if (ret < 0) {
		err();
		return ERR_CONNECT;
	}

	return 0;
}


static int send_store_ack(int family, struct nl_handle * sock, uint8_t val)
{
struct nl_msg *msg;
int ret;

	// Construct a generic netlink by allocating a new message, fill in
	// the header and append a simple integer attribute.
	msg = nlmsg_alloc();
	if (msg == NULL) {
		err();
		return ERR_MEM;
	}

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_REQUEST,
	 CMD_STORE_ACK, NCR_NL_STORAGE_VERSION);

	ret = nla_put_u8(msg, ATTR_STORE_U8, val);
	if (ret < 0) {
		err();
		ret = ERR_SEND;
		goto fail;
	}

	// Send message over netlink socket
	ret = nl_send_auto_complete(sock, msg);
	nlmsg_free(msg);

	if (ret < 0) {
		err();
		return ERR_SEND;
	}

	return 0;
fail:
	nlmsg_free(msg);
	return ret;
}
