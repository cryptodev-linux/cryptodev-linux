#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include "../ncr-storage-low.h"
#include "ncr-server.h"
#include <list.h>

static int _notify_listening(struct nl_sock * sock);

static struct nla_policy def_policy[ATTR_MAX+1] =
{
     [ATTR_STRUCT_STORE] = { .type = NLA_UNSPEC,
                          .minlen = sizeof(struct storage_item_st) },
     [ATTR_STRUCT_LOAD] = { .type = NLA_UNSPEC,
                          .minlen = sizeof(struct ncr_gnl_load_cmd_st) },
};

static struct actions {
	list_head list;
	int cmd; /* CMD_* */
	union {
		struct storage_item_st tostore;
		struct ncr_gnl_load_cmd_st toload;
	} data;
} todo;

static int add_store_cmd(struct storage_item_st* tostore)
{
	struct actions* item;

	item = malloc(sizeof(*item));
	if (item == NULL) {
		err();
		return -ERR_MEM;
	}
	item->cmd = CMD_STORE;
	memcpy(item->data.tostore, tostore, sizeof(item->data.tostore));

	list_add(item, &todo.list);
	return 0;
}

static int add_load_cmd(struct ncr_gnl_load_cmd_st* toload)
{
	struct actions* item;

	item = malloc(sizeof(*item));
	if (item == NULL) {
		err();
		return -ERR_MEM;
	}
	item->cmd = CMD_LOAD;
	memcpy(item->data.toload, toload, sizeof(item->data.toload));

	list_add(item, &todo.list);
	return 0;
}

static int msg_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlattr *attrs[ATTR_MAX+1];

		// Validate message and parse attributes
	genlmsg_parse(nlh, 0, attrs, ATTR_MAX, def_policy);

	if (attrs[ATTR_STRUCT_STORE]) {
		struct storage_item_st *item = nla_get(attrs[ATTR_STRUCT_STORE]);
		fprintf(stderr, "asked to store: %s\n", item->label);

		add_store_cmd(item);
	}

	if (attrs[ATTR_STRUCT_LOAD]) {
		struct ncr_gnl_load_cmd_st *load = nla_get(attrs[ATTR_STRUCT_LOAD]);
		fprintf(stderr, "asked to load: %s\n", load->label);

		add_load_cmd(item);
	}

	return NL_STOP;
}


int main()
{
struct nl_sock *sock;
int ret;

	memset(&todo, 0, sizeof(todo));
	LIST_HEAD_INIT(&todo.list);

	// Allocate a new netlink socket
	sock = nl_socket_alloc();
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

	ret = _notify_listening(sock);
	if (ret < 0) {
		fprintf(stderr, "Could not notify kernel subsystem.\n");
		exit(1);
	}

	// Wait for the answer and receive it
	do {
		ret = nl_recvmsgs_default(sock);

		/* we have to consume the todo list */
		if (ret == 0) {
			//store_if_needed(sock);
			//load_if_needed(sock);
		}
	} while (ret == 0);
	fprintf(stderr, "received: %d\n", ret);

}

static int _notify_listening(struct nl_sock * sock)
{
struct nl_msg *msg;
int family, ret;

	// Construct a generic netlink by allocating a new message, fill in
	// the header and append a simple integer attribute.
	msg = nlmsg_alloc();
	if (msg == NULL) {
		err();
		return ERR_MEM;
	}

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_REQUEST,
	 CMD_LISTENING, NCR_NL_STORAGE_VERSION);

	// Send message over netlink socket
	ret = nl_send_auto_complete(sock, msg);
	nlmsg_free(msg);

	if (ret < 0) {
		err();
		return ERR_CONNECT;
	}

	return 0;
}


static int send_store_ack(struct nl_sock * sock, uint8_t val)
{
struct nl_msg *msg;
int family, ret;

	// Construct a generic netlink by allocating a new message, fill in
	// the header and append a simple integer attribute.
	msg = nlmsg_alloc();
	if (msg == NULL) {
		err();
		return ERR_MEM;
	}

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_REQUEST,
	 CMD_STORE_ACK, NCR_NL_STORAGE_VERSION);

	ret = nla_put_u8(msg, ATTR_STORE_ACK, val);
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
