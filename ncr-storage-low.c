/*
 * New driver for /dev/crypto device (aka CryptoDev)

 * Copyright (c) 2010 Nikos Mavrogiannopoulos <nmav@gnutls.org>
 *
 * This file is part of linux cryptodev.
 *
 * cryptodev is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cryptodev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/mm.h>
#include <linux/highmem.h>
#include "cryptodev.h"
#include <asm/uaccess.h>
#include <net/genetlink.h>
#include <linux/kernel.h>
#include <linux/completion.h>
#include "ncr.h"
#include "ncr_int.h"
#include "ncr-storage.h"
#include "ncr-storage-low.h"

/* The idea here is to have communication via netlink to userspace
 * send our commands, put an id in the list and wait for completion of the
 * request. The server should compute our request and reply with the id.
 */

struct event_item_st {
	struct list_head list;
	struct completion completed;
	void* reply;
	size_t reply_size;
	uint32_t ireply;
	uint32_t id;
};


static struct list_sem_st event_list;

static int event_add(uint32_t id)
{
struct event_item_st* item;

	item = kmalloc( sizeof(*item), GFP_KERNEL);
	if (item == NULL) {
		err();
		return -ENOMEM;
	}
	item->id = id;
	item->reply = NULL;
	item->reply_size = 0;
	item->ireply = -1;
	init_completion(&item->completed);

	down(&event_list.sem);
	list_add(&item->list, &event_list.list);
	up(&event_list.sem);

	return 0;
}

static int event_wait(uint32_t id)
{
struct event_item_st* item;
struct completion* completed = NULL;

	down(&event_list.sem);
	list_for_each_entry(item, &event_list.list, list) {
		if (id == item->id) {
			completed = &item->completed;
			break;
		}
	}
	up(&event_list.sem);
	
	if (completed) {
		return wait_for_completion_interruptible(completed);
	} else {
		err();
		return -EIO;
	}
}


static void event_complete(uint32_t id)
{
struct event_item_st* item;

	down(&event_list.sem);

	list_for_each_entry(item, &event_list.list, list) {
		if (id == item->id) {
			complete(&item->completed);
			break;
		}
	}
	up(&event_list.sem);
}

static void event_set_data(uint32_t id, void* data, size_t data_size)
{
struct event_item_st* item;

	down(&event_list.sem);

	list_for_each_entry(item, &event_list.list, list) {
		if (id == item->id) {
			item->reply = data;
			item->reply_size = data_size;
			break;
		}
	}
	up(&event_list.sem);
	
	return;
}

static void event_set_idata(uint32_t id, uint32_t data)
{
struct event_item_st* item;

	down(&event_list.sem);

	list_for_each_entry(item, &event_list.list, list) {
		if (id == item->id) {
			item->ireply = data;
			break;
		}
	}
	up(&event_list.sem);
	
	return;
}

static void* event_get_data(uint32_t id, size_t *reply_size)
{
struct event_item_st* item;
void* reply = NULL;

	down(&event_list.sem);

	list_for_each_entry(item, &event_list.list, list) {
		if (id == item->id) {
			reply = &item->reply;
			*reply_size = item->reply_size;
			break;
		}
	}
	up(&event_list.sem);
	
	return reply;
}

static uint32_t event_get_idata(uint32_t id)
{
struct event_item_st* item;
uint32_t reply = -1;

	down(&event_list.sem);

	list_for_each_entry(item, &event_list.list, list) {
		if (id == item->id) {
			reply = item->ireply;
			break;
		}
	}
	up(&event_list.sem);
	
	return reply;
}

static void event_remove(uint32_t id)
{
struct event_item_st* item, *tmp;

	down(&event_list.sem);

	list_for_each_entry_safe(item, tmp, &event_list.list, list) {
		if (id == item->id) {
			list_del(&item->list);
			if (item->reply)
				kfree(item->reply);
			kfree(item);
			break;
		}
	}
	up(&event_list.sem);
}


/* attribute policy: defines which attribute has which type (e.g int, char * etc)
 * possible values defined in net/netlink.h 
 */
static struct nla_policy ncr_genl_policy[ATTR_MAX + 1] = {
	[ATTR_STRUCT_LOAD] = { .type = NLA_BINARY },
	[ATTR_STRUCT_LOADED] = { .type = NLA_BINARY },
	[ATTR_STORE_U8] = { .type = NLA_BINARY },
	[ATTR_STRUCT_STORE] = { .type = NLA_BINARY },
};

static atomic_t ncr_event_sr;
static uint32_t listener_pid = -1;

/* family definition */
static struct genl_family ncr_gnl_family = {
	.id = GENL_ID_GENERATE,         //genetlink should generate an id
	.hdrsize = 0,
	.name = NCR_NL_STORAGE_NAME,        //the name of this family, used by userspace application
	.version = NCR_NL_STORAGE_VERSION,  //version number  
	.maxattr = ATTR_MAX,
};

/* an echo command, receives a message, prints it and sends another message back */
static void _ncr_nl_close(void)
{
	struct sk_buff *skb;
	int ret;
	void *msg_head;
	uint32_t id;

	if (listener_pid == -1) {
		err();
		return;
	}
	
	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	id = atomic_add_return(1, &ncr_event_sr);
	msg_head = genlmsg_put(skb, 0, id, &ncr_gnl_family, 0, CMD_CLOSE);
	if (msg_head == NULL) {
		err();
		ret = -ENOMEM;
		goto out;
	}
	
	ret = nla_put_u8(skb, ATTR_STORE_U8, 1);
	if (ret != 0) {
		err();
		goto out;
	}

	/* finalize the message */
	genlmsg_end(skb, msg_head);

	/* send the message back */
	ret = genlmsg_unicast(skb, listener_pid);
	if (ret != 0) {
		err();
		goto out;
	}

	return;

out:
	nlmsg_free(skb);
	printk("an error occured in ncr_gnl_store\n");
  
	return;
}

/* an echo command, receives a message, prints it and sends another message back */
int _ncr_store(const struct storage_item_st * tostore)
{
	struct sk_buff *skb;
	int ret;
	uint32_t reply;
	size_t size;
	struct nlattr *attr;
	void* msg, *msg_head;
	uint32_t id;

	if (listener_pid == -1) {
		err();
		return -EIO;
	}

	/* send a message back*/
	/* allocate some memory, since the size is not yet known use NLMSG_GOODSIZE*/
	size = nla_total_size(sizeof(struct storage_item_st)) +
            nla_total_size(0);

	skb = genlmsg_new(size, GFP_KERNEL);
	if (skb == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	id = atomic_add_return(1, &ncr_event_sr);
	msg_head = genlmsg_put(skb, 0, id,
		&ncr_gnl_family, 0, CMD_STORE);
	if (msg_head == NULL) {
		err();
		ret = -ENOMEM;
		goto out;
	}

	/* fill the data */
	attr = nla_reserve(skb, ATTR_STRUCT_STORE,
					sizeof(struct storage_item_st));
	if (!attr) {
		err();
		ret = -EINVAL;
		goto out;
	}

	msg = nla_data(attr);
	if (!msg) {
		err();
		ret = -EINVAL;
		goto out;
	}

	memcpy(msg, tostore, sizeof(*tostore));

	/* finalize the message */
	genlmsg_end(skb, msg_head);

	ret = event_add(id);
	if (ret < 0) {
		err();
		goto out;
	}

	/* send the message back */
	ret = genlmsg_unicast(skb, listener_pid);
	if (ret != 0)
		goto out;

	/* wait for an acknowledgment */
	ret = event_wait(id);
	if (ret) {
		err();
		printk(KERN_DEBUG"Error waiting for id %u\n", id);
		event_remove(id);
		return ret;
	}

	reply = event_get_idata(id);
	if (reply == (uint32_t)-1)
		BUG();

	if (reply != 0) {
		/* write failed */
		ret = -EIO;
	} else {
		ret = 0;
	}

	event_remove(id);
	return ret;

out:
	nlmsg_free(skb);
	printk("an error occured in ncr_gnl_store\n");
  
	return ret;
}


/* an echo command, receives a message, prints it and sends another message back */
int _ncr_load(struct storage_item_st * toload)
{
	struct sk_buff *skb;
	int ret;
	void *msg_head;
	size_t reply_size=0, size;
	struct nlattr *attr;
	void* msg, *reply;
	struct ncr_gnl_load_cmd_st cmd;
	uint32_t id;

	if (listener_pid == -1) {
		err();
		return -EIO;
	}
	
	/* send a message back*/
	/* allocate some memory, since the size is not yet known use NLMSG_GOODSIZE*/
	size = nla_total_size(sizeof(struct ncr_gnl_load_cmd_st)) +
            nla_total_size(0);

	skb = genlmsg_new(size, GFP_KERNEL);
	if (skb == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	id = atomic_add_return(1, &ncr_event_sr);
	msg_head = genlmsg_put(skb, 0, id,
		&ncr_gnl_family, 0, CMD_LOAD);
	if (msg_head == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	/* fill the data */
	attr = nla_reserve(skb, ATTR_STRUCT_LOAD,
					sizeof(struct ncr_gnl_load_cmd_st));
	if (!attr) {
		err();
		ret = -EINVAL;
		goto out;
	}

	msg = nla_data(attr);
	if (!msg) {
		err();
		ret = -EINVAL;
		goto out;
	}

	cmd.owner = toload->owner;
	cmd.group = toload->group;
	strcpy(cmd.label, toload->label);

	memcpy(msg, &cmd, sizeof(cmd));

	/* finalize the message */
	genlmsg_end(skb, msg_head);

	ret = event_add(id);
	if (ret < 0) {
		err();
		goto out;
	}

	/* send the message */
	ret = genlmsg_unicast(skb, listener_pid);
	if (ret != 0)
		goto out;

	/* wait for an answer */
	ret = event_wait(id);
	if (ret) {
		err();
		printk(KERN_DEBUG"Error waiting for id %u\n", id);
		event_remove(id);
		return ret;
	}

	reply = event_get_data(id, &reply_size);
	if (reply_size != sizeof(struct storage_item_st))
		BUG();

	memcpy(toload, reply, reply_size);

	event_remove(id);

	return 0;

out:
	nlmsg_free(skb);
	printk("an error occured in ncr_gnl_store\n");
  
	return ret;
}

/* with this command the userspace server registers */
int ncr_gnl_listen(struct sk_buff *skb, struct genl_info *info)
{
	if (info == NULL)
		return -EIO;

	listener_pid = info->snd_pid;
	atomic_set(&ncr_event_sr, info->snd_seq+1);
	printk(KERN_DEBUG"Setting listener pid to %d!\n", (int)listener_pid);

	return 0;
}


/* with this command the userspace server registers */
int ncr_gnl_store_ack(struct sk_buff *skb, struct genl_info *info)
{
	uint8_t * data;
	size_t len;
	struct ncr_gnl_store_ack_st *reply;
	struct nlattr *na;
	
	if (info == NULL)
		return -EIO;

	printk("Received store ack!\n");
	/*for each attribute there is an index in info->attrs which points to a nlattr structure
	 *in this structure the data is given
	 */
	na = info->attrs[ATTR_STORE_U8];
	if (na) {
		len = nla_len(na);
		data = (void *)nla_data(na);
		if (data == NULL || len != sizeof(struct ncr_gnl_store_ack_st))
			printk(KERN_DEBUG"error while receiving data\n");
		else {
			reply = (void*)data;
			event_set_idata(reply->id, (uint32_t)reply->reply);

			event_complete(reply->id);
		}
	} else
		printk(KERN_DEBUG"no info->attrs %i\n", ATTR_STORE_U8);

	return 0;
}

/* an echo command, receives a message, prints it and sends another message back */
int ncr_gnl_loaded_data(struct sk_buff *skb, struct genl_info *info)
{
	uint8_t * data, *event_reply;
	size_t len;
	struct ncr_gnl_loaded_st *reply;
	struct nlattr *na;
	
	if (info == NULL)
		return -EIO;

	/*for each attribute there is an index in info->attrs which points to a nlattr structure
	 *in this structure the data is given
	 */
	na = info->attrs[ATTR_STRUCT_LOADED];
	if (na) {
		len = nla_len(na);
		data = (void *)nla_data(na);
		if (data == NULL || len != sizeof(struct ncr_gnl_loaded_st))
			printk(KERN_DEBUG"error while receiving data\n");
		else {
			reply = (void*)data;
			event_reply = kmalloc(sizeof(reply->storage), GFP_KERNEL);
			if (event_reply != NULL) {
				memcpy(event_reply, &reply->storage, sizeof(reply->storage));
				event_set_data(reply->id, event_reply, sizeof(reply->storage));
			}
			event_complete(reply->id);
		}
	} else
		printk(KERN_DEBUG"no info->attrs %i\n", ATTR_STRUCT_LOADED);

	return 0;
}


/* commands: mapping between the command enumeration and the actual function*/
struct genl_ops ncr_gnl_ops_listen = {
	.cmd = CMD_LISTENING,
	.flags = 0,
	.policy = ncr_genl_policy,
	.doit = ncr_gnl_listen,
	.dumpit = NULL,
};

struct genl_ops ncr_gnl_ops_load = {
	.cmd = CMD_LOADED_DATA,
	.flags = 0,
	.policy = ncr_genl_policy,
	.doit = ncr_gnl_loaded_data,
	.dumpit = NULL,
};

struct genl_ops ncr_gnl_ops_store_ack = {
	.cmd = CMD_STORE_ACK,
	.flags = 0,
	.policy = ncr_genl_policy,
	.doit = ncr_gnl_store_ack,
	.dumpit = NULL,
};



int ncr_gnl_init(void)
{
	int rc;

    printk(KERN_NOTICE"cryptodev: Initializing netlink subsystem.\n");

	init_MUTEX(&event_list.sem);
	INIT_LIST_HEAD(&event_list.list);
    atomic_set(&ncr_event_sr, 1);

    /*register new family*/
	rc = genl_register_family(&ncr_gnl_family);
	if (rc != 0) {
		err();
		goto failure;
	}
    /*register functions (commands) of the new family*/

	rc = genl_register_ops(&ncr_gnl_family, &ncr_gnl_ops_listen);
	if (rc != 0) {
		err();
		genl_unregister_family(&ncr_gnl_family);
		goto failure;
	}

	rc = genl_register_ops(&ncr_gnl_family, &ncr_gnl_ops_store_ack);
	if (rc != 0) {
		err();
		genl_unregister_family(&ncr_gnl_family);
		goto failure;
	}

	rc = genl_register_ops(&ncr_gnl_family, &ncr_gnl_ops_load);
	if (rc != 0) {
		err();
		genl_unregister_family(&ncr_gnl_family);
		goto failure;
	}

	return 0;
	
  failure:
    printk(KERN_ERR"an error occured while loading the cryptodev netlink subsystem\n");
	return rc;	
}

void ncr_gnl_deinit(void)
{
	int ret;
	struct event_item_st *item, *tmp;

	_ncr_nl_close();

	ret = genl_unregister_ops(&ncr_gnl_family, &ncr_gnl_ops_store_ack);
	if(ret != 0) {
		printk("unregister ops: %i\n",ret);
		return;
	}

	ret = genl_unregister_ops(&ncr_gnl_family, &ncr_gnl_ops_load);
	if(ret != 0) {
		printk("unregister ops: %i\n",ret);
		return;
	}

	ret = genl_unregister_ops(&ncr_gnl_family, &ncr_gnl_ops_listen);
	if(ret != 0) {
		printk("unregister ops: %i\n",ret);
		return;
	}

	/*unregister the family*/
	ret = genl_unregister_family(&ncr_gnl_family);
	if(ret !=0) {
		printk("unregister family %i\n",ret);
	}

	/* deinitialize the event list */
	down(&event_list.sem);
	list_for_each_entry_safe(item, tmp, &event_list.list, list) {
		list_del(&item->list);
		if (item->reply)
			kfree(item->reply);
		kfree(item);
	}
	up(&event_list.sem);

}
