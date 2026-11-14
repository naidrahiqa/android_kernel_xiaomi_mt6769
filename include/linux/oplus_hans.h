/* SPDX-License-Identifier: GPL-2.0 */
/*
 * OPLUS HANS kernel <-> userspace bridge.
 *
 * HANS (Hybrid App Notification Service) keeps background apps in a
 * cgroup-v2 freezer and needs to know when a frozen app is woken up by a
 * binder transaction, an incoming network packet or a signal.  The OPLUS
 * userspace daemon (/system_ext/bin/hans) talks to this driver over the
 * generic netlink family "oplus_hans".
 *
 * Ported to the MediaTek MT6769 4.14 kernel for ColorOS 17.
 */

#ifndef _LINUX_OPLUS_HANS_H
#define _LINUX_OPLUS_HANS_H

#include <linux/types.h>
#include <linux/sched.h>
#include <uapi/linux/android/binder.h>

#define HANS_NOERROR		0
#define HANS_ERROR		(-1)

#define MIN_USERAPP_UID		10000
#define MAX_SYSTEM_UID		2000
#define HANS_SYSTEM_UID		1000
#define INTERFACETOKEN_BUFF_SIZE 140
#define PARCEL_OFFSET		16
#define CPUCTL_VERSION		2

/* Special target_uid values used by the native daemon. */
#define HANS_USE_CGRPV2			(-99)
#define TRANS_BINDER_DEBUG_ON		(-10000)
#define TRANS_BINDER_DEBUG_OFF		(-9000)
#define CHECK_KERN_SUPPORT_CGRPV2	(-8000)

#define HANS_FAMILY_VERSION	1
#define HANS_FAMILY		"oplus_hans"
#define NETLINK_OPLUS_HANS	29

/* Generic netlink attribute type. */
enum {
	HANS_ATTR_MSG_UNDEFINE = 0,
	HANS_ATTR_MSG_GENL,
	__HANS_ATTR_MSG_MAX
};
#define HANS_ATTR_MSG_MAX (__HANS_ATTR_MSG_MAX - 1)

/* Generic netlink command type. */
enum {
	HANS_CMD_UNDEFINE = 0,
	HANS_CMD_GENL,
	__HANS_CMD_MAX
};
#define HANS_CMD_MAX (__HANS_CMD_MAX - 1)

/*
 * Message exchanged with the HANS native daemon.  The layout is part of the
 * userspace ABI: do not reorder or resize any field.  Older (ofreezer 1.0)
 * daemons send everything except the trailing "persistent" field.
 */
struct hans_message {
	int type;
	int port;		/* native daemon pid */
	int caller_uid;		/* caller -> unfreeze UID */
	int caller_pid;		/* caller -> unfreeze UID */
	int target_pid;		/* unfreeze UID, pkg add/remove UID */
	int target_uid;		/* unfreeze UID, pkg add/remove UID */
	int pkg_cmd;		/* add/remove monitored uid */
	int code;
	char rpc_name[INTERFACETOKEN_BUFF_SIZE];
	int persistent;
};

/* Message type, must match userspace. */
enum hans_message_type {
	/* kernel -> native daemon */
	HANS_ASYNC_BINDER,
	HANS_SYNC_BINDER,
	HANS_FROZEN_TRANS,
	HANS_SIGNAL,
	HANS_PKG,

	/* CPU control solution */
	HANS_SYNC_BINDER_CPUCTL,
	HANS_SIGNAL_CPUCTL,
	HANS_CPUCTL_TRANS,

	/* kernel <-> native daemon */
	HANS_LOOP_BACK,
	HANS_TYPE_MAX
};

/* Package command, must match userspace. */
enum hans_pkg_cmd {
	HANS_ADD_ONE_UID,
	HANS_DEL_ONE_UID,
	HANS_DEL_ALL_UID,
	HANS_PKG_CMD_MAX
};

#ifdef CONFIG_OPLUS_FEATURE_HANS

int hans_report(int type, int caller_pid, int caller_uid, int target_pid,
		int target_uid, const char *rpc_name, int code);
void hans_network_cmd_parse(uid_t uid, int persistent, int cmd);
int hans_netfilter_init(void);
void hans_netfilter_deinit(void);

/*
 * Scan the binder state of @uid and report transactions that are waiting for
 * the (frozen) target.  Implemented in drivers/android/binder.c.
 */
void binder_hans_check_frozen_transaction(uid_t uid, int type);

/* Hook call sites (drivers/android/binder.c, binder_alloc.c, kernel/signal.c). */
void hans_binder_trans(struct task_struct *caller, struct task_struct *target,
		       struct binder_transaction_data *tr);
void hans_binder_reply(struct task_struct *target, struct task_struct *caller,
		       struct binder_transaction_data *tr);
void hans_binder_alloc(int pid, size_t size, size_t free_async_space,
		       int is_async);
void hans_send_signal(int sig, struct task_struct *killer,
		      struct task_struct *dst);

#else /* !CONFIG_OPLUS_FEATURE_HANS */

static inline int hans_report(int type, int caller_pid, int caller_uid,
			      int target_pid, int target_uid,
			      const char *rpc_name, int code)
{
	return HANS_ERROR;
}
static inline void hans_network_cmd_parse(uid_t uid, int persistent, int cmd) { }
static inline int hans_netfilter_init(void) { return HANS_ERROR; }
static inline void hans_netfilter_deinit(void) { }
static inline void binder_hans_check_frozen_transaction(uid_t uid, int type) { }
static inline void hans_binder_trans(struct task_struct *caller,
				     struct task_struct *target,
				     struct binder_transaction_data *tr) { }
static inline void hans_binder_reply(struct task_struct *target,
				     struct task_struct *caller,
				     struct binder_transaction_data *tr) { }
static inline void hans_binder_alloc(int pid, size_t size,
				     size_t free_async_space, int is_async) { }
static inline void hans_send_signal(int sig, struct task_struct *killer,
				    struct task_struct *dst) { }

#endif /* CONFIG_OPLUS_FEATURE_HANS */

#endif /* _LINUX_OPLUS_HANS_H */
