// SPDX-License-Identifier: GPL-2.0
/*
 * OPLUS HANS netlink bridge.
 *
 * Kernel side of the HANS (Hybrid App Notification Service) freezer.
 * Supports both:
 *  - Raw Netlink Protocol 29 (used by /system_ext/bin/hans on kernel < 5.10)
 *  - Generic Netlink "oplus_hans" (used on kernel >= 5.10)
 *
 * The native daemon performs a LOOP_BACK handshake, registers UIDs whose network
 * traffic should thaw them (PKG) and asks the kernel to scan binder state
 * before freezing a UID (FROZEN_TRANS/CPUCTL_TRANS). The kernel reports
 * binder/signal/network wakeup events back to the daemon.
 *
 * Ported from vendor/oplus/kernel/system/oplus_hans to the MediaTek MT6769
 * 4.14 kernel for ColorOS 17.
 */

#define pr_fmt(fmt) "oplus_hans: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/genetlink.h>
#include <linux/oplus_hans.h>

#define NETLINK_PORT_HANS	(0x15356)

static atomic_t hans_daemon_port;
static bool hans_is_raw_netlink = false;
static struct sock *hans_nl_sock = NULL;

static int hans_handler(struct sk_buff *skb, struct genl_info *info);

static const struct genl_ops hans_genl_ops[] = {
	{
		.cmd = HANS_CMD_GENL,
		.flags = 0,
		.doit = hans_handler,
		.dumpit = NULL,
	},
};

static struct genl_family hans_genl_family = {
	.hdrsize = 0,
	.name = HANS_FAMILY,
	.version = HANS_FAMILY_VERSION,
	.maxattr = HANS_ATTR_MSG_MAX,
	.ops = hans_genl_ops,
	.n_ops = ARRAY_SIZE(hans_genl_ops),
};

static int genl_msg_prepare_usr_msg(unsigned char cmd, size_t size,
				    pid_t pid, struct sk_buff **skbp)
{
	struct sk_buff *skb;

	skb = genlmsg_new(size, GFP_ATOMIC);
	if (!skb) {
		pr_err("new genlmsg alloc failed\n");
		return -ENOMEM;
	}

	genlmsg_put(skb, pid, 0, &hans_genl_family, 0, cmd);
	*skbp = skb;
	return 0;
}

static int genl_msg_mk_usr_msg(struct sk_buff *skb, int type, void *data,
			       int len)
{
	return nla_put(skb, type, len, data);
}

/*
 * Reuse the LOOP_BACK/PKG channel to tell the framework that this kernel
 * supports the cgroup-v2 freezer. The daemon then uses FROZEN_TRANS instead
 * of the legacy CPUCTL solution.
 */
static void hans_kern_support_cgrpv2(void)
{
	hans_report(HANS_PKG, -1, -1, -1, -1, "PKG", HANS_USE_CGRPV2);
	pr_info("hans support cgroupv2\n");
}

/*
 * Report a HANS event to the native daemon. Empty parameters are filled
 * with -1 by the caller.
 */
int hans_report(int type, int caller_pid, int caller_uid, int target_pid,
		int target_uid, const char *rpc_name, int code)
{
	struct hans_message data;
	int port;

	if (type >= HANS_TYPE_MAX) {
		pr_err("type = %d invalid\n", type);
		return HANS_ERROR;
	}

	port = atomic_read(&hans_daemon_port);
	if (port == -1) {
		pr_err("hans daemon port invalid\n");
		return HANS_ERROR;
	}

	memset(&data, 0, sizeof(data));
	data.type = type;
	data.port = NETLINK_PORT_HANS;
	data.caller_pid = caller_pid;
	data.caller_uid = caller_uid;
	data.target_pid = target_pid;
	data.target_uid = target_uid;
	data.pkg_cmd = -1;	/* invalid package cmd */
	data.code = code;
	data.persistent = 0;
	if (rpc_name)
		strlcpy(data.rpc_name, rpc_name, INTERFACETOKEN_BUFF_SIZE);

	/* Raw Netlink protocol 29 mode (kernel 4.14 hans native daemon) */
	if (hans_is_raw_netlink && hans_nl_sock) {
		struct sk_buff *skb;
		struct nlmsghdr *nlh;
		int len = sizeof(struct hans_message);
		int ret;

		skb = nlmsg_new(len, GFP_ATOMIC);
		if (!skb) {
			pr_err("raw nlmsg_new failed\n");
			return HANS_ERROR;
		}

		nlh = nlmsg_put(skb, (u32)port, 0, 0, len, 0);
		if (!nlh) {
			kfree_skb(skb);
			pr_err("raw nlmsg_put failed\n");
			return HANS_ERROR;
		}

		memcpy(nlmsg_data(nlh), &data, len);
		ret = netlink_unicast(hans_nl_sock, skb, (u32)port, MSG_DONTWAIT);
		if (ret < 0) {
			pr_err("netlink_unicast (proto 29) failed, err = %d\n", ret);
			return HANS_ERROR;
		}
		return HANS_NOERROR;
	}

	/* Generic Netlink mode (kernel >= 5.10) */
	{
		struct sk_buff *skb = NULL;
		void *head;
		size_t size;
		int len = sizeof(struct hans_message);
		int ret;

		size = nla_total_size(len);
		ret = genl_msg_prepare_usr_msg(HANS_CMD_GENL, size, (pid_t)port, &skb);
		if (ret) {
			pr_err("genl_msg_prepare_usr_msg failed\n");
			return HANS_ERROR;
		}

		ret = genl_msg_mk_usr_msg(skb, HANS_ATTR_MSG_GENL, &data, len);
		if (ret) {
			pr_err("genl_msg_mk_usr_msg failed\n");
			kfree_skb(skb);
			return HANS_ERROR;
		}

		head = genlmsg_data(nlmsg_data(nlmsg_hdr(skb)));
		genlmsg_end(skb, head);

		ret = genlmsg_unicast(&init_net, skb, (u32)port);
		if (ret < 0) {
			pr_err("genlmsg_unicast failed, err = %d\n", ret);
			return HANS_ERROR;
		}
		return HANS_NOERROR;
	}
}

/* Common parser for messages received from the daemon */
static int hans_process_data(struct hans_message *data, size_t len, bool is_raw)
{
	if (!data)
		return HANS_ERROR;

	pr_debug("hans_process_data: len=%zu, sizeof=%zu, is_raw=%d\n",
		 len, sizeof(struct hans_message), is_raw);

	if (len < (sizeof(struct hans_message) - sizeof(int))) {
		pr_err("hans_message len check failed! len = %zu min = %zu\n",
		       len, sizeof(struct hans_message) - sizeof(int));
		return HANS_ERROR;
	}

	if (data->port < 0) {
		pr_err("portid = %d invalid\n", data->port);
		return HANS_ERROR;
	}

	if (data->type >= HANS_TYPE_MAX) {
		pr_err("type = %d invalid\n", data->type);
		return HANS_ERROR;
	}

	if (atomic_read(&hans_daemon_port) == -1 &&
	    data->type != HANS_LOOP_BACK) {
		pr_err("handshake not setup, type = %d\n", data->type);
		return HANS_ERROR;
	}

	switch (data->type) {
	case HANS_LOOP_BACK:
		hans_is_raw_netlink = is_raw;
		atomic_set(&hans_daemon_port, data->port);
		hans_report(HANS_LOOP_BACK, -1, -1, -1, -1,
			    "loop back", CPUCTL_VERSION);
		pr_info("LOOP_BACK, port = %d (raw_proto29 = %d)\n",
			data->port, is_raw);
		hans_kern_support_cgrpv2();
		break;

	case HANS_PKG:
		if (len < sizeof(struct hans_message)) {
			/* ofreezer 1.0 daemon has no trailing persistent field */
			pr_debug("PKG, 1.0 native, uid = %d, pkg_cmd = %d\n",
				 data->target_uid, data->pkg_cmd);
			hans_network_cmd_parse(data->target_uid, 0,
					       data->pkg_cmd);
			break;
		}
		pr_debug("PKG, uid = %d, persistent = %d, pkg_cmd = %d\n",
			 data->target_uid, data->persistent, data->pkg_cmd);
		hans_network_cmd_parse(data->target_uid, data->persistent,
				       data->pkg_cmd);
		break;

	case HANS_FROZEN_TRANS:
	case HANS_CPUCTL_TRANS:
		if (data->target_uid == CHECK_KERN_SUPPORT_CGRPV2) {
			hans_kern_support_cgrpv2();
		} else {
			pr_debug("FROZEN_TRANS, uid = %d\n", data->target_uid);
			binder_hans_check_frozen_transaction(data->target_uid,
							     data->type);
		}
		break;

	default:
		pr_err("hans_message type invalid %d\n", data->type);
		break;
	}

	return HANS_NOERROR;
}

/* Handler for Raw Netlink Protocol 29 */
static void hans_nl_rcv_msg(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	struct hans_message *data;
	size_t len;

	if (!skb || skb->len < NLMSG_SPACE(0))
		return;

	nlh = nlmsg_hdr(skb);
	if (!nlh || skb->len < nlh->nlmsg_len ||
	    nlh->nlmsg_len < NLMSG_SPACE(sizeof(struct hans_message) - sizeof(int)))
		return;

	data = (struct hans_message *)NLMSG_DATA(nlh);
	len = nlh->nlmsg_len - NLMSG_HDRLEN;
	hans_process_data(data, len, true);
}

/* Handler for Generic Netlink */
static int hans_handler(struct sk_buff *skb, struct genl_info *info)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *genlhdr;
	struct nlattr *nla;
	struct hans_message *data;
	size_t len;

	if (!skb || skb->len < NLMSG_SPACE(0))
		return HANS_NOERROR;

	nlh = nlmsg_hdr(skb);
	genlhdr = nlmsg_data(nlh);
	nla = genlmsg_data(genlhdr);

	if (nla->nla_type != HANS_ATTR_MSG_GENL)
		return HANS_NOERROR;

	len = nla_len(nla);
	data = (struct hans_message *)nla_data(nla);
	return hans_process_data(data, len, false);
}

static int __init hans_core_init(void)
{
	int ret;
	struct netlink_kernel_cfg cfg = {
		.input = hans_nl_rcv_msg,
	};

	atomic_set(&hans_daemon_port, -1);
	hans_is_raw_netlink = false;

	/* 1. Register raw Netlink Protocol 29 for ColorOS 4.14 daemon */
	hans_nl_sock = netlink_kernel_create(&init_net, NETLINK_OPLUS_HANS, &cfg);
	if (!hans_nl_sock)
		pr_err("netlink_kernel_create for proto %d failed\n", NETLINK_OPLUS_HANS);
	else
		pr_info("HANS protocol %d socket created\n", NETLINK_OPLUS_HANS);

	/* 2. Register Generic Netlink family as well */
	ret = genl_register_family(&hans_genl_family);
	if (ret) {
		pr_err("genl_register_family error %d\n", ret);
		if (hans_nl_sock) {
			netlink_kernel_release(hans_nl_sock);
			hans_nl_sock = NULL;
		}
		return HANS_ERROR;
	}

	/* 3. Register Netfilter hooks */
	ret = hans_netfilter_init();
	if (ret == HANS_ERROR) {
		pr_err("netfilter init failed\n");
		genl_unregister_family(&hans_genl_family);
		if (hans_nl_sock) {
			netlink_kernel_release(hans_nl_sock);
			hans_nl_sock = NULL;
		}
		return HANS_ERROR;
	}

	pr_info("HANS bridge initialized\n");
	return HANS_NOERROR;
}

static void __exit hans_core_exit(void)
{
	hans_netfilter_deinit();
	genl_unregister_family(&hans_genl_family);
	if (hans_nl_sock) {
		netlink_kernel_release(hans_nl_sock);
		hans_nl_sock = NULL;
	}
	pr_info("HANS bridge exited\n");
}

module_init(hans_core_init);
module_exit(hans_core_exit);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("OPLUS / ported for selene");
MODULE_DESCRIPTION("OPLUS HANS kernel bridge");
