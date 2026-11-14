// SPDX-License-Identifier: GPL-2.0
/*
 * OPLUS HANS network wakeup tracking.
 *
 * The HANS daemon registers UIDs that must be thawed when an incoming TCP
 * packet arrives.  Packets are matched by the socket owner UID, so no
 * connection tracking is required.
 *
 * Ported from vendor/oplus/kernel/system/oplus_hans/hans_netfilter.c.
 */

#define pr_fmt(fmt) "oplus_hans: " fmt

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/rtnetlink.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <linux/jiffies.h>
#include <linux/hashtable.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/oplus_hans.h>

/* hashmap for monitored uids */
#define HANS_UID_HASH_BITS	6
static DEFINE_HASHTABLE(uid_map, HANS_UID_HASH_BITS);
struct uid_info {
	uid_t uid;
	struct hlist_node hnode;
};

/* hashmap for persistent uids */
#define HANS_P_UID_HASH_BITS	5
static DEFINE_HASHTABLE(p_uid_map, HANS_P_UID_HASH_BITS);
struct p_uid_info {
	uid_t uid;
	unsigned long last_arrival_time;	/* jiffies */
	struct hlist_node hnode;
};

/* both maps use the same lock */
static DEFINE_SPINLOCK(map_lock);

/*
 * persistent == 0: add a monitored uid, removed on the next received packet
 * persistent == 1: add a persistent uid
 * persistent == 2: remove a persistent uid
 */
static int hans_add_uid_hash(uid_t target_uid, int persistent)
{
	unsigned long flags;
	struct p_uid_info *p_info;
	struct uid_info *info;

	spin_lock_irqsave(&map_lock, flags);

	if (persistent == 1) {
		hash_for_each_possible(p_uid_map, p_info, hnode, target_uid) {
			if (p_info->uid == target_uid) {
				spin_unlock_irqrestore(&map_lock, flags);
				pr_warn("uid %d is already in p_uid_map\n",
					target_uid);
				return -1;
			}
		}

		p_info = kmalloc(sizeof(*p_info), GFP_ATOMIC);
		if (!p_info) {
			spin_unlock_irqrestore(&map_lock, flags);
			pr_warn("uid %d not added to p_uid_map, no memory\n",
				target_uid);
			return -1;
		}
		p_info->uid = target_uid;
		p_info->last_arrival_time = 0UL;
		hash_add(p_uid_map, &p_info->hnode, target_uid);
		spin_unlock_irqrestore(&map_lock, flags);
		pr_info("uid %d added to p_uid_map\n", target_uid);
		return 0;
	} else if (persistent == 2) {
		hash_for_each_possible(p_uid_map, p_info, hnode, target_uid) {
			if (p_info->uid == target_uid) {
				hash_del(&p_info->hnode);
				kfree(p_info);
				spin_unlock_irqrestore(&map_lock, flags);
				pr_info("uid %d removed from p_uid_map\n",
					target_uid);
				return 0;
			}
		}
		spin_unlock_irqrestore(&map_lock, flags);
		pr_warn("uid %d to remove not found in p_uid_map\n",
			target_uid);
		return -1;
	}

	/* search monitored uid map */
	hash_for_each_possible(uid_map, info, hnode, target_uid) {
		if (info->uid == target_uid) {
			spin_unlock_irqrestore(&map_lock, flags);
			pr_warn("uid %d is already in uid_map\n", target_uid);
			return -1;
		}
	}

	/* search persistent uid map */
	hash_for_each_possible(p_uid_map, p_info, hnode, target_uid) {
		if (p_info->uid == target_uid) {
			if (time_before(jiffies,
					p_info->last_arrival_time + HZ)) {
				spin_unlock_irqrestore(&map_lock, flags);
				pr_warn("uid=%d less than 1s after last packet\n",
					target_uid);
				/* it just received traffic, do not freeze it */
				if (hans_report(HANS_PKG, -1, target_uid, -1,
						target_uid, "PKG", -1) !=
				    HANS_NOERROR)
					pr_err("hans_report PKG failed, uid = %d\n",
					       target_uid);
				return -1;
			}
		}
	}

	info = kmalloc(sizeof(*info), GFP_ATOMIC);
	if (!info) {
		spin_unlock_irqrestore(&map_lock, flags);
		pr_warn("uid %d not added to uid_map, no memory\n",
			target_uid);
		return -1;
	}
	info->uid = target_uid;
	hash_add(uid_map, &info->hnode, target_uid);
	spin_unlock_irqrestore(&map_lock, flags);
	pr_info("uid %d added to uid_map\n", target_uid);
	return 0;
}

static void hans_save_persistent_uid_info_hash(uid_t target_uid,
					       struct sk_buff *skb)
{
	unsigned long flags;
	struct p_uid_info *p_info;

	if (ip_hdr(skb)->version == 4) {
		struct iphdr *iph = ip_hdr(skb);

		if (iph->protocol == IPPROTO_TCP) {
			struct tcphdr *tcph = tcp_hdr(skb);
			int tcp_payload_len = ntohs(iph->tot_len) -
					      ip_hdrlen(skb) -
					      (tcph->doff * 4);

			if (tcp_payload_len > 0) {
				spin_lock_irqsave(&map_lock, flags);
				hash_for_each_possible(p_uid_map, p_info, hnode,
						       target_uid) {
					if (p_info->uid == target_uid) {
						p_info->last_arrival_time =
							jiffies;
						break;
					}
				}
				spin_unlock_irqrestore(&map_lock, flags);
			}
		}
#if IS_ENABLED(CONFIG_IPV6)
	} else if (ip_hdr(skb)->version == 6) {
		struct ipv6hdr *ipv6h = ipv6_hdr(skb);

		if (ipv6h->nexthdr == NEXTHDR_TCP) {
			struct tcphdr *tcph = tcp_hdr(skb);
			int tcp_payload_len = ntohs(ipv6h->payload_len) -
					      (tcph->doff * 4);

			if (tcp_payload_len > 0) {
				spin_lock_irqsave(&map_lock, flags);
				hash_for_each_possible(p_uid_map, p_info, hnode,
						       target_uid) {
					if (p_info->uid == target_uid) {
						p_info->last_arrival_time =
							jiffies;
						break;
					}
				}
				spin_unlock_irqrestore(&map_lock, flags);
			}
		}
#endif
	}
}

static bool hans_find_remove_monitored_uid_hash(uid_t target_uid)
{
	bool found = false;
	unsigned long flags;
	struct uid_info *info;

	spin_lock_irqsave(&map_lock, flags);
	hash_for_each_possible(uid_map, info, hnode, target_uid) {
		if (info->uid == target_uid) {
			hash_del(&info->hnode);
			kfree(info);
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&map_lock, flags);

	if (found)
		pr_info("uid %d found and removed from uid_map\n", target_uid);

	return found;
}

static void hans_remove_all_monitored_uid_hash(void)
{
	unsigned long flags;
	int bkt;
	struct hlist_node *tmp;
	struct uid_info *info;
	struct p_uid_info *p_info;

	spin_lock_irqsave(&map_lock, flags);

	hash_for_each_safe(uid_map, bkt, tmp, info, hnode) {
		hash_del(&info->hnode);
		kfree(info);
	}

	hash_for_each_safe(p_uid_map, bkt, tmp, p_info, hnode) {
		hash_del(&p_info->hnode);
		kfree(p_info);
	}

	hash_init(uid_map);
	hash_init(p_uid_map);

	spin_unlock_irqrestore(&map_lock, flags);
}

static inline uid_t sock2uid(struct sock *sk)
{
	if (sk && sk->sk_socket)
		return SOCK_INODE(sk->sk_socket)->i_uid.val;

	return 0;
}

void hans_network_cmd_parse(uid_t uid, int persistent, int cmd)
{
	switch (cmd) {
	case HANS_ADD_ONE_UID:
		hans_add_uid_hash(uid, persistent);
		break;
	case HANS_DEL_ONE_UID:
		hans_find_remove_monitored_uid_hash(uid);
		break;
	case HANS_DEL_ALL_UID:
		hans_remove_all_monitored_uid_hash();
		break;
	default:
		pr_err("pkg_cmd type invalid %d\n", cmd);
		break;
	}
}

/* Monitor the registered UIDs with a netfilter LOCAL_IN hook. */
static unsigned int hans_nf_ipv4v6_in(void *priv, struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	struct sock *sk;
	uid_t uid;
	unsigned int thoff = 0;
	unsigned short frag_off = 0;
	bool found;

	if (!skb || !skb->len || !state)
		return NF_ACCEPT;

	if (!state->in)
		return NF_ACCEPT;

	if (ip_hdr(skb)->version == 4) {
		if (ip_hdr(skb)->protocol != IPPROTO_TCP)
			return NF_ACCEPT;
#if IS_ENABLED(CONFIG_IPV6)
	} else if (ip_hdr(skb)->version == 6) {
		if (ipv6_find_hdr(skb, &thoff, -1, &frag_off, NULL) !=
		    IPPROTO_TCP)
			return NF_ACCEPT;
#endif
	} else {
		return NF_ACCEPT;
	}

	sk = skb_to_full_sk(skb);
	if (!sk)
		return NF_ACCEPT;
	if (!sk_fullsock(sk))
		return NF_ACCEPT;

	uid = sock2uid(sk);
	if (uid < MIN_USERAPP_UID)
		return NF_ACCEPT;

	hans_save_persistent_uid_info_hash(uid, skb);

	/* Find the monitored UID and clear it from the monitored array. */
	found = hans_find_remove_monitored_uid_hash(uid);
	if (!found)
		return NF_ACCEPT;

	if (hans_report(HANS_PKG, -1, -1, -1, uid, "PKG", -1) != HANS_NOERROR)
		pr_err("hans_report PKG failed, uid = %d\n", uid);

	return NF_ACCEPT;
}

/* Only monitor incoming network packets. */
static struct nf_hook_ops hans_nf_ops[] = {
	{
		.hook = hans_nf_ipv4v6_in,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_SELINUX_LAST + 1,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook = hans_nf_ipv4v6_in,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP6_PRI_SELINUX_LAST + 1,
	},
#endif
};

void hans_netfilter_deinit(void)
{
	struct net *net;

	rtnl_lock();
	for_each_net(net)
		nf_unregister_net_hooks(net, hans_nf_ops,
					ARRAY_SIZE(hans_nf_ops));
	rtnl_unlock();
}

int hans_netfilter_init(void)
{
	struct net *net;
	int err = 0;

	spin_lock_init(&map_lock);
	hash_init(uid_map);
	hash_init(p_uid_map);

	rtnl_lock();
	for_each_net(net) {
		err = nf_register_net_hooks(net, hans_nf_ops,
					    ARRAY_SIZE(hans_nf_ops));
		if (err) {
			pr_err("register netfilter hooks failed\n");
			break;
		}
	}
	rtnl_unlock();

	if (err) {
		hans_netfilter_deinit();
		return HANS_ERROR;
	}

	return HANS_NOERROR;
}
