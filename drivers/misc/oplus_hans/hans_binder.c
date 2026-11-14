// SPDX-License-Identifier: GPL-2.0
/*
 * OPLUS HANS binder/signal hooks.
 *
 * The original OPLUS driver used Android vendor hooks
 * (register_trace_android_vh_binder_*).  This tree has no vendor hook
 * framework, so the same logic is called directly from binder.c,
 * binder_alloc.c and kernel/signal.c.
 */

#define pr_fmt(fmt) "oplus_hans: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/jobctl.h>
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/freezer.h>
#include <linux/cgroup.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/oplus_hans.h>

/* Needed for struct task_group and RUNTIME_INF. */
#include "../../../kernel/sched/sched.h"

static inline bool hans_jobctl_frozen(struct task_struct *task)
{
	return !!(task->jobctl & JOBCTL_TRAP_FREEZE);
}

static inline bool hans_frozen_tg(struct task_struct *task)
{
	if (!task || !task->group_leader)
		return false;

	return (cgroup_task_frozen(task) && hans_jobctl_frozen(task)) ||
	       frozen(task->group_leader) || freezing(task->group_leader);
}

static inline bool hans_zombie_tg(struct task_struct *task)
{
	return task && task->group_leader &&
	       task->group_leader->exit_state == EXIT_ZOMBIE;
}

#if IS_ENABLED(CONFIG_CFS_BANDWIDTH)
static inline bool hans_belong_cpugrp(struct task_struct *task)
{
	struct task_group *tg = task->sched_task_group;

	return tg && tg->cfs_bandwidth.quota != RUNTIME_INF;
}
#else
static inline bool hans_belong_cpugrp(struct task_struct *task)
{
	return false;
}
#endif

/*
 * Report sync/async binder transactions targeting a frozen task.  This is
 * the direct-call replacement for the vendor hook
 * android_vh_binder_trans.
 */
void hans_binder_trans(struct task_struct *caller, struct task_struct *target,
		       struct binder_transaction_data *tr)
{
	char buf_data[INTERFACETOKEN_BUFF_SIZE];
	size_t buf_data_size;
	char buf[INTERFACETOKEN_BUFF_SIZE] = {0};
	int i = 0;
	int j = 0;
	uid_t target_uid;

	if (!caller || !target || !tr)
		return;

	target_uid = task_uid(target).val;

	if (!(tr->flags & TF_ONE_WAY) &&
	    target_uid > MIN_USERAPP_UID &&
	    task_tgid_nr(caller) != task_tgid_nr(target) &&
	    (hans_frozen_tg(target) || hans_zombie_tg(target))) {
		hans_report(HANS_SYNC_BINDER, task_tgid_nr(caller),
			    task_uid(caller).val, task_tgid_nr(target),
			    target_uid, "SYNC_BINDER", -1);
	}

#if IS_ENABLED(CONFIG_CFS_BANDWIDTH)
	if (!(tr->flags & TF_ONE_WAY) &&
	    target_uid > MIN_USERAPP_UID &&
	    task_tgid_nr(caller) != task_tgid_nr(target) &&
	    (hans_belong_cpugrp(target) || hans_zombie_tg(target))) {
		hans_report(HANS_SYNC_BINDER_CPUCTL, task_tgid_nr(caller),
			    task_uid(caller).val, task_tgid_nr(target),
			    target_uid, "SYNC_BINDER_CPUCTL", -1);
	}
#endif

	if ((tr->flags & TF_ONE_WAY) &&
	    target_uid > MIN_USERAPP_UID &&
	    task_tgid_nr(caller) != task_tgid_nr(target) &&
	    hans_frozen_tg(target)) {
		buf_data_size = min_t(size_t, tr->data_size,
				      INTERFACETOKEN_BUFF_SIZE);
		if (!copy_from_user(buf_data,
				    (void __user *)tr->data.ptr.buffer,
				    buf_data_size)) {
			/*
			 * Java parcels start with 16 bytes of header and store
			 * UTF-16 strings, so only every second byte carries the
			 * interface token.
			 */
			if (buf_data_size > PARCEL_OFFSET) {
				char *p = (char *)buf_data + PARCEL_OFFSET;

				j = PARCEL_OFFSET + 1;
				while (i < INTERFACETOKEN_BUFF_SIZE &&
				       j < buf_data_size && *p != '\0') {
					buf[i++] = *p;
					j += 2;
					p += 2;
				}
				if (i == INTERFACETOKEN_BUFF_SIZE)
					buf[i - 1] = '\0';
			}
			hans_report(HANS_ASYNC_BINDER, task_tgid_nr(caller),
				    task_uid(caller).val, task_tgid_nr(target),
				    target_uid, buf, tr->code);
		}
	}
}

/*
 * Report a reply going to a frozen system process.  Direct-call replacement
 * for android_vh_binder_reply.
 */
void hans_binder_reply(struct task_struct *target, struct task_struct *caller,
		       struct binder_transaction_data *tr)
{
	if (!target || !caller || !tr)
		return;

	if (task_uid(target).val <= MAX_SYSTEM_UID &&
	    task_tgid_nr(caller) != task_tgid_nr(target) &&
	    hans_frozen_tg(target)) {
		hans_report(HANS_SYNC_BINDER, task_tgid_nr(caller),
			    task_uid(caller).val, task_tgid_nr(target),
			    task_uid(target).val, "SYNC_BINDER_REPLY", -1);
	}
}

/*
 * Report when a frozen target is close to exhausting its async binder
 * buffer.  Direct-call replacement for
 * android_vh_binder_alloc_new_buf_locked.
 */
void hans_binder_alloc(int pid, size_t size, size_t free_async_space,
		       int is_async)
{
	struct task_struct *p;

	if (!is_async)
		return;

	/* Report below one third of the transaction size or below 100K. */
	if (free_async_space >= 3 * size && free_async_space >= 100 * 1024)
		return;

	rcu_read_lock();
	p = find_task_by_vpid(pid);
	if (p)
		get_task_struct(p);
	rcu_read_unlock();

	if (!p)
		return;

	if (hans_frozen_tg(p)) {
		hans_report(HANS_ASYNC_BINDER, task_tgid_nr(current),
			    task_uid(current).val, task_tgid_nr(p),
			    task_uid(p).val, "free_buffer_full", -1);
	}
	put_task_struct(p);
}

/*
 * Report signals sent to frozen tasks.  Direct-call replacement for
 * android_vh_do_send_sig_info.
 */
void hans_send_signal(int sig, struct task_struct *killer,
		      struct task_struct *dst)
{
	if (!killer || !dst)
		return;

	if (sig == SIGSEGV)
		dst->flags |= PF_FREEZER_SKIP;

	if (hans_frozen_tg(dst) &&
	    (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT ||
	     sig == SIGQUIT || sig == SIGSEGV || sig == SIGIO)) {
		if (hans_report(HANS_SIGNAL, task_tgid_nr(killer),
				task_uid(killer).val, task_tgid_nr(dst),
				task_uid(dst).val, "signal", -1) == HANS_ERROR)
			pr_err("report signal-freeze failed, sig = %d, caller = %d, target_uid = %d\n",
			       sig, task_tgid_nr(killer), task_uid(dst).val);
	}

#if IS_ENABLED(CONFIG_CFS_BANDWIDTH)
	if ((hans_belong_cpugrp(dst) || hans_zombie_tg(dst)) &&
	    (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT ||
	     sig == SIGQUIT)) {
		if (hans_report(HANS_SIGNAL, task_tgid_nr(killer),
				task_uid(killer).val, task_tgid_nr(dst),
				task_uid(dst).val, "signal", -1) == HANS_ERROR)
			pr_err("report signal-cpuctl failed, sig = %d, caller = %d, target_uid = %d\n",
			       sig, task_tgid_nr(killer), task_uid(dst).val);
	}
#endif
}
