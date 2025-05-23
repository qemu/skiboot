// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * run something, but later.
 *
 * Timers are run when the SBE timer interrupt triggers (based on us setting
 * it) or when the regular heartbeat call from the OS occurs and there's a
 * timer that's expired.
 *
 * Copyright 2014-2019 IBM Corp.
 */

#include <timer.h>
#include <timebase.h>
#include <lock.h>
#include <fsp.h>
#include <device.h>
#include <opal.h>
#include <sbe.h>

#ifdef __TEST__
#define this_cpu()	((void *)-1)
#define cpu_relax()
static bool running_timer;
#else
#include <cpu.h>
#endif

/* Heartbeat requested from Linux */
#define HEARTBEAT_DEFAULT_MS	200

static struct lock timer_lock = LOCK_UNLOCKED;
static LIST_HEAD(timer_list);
static LIST_HEAD(timer_poll_list);
static bool timer_in_poll;

static inline bool this_cpu_is_running_timer(void)
{
#ifdef __TEST__
	return running_timer;
#else
	return this_cpu()->running_timer;
#endif
}

static inline void this_cpu_set_running_timer(bool running)
{
#ifdef __TEST__
	running_timer = running;
#else
	this_cpu()->running_timer = running;
#endif
}

static inline void update_timer_expiry(uint64_t target)
{
	if (sbe_timer_present())
		sbe_update_timer_expiry(target);
}

void init_timer(struct timer *t, timer_func_t expiry, void *data)
{
	t->link.next = t->link.prev = NULL;
	t->target = 0;
	t->expiry = expiry;
	t->user_data = data;
	t->running = NULL;
}

static void __remove_timer(struct timer *t)
{
	list_del(&t->link);
	t->link.next = t->link.prev = NULL;
}

static void __sync_timer(struct timer *t)
{
	sync();

	/* Guard against re-entrancy */
	assert(t->running != this_cpu());

	while (t->running) {
		unlock(&timer_lock);
		smt_lowest();
		while (t->running)
			barrier();
		smt_medium();
		/* Should we call the pollers here ? */
		lock(&timer_lock);
	}
}

void sync_timer(struct timer *t)
{
	lock(&timer_lock);
	__sync_timer(t);
	unlock(&timer_lock);
}

void cancel_timer(struct timer *t)
{
	lock(&timer_lock);
	__sync_timer(t);
	if (t->link.next)
		__remove_timer(t);
	unlock(&timer_lock);
}

void cancel_timer_async(struct timer *t)
{
	lock(&timer_lock);
	if (t->link.next)
		__remove_timer(t);
	unlock(&timer_lock);
}

static void __schedule_timer_at(struct timer *t, uint64_t when)
{
	struct timer *lt;

	/* If the timer is already scheduled, take it out */
	if (t->link.next)
		__remove_timer(t);

	/* Update target */
	t->target = when;

	if (when == TIMER_POLL) {
		/* It's a poller, add it to the poller list */
		list_add_tail(&timer_poll_list, &t->link);
	} else {
		/* It's a real timer, add it in the right spot in the
		 * ordered timer list
		 */
		list_for_each(&timer_list, lt, link) {
			if (when >= lt->target)
				continue;
			list_add_before(&timer_list, &lt->link, &t->link);
			goto added;
		}
		list_add_tail(&timer_list, &t->link);
 added:
		/* Timer running code will update expiry at the end */
		if (!this_cpu_is_running_timer()) {
			/* Pick the next timer and upddate the SBE HW timer */
			lt = list_top(&timer_list, struct timer, link);
			if (lt && (lt == t || when < lt->target))
				update_timer_expiry(lt->target);
		}
	}
}

void schedule_timer_at(struct timer *t, uint64_t when)
{
	lock(&timer_lock);
	__schedule_timer_at(t, when);
	unlock(&timer_lock);
}

uint64_t schedule_timer(struct timer *t, uint64_t how_long)
{
	uint64_t now = mftb();

	if (how_long == TIMER_POLL)
		schedule_timer_at(t, TIMER_POLL);
	else
		schedule_timer_at(t, now + how_long);

	return now;
}

static void __check_poll_timers(uint64_t now)
{
	struct timer *t;
	struct list_head list;

	/* Don't call this from multiple CPUs at once */
	if (timer_in_poll)
		return;
	timer_in_poll = true;

	/* Move all poll timers to a private list */
	list_head_init(&list);
	list_append_list(&list, &timer_poll_list);

	/*
	 * Poll timers might re-enqueue themselves and don't have an
	 * expiry so we can't do like normal timers and just run until
	 * we hit a wall. Instead, each timer has a generation count,
	 * which we set to the current global gen count when we schedule
	 * it and update when we run it. It will only be considered if
	 * the generation count is different than the current one. We
	 * don't try to compare generations being larger or smaller
	 * because at boot, this can be called quite quickly and I want
	 * to be safe vs. wraps.
	 */
	for (;;) {
		t = list_top(&list, struct timer, link);

		/* Top timer has a different generation than current ? Must
		 * be older, we are done.
		 */
		if (!t)
			break;

		/* Top of list still running, we have to delay handling
		 * it. Just skip until the next poll.
		 */
		if (t->running) {
			list_del(&t->link);
			list_add_tail(&timer_poll_list, &t->link);
			continue;
		}

		/* Allright, first remove it and mark it running */
		__remove_timer(t);
		t->running = this_cpu();
		this_cpu_set_running_timer(true);

		/* Now we can unlock and call it's expiry */
		unlock(&timer_lock);
		t->expiry(t, t->user_data, now);

		/* Re-lock and mark not running */
		lock(&timer_lock);
		this_cpu_set_running_timer(false);
		t->running = NULL;
	}
	timer_in_poll = false;
}

static void __check_timers(uint64_t now)
{
	struct timer *t;

	for (;;) {
		t = list_top(&timer_list, struct timer, link);

		/* Top of list not expired ? that's it ... */
		if (!t)
			break;
		if (t->target > now) {
			update_timer_expiry(t->target);
			break;
		}

		/* Top of list still running, we have to delay handling it,
		 * let's reprogram the SLW/SBE with a small delay. We chose
		 * arbitrarily 1us.
		 */
		if (t->running) {
			update_timer_expiry(now + usecs_to_tb(1));
			break;
		}

		/* Allright, first remove it and mark it running */
		__remove_timer(t);
		t->running = this_cpu();
		this_cpu_set_running_timer(true);

		/* Now we can unlock and call it's expiry */
		unlock(&timer_lock);
		t->expiry(t, t->user_data, now);

		/* Re-lock and mark not running */
		lock(&timer_lock);
		this_cpu_set_running_timer(false);
		t->running = NULL;

		/* Update time stamp */
		now = mftb();
	}
}

void check_timers(bool from_interrupt)
{
	uint64_t now = mftb();

	/* This is the polling variant, the SLW interrupt path, when it
	 * exists, will use a slight variant of this that doesn't call
	 * the pollers
	 */

	/* Lockless "peek", a bit racy but shouldn't be a problem as
	 * we are only looking at whether the list is empty
	 */
	if (list_empty_nocheck(&timer_poll_list) &&
	    list_empty_nocheck(&timer_list))
		return;

	/* Take lock and try again */
	lock(&timer_lock);
	if (!from_interrupt)
		__check_poll_timers(now);
	__check_timers(now);
	unlock(&timer_lock);
}

#ifndef __TEST__

void late_init_timers(void)
{
	int heartbeat = HEARTBEAT_DEFAULT_MS;

	/* Add a property requesting the OS to call opal_poll_event() at
	 * a specified interval in order for us to run our background
	 * low priority pollers.
	 *
	 * If a platform quirk exists, use that, else use the default.
	 *
	 * If we have an SBE timer facility, we run this 10 times slower,
	 * we could possibly completely get rid of it.
	 *
	 * We use a value in milliseconds, we don't want this to ever be
	 * faster than that.
	 */
	if (platform.heartbeat_time) {
		heartbeat = platform.heartbeat_time();
	} else if (sbe_timer_present()) {
		heartbeat = HEARTBEAT_DEFAULT_MS * 10;
	}

	dt_add_property_cells(opal_node, "ibm,heartbeat-ms", heartbeat);
}
#endif
