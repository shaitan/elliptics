/*
 * Copyright 2008+ Evgeniy Polyakov <zbr@ioremap.net>
 *
 * This file is part of Elliptics.
 * 
 * Elliptics is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Elliptics is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with Elliptics.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "elliptics.h"
#include "elliptics/packet.h"
#include "elliptics/interface.h"
#include "library/logger.hpp"
#include "library/n2_protocol.h"

#define CHECK_THREAD_WAKEUP_PERIOD_NS (10 * 1000 * 1000)

/*
 * Ascending transaction order
 */
static inline int dnet_trans_cmp(uint64_t t2, uint64_t t1)
{
	if (t1 > t2)
		return 1;
	if (t1 < t2)
		return -1;
	return 0;
}

struct dnet_trans *dnet_trans_search(struct dnet_net_state *st, uint64_t trans)
{
	struct rb_root *root = &st->trans_root;
	struct rb_node *n = root->rb_node;
	struct dnet_trans *t = NULL;
	int cmp = 1;

	while (n) {
		t = rb_entry(n, struct dnet_trans, trans_entry);

		cmp = dnet_trans_cmp(t->trans, trans);
		if (cmp < 0)
			n = n->rb_left;
		else if (cmp > 0)
			n = n->rb_right;
		else
			return dnet_trans_get(t);
	}

	return NULL;
}

int dnet_trans_insert_nolock(struct dnet_net_state *st, struct dnet_trans *a)
{
	struct rb_root *root = &st->trans_root;
	struct rb_node **n = &root->rb_node, *parent = NULL;
	struct dnet_trans *t;
	int cmp;

	while (*n) {
		parent = *n;

		t = rb_entry(parent, struct dnet_trans, trans_entry);

		cmp = dnet_trans_cmp(t->trans, a->trans);
		if (cmp < 0)
			n = &parent->rb_left;
		else if (cmp > 0)
			n = &parent->rb_right;
		else
			return -EEXIST;
	}

	if (a->st && a->st->n)
		dnet_log(a->st->n, DNET_LOG_NOTICE, "%s: %s: added trans: %llu -> %s/%d",
			dnet_dump_id(&a->cmd.id), dnet_cmd_string(a->cmd.cmd), (unsigned long long)a->trans,
			dnet_addr_string(&a->st->addr), a->cmd.backend_id);

	rb_link_node(&a->trans_entry, parent, n);
	rb_insert_color(&a->trans_entry, root);
	return 0;
}

/**
 * Timer functions are used for timeout check.
 * We insert transaction into timer tree ordered/indexed by time-to-timeout-death.
 *
 * Checking thread periodically looks at the beginning of the timer tree and kills
 * those transactions which are past the deadline. When transaction reply has been
 * received transaction is removed from the timer tree, its time-to-timeout-death
 * is updated and transaction inserted into the timer tree again.
 *
 * It is possible, that multiple transaction were created at the same time with
 * the same time-to-timeout-death, in this case we compare them additionally using
 * transaction number, which is unique for node.
 *
 * This particular trans2,trans1 order of arguments is very significant - argument order plus
 * the way they are compared below ends up with ascending timeout order, i.e. the smaller
 * timeout (the closer death-time) the closer transaction is to the beginning of the timer tree
 * (do not confuse it with the tree root).
 */
static inline int dnet_trans_cmp_timer(struct dnet_trans *trans2, struct dnet_trans *trans1)
{
	struct timespec *t1 = &trans1->time_ts;
	struct timespec *t2 = &trans2->time_ts;

	if (t1->tv_sec > t2->tv_sec)
		return 1;
	if (t1->tv_sec < t2->tv_sec)
		return -1;
	if (t1->tv_nsec > t2->tv_nsec)
		return 1;
	if (t1->tv_nsec < t2->tv_nsec)
		return -1;

	return dnet_trans_cmp(trans2->trans, trans1->trans);
}

struct dnet_trans *dnet_trans_search_timer(struct dnet_net_state *st, struct dnet_trans *trans)
{
	struct rb_root *root = &st->timer_root;
	struct rb_node *n = root->rb_node;
	struct dnet_trans *t = NULL;
	int cmp = 1;

	while (n) {
		t = rb_entry(n, struct dnet_trans, timer_entry);

		cmp = dnet_trans_cmp_timer(t, trans);
		if (cmp < 0)
			n = n->rb_left;
		else if (cmp > 0)
			n = n->rb_right;
		else
			return dnet_trans_get(t);
	}

	return NULL;
}

int dnet_trans_insert_timer_nolock(struct dnet_net_state *st, struct dnet_trans *a)
{
	struct rb_root *root = &st->timer_root;
	struct rb_node **n = &root->rb_node, *parent = NULL;
	struct dnet_trans *t;
	int cmp;

	while (*n) {
		parent = *n;

		t = rb_entry(parent, struct dnet_trans, timer_entry);

		cmp = dnet_trans_cmp_timer(t, a);
		if (cmp < 0)
			n = &parent->rb_left;
		else if (cmp > 0)
			n = &parent->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&a->timer_entry, parent, n);
	rb_insert_color(&a->timer_entry, root);
	return 0;
}

void dnet_trans_remove_timer_nolock(struct dnet_net_state *st, struct dnet_trans *t)
{
	if (t->timer_entry.rb_parent_color) {
		rb_erase(&t->timer_entry, &st->timer_root);
		t->timer_entry.rb_parent_color = 0;
	}
}

void dnet_trans_remove_nolock(struct dnet_net_state *st, struct dnet_trans *t)
{
	if (!t->trans_entry.rb_parent_color) {
		dnet_log(st->n, DNET_LOG_ERROR, "%s: trying to remove out-of-trans-tree transaction %llu.",
			dnet_dump_id(&t->cmd.id), (unsigned long long)t->trans);
		return;
	}

	rb_erase(&t->trans_entry, &st->trans_root);
	t->trans_entry.rb_parent_color = 0;

	dnet_trans_remove_timer_nolock(st, t);
}

void dnet_trans_remove(struct dnet_trans *t)
{
	struct dnet_net_state *st = t->st;

	/* if transaction is removed, it is about to be killed - remove it from everywhere */
	pthread_mutex_lock(&st->trans_lock);
	dnet_trans_remove_nolock(st, t);
	list_del_init(&t->trans_list_entry);
	pthread_mutex_unlock(&st->trans_lock);
}

struct dnet_trans *dnet_trans_alloc(struct dnet_node *n, uint64_t size)
{
	struct dnet_trans *t;

	t = calloc(1, sizeof(struct dnet_trans) + size);
	if (!t)
		goto err_out_exit;

	t->alloc_size = size;
	t->n = n;
	t->wait_ts = n->wait_ts;

	atomic_init(&t->refcnt, 1);
	INIT_LIST_HEAD(&t->trans_list_entry);

	clock_gettime(CLOCK_MONOTONIC_RAW, &t->start_ts);

	return t;

err_out_exit:
	return NULL;
}

void dnet_trans_destroy(struct dnet_trans *t)
{
	struct dnet_net_state *st = NULL;

	if (!t)
		return;

	dnet_logger_set_trace_id(t->cmd.trace_id, !!(t->cmd.flags & DNET_FLAGS_TRACE_BIT));

	if (t->st && t->st->n) {
		st = t->st;

		pthread_mutex_lock(&st->trans_lock);
		list_del_init(&t->trans_list_entry);

		if (t->trans_entry.rb_parent_color) {
			dnet_trans_remove_nolock(st, t);
		}

		pthread_mutex_unlock(&st->trans_lock);
	} else if (!list_empty(&t->trans_list_entry)) {
		assert(0);
	}

	if (t->complete) {
		t->cmd.flags |= DNET_FLAGS_DESTROY;
		t->complete(t->st ? dnet_state_addr(t->st) : NULL, &t->cmd, t->priv);
	}

	if (t->repliers) {
		n2_trans_destroy_repliers(t->repliers);
	}

	if (st && st->n && t->command) {
		if (t->cmd.status != -ETIMEDOUT) {
			if (st->stall) {
				dnet_log(st->n, DNET_LOG_INFO, "%s/%d: resetting state stall counter",
					 dnet_state_dump_addr(st), t->cmd.backend_id);
			}

			st->stall = 0;
		}

		dnet_trans_log(st->n, t);
	}

	dnet_state_put(t->st);
	dnet_state_put(t->orig);

	dnet_logger_unset_trace_id();
	free(t);
}

static void dnet_trans_control_fill_cmd(struct dnet_session *s, const struct dnet_trans_control *ctl, struct dnet_cmd *cmd)
{
	memcpy(&cmd->id, &ctl->id, sizeof(struct dnet_id));
	cmd->flags = ctl->cflags;
	cmd->size = ctl->size;
	cmd->cmd = ctl->cmd;
	if (s) {
		cmd->flags |= dnet_session_get_cflags(s);
		cmd->trace_id = dnet_session_get_trace_id(s);
		if (cmd->flags & DNET_FLAGS_DIRECT_BACKEND)
			cmd->backend_id = dnet_session_get_direct_backend(s);
	}
}

int dnet_trans_send_fail(struct dnet_session *s, struct dnet_addr *addr, struct dnet_trans_control *ctl, int err, int destroy)
{
	struct dnet_cmd cmd;
	memset(&cmd, 0, sizeof(cmd));
	dnet_trans_control_fill_cmd(s, ctl, &cmd);

	cmd.status = err;
	cmd.size = 0;

	if (ctl->complete) {
		cmd.flags &= ~DNET_FLAGS_REPLY;

		ctl->complete(addr, &cmd, ctl->priv);

		if (destroy) {
			cmd.flags |= DNET_FLAGS_DESTROY;
			ctl->complete(addr, &cmd, ctl->priv);
		}
	}

	return 0;
}

/*
 * Allocates and sends transaction into given @st network state/connection.
 * Uses @s session only to get wait timeout for transaction, if it is NULL, global node timeout (@dnet_node::wait_ts) is used.
 *
 * If something fails, completion handler from @ctl will be invoked with (NULL, NULL, @ctl->priv) arguments
 */
int dnet_trans_alloc_send_state(struct dnet_session *s, struct dnet_net_state *st, struct dnet_trans_control *ctl)
{
	struct dnet_io_req req;
	struct dnet_node *n = st->n;
	struct dnet_cmd *cmd;
	struct dnet_trans *t;
	int err;

	t = dnet_trans_alloc(n, sizeof(struct dnet_cmd) + ctl->size);
	if (!t) {
		err = dnet_trans_send_fail(s, dnet_state_addr(st), ctl, -ENOMEM, 1);
		goto err_out_exit;
	}

	t->complete = ctl->complete;
	t->priv = ctl->priv;
	if (s) {
		t->wait_ts = *dnet_session_get_timeout(s);
	}

	cmd = (struct dnet_cmd *)(t + 1);

	dnet_trans_control_fill_cmd(s, ctl, cmd);
	t->command = cmd->cmd;
	cmd->trans = t->rcv_trans = t->trans = atomic_inc(&n->trans);

	memcpy(&t->cmd, cmd, sizeof(struct dnet_cmd));

	if (ctl->size && ctl->data)
		memcpy(cmd + 1, ctl->data, ctl->size);

	dnet_convert_cmd(cmd);

	t->st = dnet_state_get(st);

	memset(&req, 0, sizeof(req));
	req.st = st;
	req.header = cmd;
	req.hsize = sizeof(struct dnet_cmd) + ctl->size;
	req.fd = -1;

	dnet_log(n, DNET_LOG_INFO, "%s: %s: created %s",
			dnet_dump_id(&cmd->id),
			dnet_cmd_string(cmd->cmd),
			dnet_print_trans(t)
		);

	err = dnet_trans_send(t, &req);
	if (err)
		goto err_out_put;

	return 0;

err_out_put:
	dnet_trans_send_fail(s, dnet_state_addr(st), ctl, err, 0);
	dnet_trans_put(t);
err_out_exit:
	return 0;
}

int dnet_trans_alloc_send(struct dnet_session *s, struct dnet_trans_control *ctl)
{
	struct dnet_node *n = s->node;
	struct dnet_net_state *st;
	struct dnet_addr *addr = NULL;
	int err;

	if (dnet_session_get_cflags(s) & DNET_FLAGS_DIRECT) {
		st = dnet_state_search_by_addr(n, &s->direct_addr);
		addr = &s->direct_addr;
	} else if(dnet_session_get_cflags(s) & DNET_FLAGS_FORWARD) {
		st = dnet_state_search_by_addr(n, &s->forward_addr);
		addr = &s->forward_addr;
	}else {
		st = dnet_state_get_first(n, &ctl->id);
	}

	if (!st) {
		dnet_log(n, DNET_LOG_ERROR, "%s: direct: %d, direct-addr: %s, forward: %d: trans_send: could not find network state for address",
			dnet_dump_id(&ctl->id),
			!!(dnet_session_get_cflags(s) & DNET_FLAGS_DIRECT), dnet_addr_string(&s->direct_addr),
			!!(dnet_session_get_cflags(s) & DNET_FLAGS_FORWARD));

		err = dnet_trans_send_fail(s, addr, ctl, -ENXIO, 1);
	} else {
		err = dnet_trans_alloc_send_state(s, st, ctl);
		dnet_state_put(st);
	}

	return err;
}

void dnet_trans_clean_list(struct list_head *head, int error)
{
	struct dnet_trans *t, *tmp;

	list_for_each_entry_safe(t, tmp, head, trans_list_entry) {
		list_del_init(&t->trans_list_entry);

		t->cmd.size = 0;
		t->cmd.flags &= ~DNET_FLAGS_REPLY;
		t->cmd.status = error;

		dnet_logger_set_trace_id(t->cmd.trace_id, t->cmd.flags & DNET_FLAGS_TRACE_BIT);
		if (t->complete) {
			t->complete(dnet_state_addr(t->st), &t->cmd, t->priv);
		}

		dnet_trans_put(t);
		dnet_logger_unset_trace_id();
	}
}

void dnet_update_stall_backend_weights(struct list_head *stall_transactions)
{
	struct dnet_io_req *r, *tmp;
	struct dnet_cmd *cmd;
	struct dnet_net_state *st;
	double old_cache_weight, new_cache_weight;
	double old_disk_weight, new_disk_weight;
	int err;

	list_for_each_entry_safe(r, tmp, stall_transactions, req_entry) {
		cmd = r->header;
		st = r->st;

		err = dnet_get_backend_weight(st, cmd->backend_id, DNET_IO_FLAGS_CACHE, &old_cache_weight);
		if (!err) {
			new_cache_weight = old_cache_weight;
			if (new_cache_weight >= 2) {
				new_cache_weight /= 10;
				dnet_set_backend_weight(st, cmd->backend_id, DNET_IO_FLAGS_CACHE, new_cache_weight);
			}

			err = dnet_get_backend_weight(st, cmd->backend_id, 0, &old_disk_weight);
			if (!err) {
				new_disk_weight = old_disk_weight;
				if (new_disk_weight >= 2) {
					new_disk_weight /= 10;
					dnet_set_backend_weight(st, cmd->backend_id, 0, new_disk_weight);
				}

				dnet_log(st->n, DNET_LOG_INFO, "%s/%d: TIMEOUT: update backend weight: weight: "
						"cache: %f -> %f, disk: %f -> %f",
					 dnet_state_dump_addr(st), cmd->backend_id,
					 old_cache_weight, new_cache_weight,
					 old_disk_weight, new_disk_weight);
			}
		}
	}
}

static int dnet_timespec_cmp(struct timespec *l, struct timespec *r)
{
	if (l->tv_sec > r->tv_sec) {
		return 1;
	} else if (l->tv_sec < r->tv_sec) {
		return -1;
	} else if (l->tv_nsec > r->tv_nsec) {
		return 1;
	} else if (l->tv_nsec < r->tv_nsec) {
		return -1;
	} else {
		return 0;
	}
}

int dnet_trans_iterate_move_transaction(struct dnet_net_state *st, struct list_head *head)
{
	struct dnet_trans *t;
	struct rb_node *rb_node;
	struct timespec ts;
	int trans_moved = 0;
	long diff = 0;

	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);

	while (1) {
		/* lock is being locked/unlocked to get a chance for IO thread to process other transactions
		 * without being stalled for too long waiting for this checking thread to complete
		 */
		pthread_mutex_lock(&st->trans_lock);

		t = NULL;
		if (!RB_EMPTY_ROOT(&st->timer_root)) {
			rb_node = rb_first(&st->timer_root);
			t = rb_entry(rb_node, struct dnet_trans, timer_entry);
		} else if (st->__need_exit && !RB_EMPTY_ROOT(&st->trans_root)) {
			rb_node = rb_first(&st->trans_root);
			t = rb_entry(rb_node, struct dnet_trans, trans_entry);
		}
		if (!t) {
			pthread_mutex_unlock(&st->trans_lock);
			break;
		}

		if (!st->__need_exit && dnet_timespec_cmp(&ts, &t->time_ts) < 0) {
			// We don't need to exit => here the case when we searched timed out transaction. We found
			// the first transaction that hasn't timed out => stop search, exit loop
			pthread_mutex_unlock(&st->trans_lock);
			break;
		}

		diff = DIFF_TIMESPEC(t->start_ts, ts);

		// TODO: We may use dnet_log_record_set_request_id here,
		// but blackhole currently has higher priority for scoped attributes =(
		dnet_logger_set_trace_id(t->cmd.trace_id, t->cmd.flags & DNET_FLAGS_TRACE_BIT);

		dnet_log(st->n, DNET_LOG_ERROR, "%s: %s: TIMEOUT/need-exit %s, "
				"need-exit: %d, time: %ld",
				dnet_dump_id(&t->cmd.id), dnet_cmd_string(t->cmd.cmd),
				dnet_print_trans(t),
				st->__need_exit,
				diff);

		trans_moved++;

		/*
		 * Remove transaction from every tree/list, so it could not be accessed and found while we deal with it.
		 * In particular, we will call ->complete() callback, which must ensure that no other thread calls it.
		 *
		 * Memory allocation for every transaction is handled by reference counters, but callbacks must ensure,
		 * that no calls are made after 'final' callback has been invoked. 'Final' means is_trans_destroyed() returns true.
		 *
		 * We can not destroy transaction right here since route table is locked above this function and transaction
		 * destruction can lead to state destruction which in turn may kill state and remove it from route table,
		 * which will deadlock.
		 */
		dnet_trans_remove_nolock(st, t);

		if (!list_empty(&t->trans_list_entry)) {
			list_del(&t->trans_list_entry);
			dnet_log(st->n, DNET_LOG_ERROR, "%s: %s: TIMEOUT/need-exit: stall %s, "
					"it was moved into some timeout list, but yet it exists in timer tree, "
					"need-exit: %d, time: %ld",
					dnet_dump_id(&t->cmd.id), dnet_cmd_string(t->cmd.cmd),
					dnet_print_trans(t),
					st->__need_exit,
					diff);
		}

		list_add_tail(&t->trans_list_entry, head);
		dnet_logger_unset_trace_id();

		pthread_mutex_unlock(&st->trans_lock);
	}

	return trans_moved;
}

struct dnet_ping_node_private
{
	struct dnet_session	*session;
	struct dnet_net_state	*net_state;
};

static int dnet_ping_stall_node_complete(struct dnet_addr *addr __unused, struct dnet_cmd *cmd, void *priv)
{
	struct dnet_ping_node_private *ping_private;
	struct dnet_net_state *st;

	if (is_trans_destroyed(cmd)) {
	        ping_private = priv;
		st = ping_private->net_state;

		dnet_session_destroy(ping_private->session);
		free(ping_private);

		if (cmd->status == -ETIMEDOUT)
			dnet_state_reset(st, cmd->status);
	}

	return 0;
}

static int dnet_ping_stall_node(struct dnet_net_state *st)
{
	struct dnet_node_status node_status;
	struct dnet_trans_control ctl;
	struct dnet_session *sess;
	struct dnet_ping_node_private *ping_private;

	ping_private = malloc(sizeof(struct dnet_ping_node_private));
	if (!ping_private)
		return -ENOMEM;

	sess = dnet_session_create(st->n);
	if (!sess) {
		free(ping_private);
		return -ENOMEM;
	}

	dnet_session_set_direct_addr(sess, &st->addr);

	ping_private->session = sess;
	ping_private->net_state = st;

	memset(&node_status, 0, sizeof(struct dnet_node_status));

	/* this values of node_status will not affect remote node state */
	node_status.nflags = -1;
	node_status.status_flags = -1;
	node_status.log_level = ~0U;

	memset(&ctl, 0, sizeof(struct dnet_trans_control));

	ctl.cmd = DNET_CMD_STATUS;
	ctl.cflags = DNET_FLAGS_NEED_ACK | DNET_FLAGS_DIRECT;
	ctl.size = sizeof(struct dnet_node_status);
	ctl.data = &node_status;

	ctl.complete = dnet_ping_stall_node_complete;
	ctl.priv = ping_private;

	return dnet_trans_alloc_send_state(sess, st, &ctl);
}

static int dnet_trans_convert_timed_out_to_responses(struct dnet_net_state *st, struct list_head *timeout_responses) {
	struct dnet_trans *t;
	struct rb_node *rb_node;
	struct timespec ts;
	int trans_moved = 0;
	long diff = 0;
	struct dnet_cmd *cmd;
	struct dnet_io_req *r;
	static const size_t cmd_size = sizeof(struct dnet_io_req) + sizeof(struct dnet_cmd);

	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);

	while (1) {
		pthread_mutex_lock(&st->trans_lock);

		t = NULL;
		if (!RB_EMPTY_ROOT(&st->timer_root)) {
			rb_node = rb_first(&st->timer_root);
			t = rb_entry(rb_node, struct dnet_trans, timer_entry);
		}

		if (!t) {
			pthread_mutex_unlock(&st->trans_lock);
			break;
		}

		if (dnet_timespec_cmp(&ts, &t->time_ts) < 0) {
			// Found transaction that hasn't timed out => stop search in rb_tree, exit loop
			pthread_mutex_unlock(&st->trans_lock);
			break;
		}

		diff = DIFF_TIMESPEC(t->start_ts, ts);
		dnet_logger_set_trace_id(t->cmd.trace_id, t->cmd.flags & DNET_FLAGS_TRACE_BIT);

		dnet_log(st->n, DNET_LOG_ERROR, "%s: %s: TIMEOUT/need-exit %s, "
		                                "need-exit: %d, time: %ld",
		         dnet_dump_id(&t->cmd.id), dnet_cmd_string(t->cmd.cmd),
		         dnet_print_trans(t),
		         st->__need_exit,
		         diff);

		trans_moved++;

		/*
		 * Remove timed-out transaction from net_state's timer-list, and then create
		 * error-response for this transaction, and add to the function's output list (timeout_responses).
		 * The output list will be added to request_queue of the net state.
		 */
		dnet_trans_remove_timer_nolock(st, t);

		r = calloc(1, cmd_size);
		if (!r) {
			dnet_log(st->n, DNET_LOG_ERROR, "%s: %s: bad allocation, cannot save "
			                                "timed-out transaction %s in output list",
				 dnet_dump_id(&t->cmd.id), dnet_cmd_string(t->cmd.cmd),
				 dnet_print_trans(t));
			dnet_logger_unset_trace_id();
			pthread_mutex_unlock(&st->trans_lock);
			continue;
		}

		r->st = dnet_state_get(st);

		r->header = r + 1;
		r->hsize = sizeof(struct dnet_cmd);
		memcpy(r->header, &t->cmd, r->hsize);

		cmd = r->header;
		cmd->size = 0;
		cmd->flags |= DNET_FLAGS_REPLY;
		cmd->flags &= ~(DNET_FLAGS_MORE | DNET_FLAGS_NEED_ACK);
		cmd->status = -ETIMEDOUT;

		list_add_tail(&r->req_entry, timeout_responses);

		dnet_logger_unset_trace_id();

		pthread_mutex_unlock(&st->trans_lock);
	}

	return trans_moved;
}

static int dnet_trans_check_stall(struct dnet_net_state *st, struct list_head *timeout_responses)
{
	int is_stall_state = 0;
	int trans_timeout = dnet_trans_convert_timed_out_to_responses(st, timeout_responses);

	if (trans_timeout) {
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC_RAW, &ts);

		if (DIFF_TIMESPEC(st->stall_ts, ts) >= 1000000) {
			st->stall++;
			st->stall_ts = ts;

			if (st->stall >= st->n->stall_count && st != st->n->st)
				is_stall_state = 1;
		}

		dnet_log(st->n, DNET_LOG_ERROR, "%s: TIMEOUT: transactions: %d, stall counter: %d/%lu",
				dnet_state_dump_addr(st), trans_timeout, st->stall, st->n->stall_count);
	}

	return is_stall_state;
}

static void dnet_trans_enqueue_responses_on_timed_out(struct dnet_node *n, struct list_head *timeout_responses) {
	struct dnet_io_req *r, *tmp;

	list_for_each_entry_safe(r, tmp, timeout_responses, req_entry) {
		list_del_init(&r->req_entry);

		dnet_schedule_io(n, r);
	}
}

static void dnet_check_all_states(struct dnet_node *n)
{
	struct dnet_net_state *st;
	int i, err;
	int num_stall_state = 0;
	int max_state_count = 0;
	struct dnet_net_state **stall_states = NULL;
	LIST_HEAD(timeout_responses);

	pthread_mutex_lock(&n->state_lock);
	/*
	 * It isn't possible to send a ping transaction while checking stall transactions within dnet_trans_check_stall(),
	 * because it may invoke callback directly, where dnet_state_reset() is called that will deadlock on state_lock mutex.
	 */
	rb_for_each_entry(st, &n->dht_state_root, node_entry) {
		++max_state_count;
	}

	if (max_state_count > 0) {
		stall_states = malloc(max_state_count * sizeof(struct dnet_net_state *));
		if (!stall_states) {
			dnet_log(n, DNET_LOG_ERROR, "dnet_check_all_states: malloc failed for stall_states: %d", max_state_count);
			pthread_mutex_unlock(&n->state_lock);
			return;
		}
	}

	rb_for_each_entry(st, &n->dht_state_root, node_entry) {
		if (dnet_trans_check_stall(st, &timeout_responses)) {
			dnet_state_get(st);
			stall_states[num_stall_state++] = st;
		}
	}
	pthread_mutex_unlock(&n->state_lock);

	dnet_update_stall_backend_weights(&timeout_responses);

	dnet_trans_enqueue_responses_on_timed_out(n, &timeout_responses);

	for (i = 0; i < num_stall_state; ++i) {
		st = stall_states[i];
		st->stall = 0;
		err = dnet_ping_stall_node(st);
		if (err)
			dnet_log(st->n, DNET_LOG_ERROR, "dnet_ping_stall_node failed: %s [%d]", strerror(-err), err);
		dnet_state_put(st);
	}

	free(stall_states);
}

static void *dnet_reconnect_process(void *data)
{
	struct dnet_node *n = data;
	long i, timeout;
	struct timespec ts1, ts2;

	dnet_set_name("dnet_reconnect");

	if (!n->check_timeout)
		n->check_timeout = 10;

	dnet_log(n, DNET_LOG_INFO, "Started reconnection thread. Timeout: %lu seconds. Route table update every %lu seconds.",
			n->check_timeout, n->check_timeout);

	while (!n->need_exit) {
		clock_gettime(CLOCK_MONOTONIC_RAW, &ts1);

		dnet_log(n, DNET_LOG_INFO, "Started reconnection process");
		dnet_reconnect_and_check_route_table(n);
		dnet_log(n, DNET_LOG_INFO, "Finished reconnection process");

		clock_gettime(CLOCK_MONOTONIC_RAW, &ts2);

		timeout = n->check_timeout - (ts2.tv_sec - ts1.tv_sec);

		for (i=0; i<timeout; ++i) {
			if (n->need_exit)
				break;

			sleep(1);
		}
	}

	return NULL;
}


static void *dnet_check_process(void *data)
{
	struct dnet_node *n = data;

	dnet_set_name("dnet_check");

	while (!n->need_exit) {
		dnet_check_all_states(n);

		struct timespec ts;
		ts.tv_sec = 0;
		ts.tv_nsec = CHECK_THREAD_WAKEUP_PERIOD_NS;
		nanosleep(&ts, NULL);
	}

	return NULL;
}

int dnet_check_thread_start(struct dnet_node *n)
{
	int err;

	err = pthread_create(&n->check_tid, NULL, dnet_check_process, n);
	if (err) {
		err = -err;
		dnet_log(n, DNET_LOG_ERROR, "Failed to start tree checking thread: err: %d.",
				err);
		goto err_out_exit;
	}

	err = pthread_create(&n->reconnect_tid, NULL, dnet_reconnect_process, n);
	if (err) {
		err = -err;
		dnet_log(n, DNET_LOG_ERROR, "Failed to start reconnection thread: err: %d.",
				err);
		goto err_out_stop_check_thread;
	}

	return 0;

err_out_stop_check_thread:
	n->need_exit = 1;
	pthread_join(n->check_tid, NULL);
err_out_exit:
	return err;
}

void dnet_check_thread_stop(struct dnet_node *n)
{
	pthread_join(n->reconnect_tid, NULL);
	pthread_join(n->check_tid, NULL);
	dnet_log(n, DNET_LOG_NOTICE, "Checking thread stopped");
}
