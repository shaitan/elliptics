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

#ifndef __DNET_ELLIPTICS_H
#define __DNET_ELLIPTICS_H

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <string.h>
#include <time.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "list.h"

#include "rbtree.h"

#include "atomic.h"
#include "lock.h"

#include "elliptics/packet.h"
#include "elliptics/interface.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __unused
#define __unused	__attribute__ ((unused))
#endif

struct dnet_test_settings;
struct dnet_node;
struct dnet_group;
struct dnet_net_state;
struct dnet_cmd_stats;
struct dnet_access_context;

struct dnet_io_req {
	struct list_head	req_entry;

	struct dnet_net_state	*st;

	void			*header;
	size_t			hsize;

	void			*data;
	size_t			dsize;

	int			on_exit;
	int			fd;
	off_t			local_offset;
	size_t			fsize;

	struct timespec		queue_start_ts;
	uint64_t		queue_time;
	uint64_t		recv_time;

	struct dnet_access_context *context;
};

#define ELLIPTICS_PROTOCOL_VERSION_0 2
#define ELLIPTICS_PROTOCOL_VERSION_1 26
#define ELLIPTICS_PROTOCOL_VERSION_2 0
#define ELLIPTICS_PROTOCOL_VERSION_3 0

/*
 * Currently executed network state machine:
 * receives and sends command and data.
 */

/* Reading a command */
#define DNET_IO_CMD		(1<<0)

/* Attached data should be discarded */
#define DNET_IO_DROP		(1<<1)

#define DNET_STATE_DEFAULT_WEIGHT	1.0

/* Iterator watermarks for sending data and sleeping */
#define DNET_SEND_WATERMARK_HIGH	(1024 * 100)
#define DNET_SEND_WATERMARK_LOW		(512 * 100)

/* Internal flag to ignore cache */
#define DNET_IO_FLAGS_NOCACHE		(1<<28)

struct dnet_net_epoll_data
{
	struct dnet_net_state *st;
	int fd;
};

struct dnet_net_state
{
	// To store state either at node::empty_state_root (Map of all client nodes by addresses, used for statistics)
	// or at node::dht_state_root (Map of all server nodes by addresses)
	struct rb_node		node_entry;
	// Pointer to rb tree with node_entry. It can be &node::dht_state_root, &node::dht_state_root or NULL
	struct rb_root		*root;
	// To store at node::storage_state_list (List of all network-active states, used for unscheduling process)
	struct list_head	storage_state_entry;
	// Mapping backend_id -> struct dnet_idc
	struct rb_root		idc_root;
	// idc_lock is guard of idc_root structure, not values of idc_root items
	pthread_rwlock_t	idc_lock;

	struct dnet_node	*n;

	atomic_t		refcnt;
	int			read_s, write_s;
	int			accept_s;

	int			__need_exit;

	int			stall;
	struct timespec		stall_ts;

	int			__join_state;
	int			__ids_sent;

	/* all address of the given node */
	int			addr_num;
	struct dnet_addr	*addrs;

	/* index of the connected address in array of all addresses of given node */
	int			idx;

	/* address used to connect to cluster */
	struct dnet_addr	addr;

	struct dnet_cmd		rcv_cmd;
	uint64_t		rcv_offset;
	uint64_t		rcv_end;
	unsigned int		rcv_flags;
	struct timespec		rcv_start_ts;
	struct timespec		rcv_finish_ts;
	void			*rcv_data;

	int			epoll_fd;
	size_t			send_offset;
	pthread_mutex_t		send_lock;
	struct list_head	send_list;
	struct timespec		send_start_ts;
	/*
	 * Condition variable to wait when send_queue_size reaches high
	 * watermark
	 */
	pthread_cond_t		send_wait;
	/* Number of queued requests in send queue from iterator */
	atomic_t		send_queue_size;

	pthread_mutex_t		trans_lock;
	struct rb_root		trans_root;
	struct rb_root		timer_root;


	int			la;
	unsigned long long	free;

	struct dnet_stat_count	stat[__DNET_CMD_MAX];

	/* Remote protocol version */
	int version[4];

	struct dnet_net_epoll_data read_data;
	struct dnet_net_epoll_data write_data;
	struct dnet_net_epoll_data accept_data;
};

int dnet_socket_local_addr(int s, struct dnet_addr *addr);
int dnet_local_addr_index(struct dnet_node *n, struct dnet_addr *addr);

int dnet_copy_addrs_nolock(struct dnet_net_state *nst, struct dnet_addr *addrs, int addr_num);

struct dnet_idc;
struct dnet_state_id {
	struct dnet_raw_id	raw;
	struct dnet_idc		*idc;
};

/* container of dnet_state_id */
struct dnet_idc {
	struct rb_node		state_entry;
	struct list_head	group_entry;
	struct dnet_net_state	*st;
	int			backend_id;
	double			disk_weight/*, cache_weight*/;
	struct dnet_group	*group;
	int			id_num;
	struct dnet_state_id	ids[];
};

int dnet_group_id_search_by_backend(struct dnet_net_state *st, int backend_id);

int dnet_idc_insert(struct dnet_net_state *st, struct dnet_idc *idc);
void dnet_idc_remove_backend_nolock(struct dnet_net_state *st, int backend_id);
int dnet_idc_update_backend(struct dnet_net_state *st, struct dnet_backend_ids *ids);
void dnet_idc_destroy_nolock(struct dnet_net_state *st);

int dnet_state_micro_init(struct dnet_net_state *st, struct dnet_node *n, struct dnet_addr *addr, int join);
int dnet_state_set_server_prio(struct dnet_net_state *st);

int dnet_state_move_to_dht(struct dnet_net_state *st, struct dnet_addr *addrs, int addrs_count);
struct dnet_net_state *dnet_state_create(struct dnet_node *n,
		struct dnet_backend_ids **backends, int backends_count,
		struct dnet_addr *addr, int s, int *errp, int join, int server_node, int idx,
		int accepting_state, struct dnet_addr *addrs, int addrs_count);

void dnet_state_reset(struct dnet_net_state *st, int error);
void dnet_state_clean(struct dnet_net_state *st);
int dnet_state_insert_nolock(struct rb_root *root, struct dnet_net_state *st);
void dnet_state_rb_remove_nolock(struct dnet_net_state *st);
void dnet_state_remove_nolock(struct dnet_net_state *st);

struct dnet_net_state *dnet_state_search_by_addr_nolock(struct dnet_node *n, const struct dnet_addr *addr);
struct dnet_net_state *dnet_state_search_by_addr(struct dnet_node *n, const struct dnet_addr *addr);
struct dnet_net_state *dnet_state_get_first(struct dnet_node *n, const struct dnet_id *id);
ssize_t dnet_state_search_backend(struct dnet_node *n, const struct dnet_id *id);
int dnet_get_backend_weight(struct dnet_net_state *st, int backend_id, uint32_t ioflags, double *weight);
void dnet_set_backend_weight(struct dnet_net_state *st, int backend_id, uint32_t ioflags, double weight);
void dnet_update_backend_weight(struct dnet_net_state *st, const struct dnet_cmd *, uint64_t ioflags, long time);
struct dnet_net_state *dnet_state_search_nolock(struct dnet_node *n, const struct dnet_id *id, int *backend_id);
struct dnet_net_state *dnet_node_state(struct dnet_node *n);

/* Set need_exit flag, cancel iterators, stop and join node threads */
void dnet_node_stop_common_resources(struct dnet_node *n);
/* Free resources of node. Must be called after dnet_node_stop_common_resources() */
void dnet_node_cleanup_common_resources(struct dnet_node *n);

int dnet_node_reset_log(struct dnet_node *n);
enum dnet_log_level dnet_node_get_verbosity(struct dnet_node *n);
int dnet_node_set_verbosity(struct dnet_node *n, enum dnet_log_level level);

uint64_t dnet_node_get_queue_timeout(struct dnet_node *node);

int dnet_search_range(struct dnet_node *n, struct dnet_id *id,
		struct dnet_raw_id *start, struct dnet_raw_id *next);

int dnet_validate_route_list(struct dnet_net_state *st, struct dnet_cmd *cmd);
int dnet_recv_route_list(struct dnet_net_state *st, int (*complete)(struct dnet_addr *addr, struct dnet_cmd *cmd, void *priv), void *priv);

void dnet_state_destroy(struct dnet_net_state *st);

void dnet_schedule_command(struct dnet_net_state *st);

int dnet_schedule_send(struct dnet_net_state *st);
int dnet_schedule_recv(struct dnet_net_state *st);

void dnet_unschedule_send(struct dnet_net_state *st);
void dnet_unschedule_all(struct dnet_net_state *st);

int dnet_setup_control_nolock(struct dnet_net_state *st);

int dnet_add_reconnect_state(struct dnet_node *n, const struct dnet_addr *addr, unsigned int join_state);

static inline struct dnet_net_state *dnet_state_get(struct dnet_net_state *st)
{
	atomic_inc(&st->refcnt);
	return st;
}

struct dnet_notify_bucket
{
	struct list_head		notify_list;
	pthread_rwlock_t		notify_lock;
};

int dnet_update_notify(struct dnet_net_state *st, struct dnet_cmd *cmd, void *data);

int dnet_notify_add(struct dnet_net_state *st, struct dnet_cmd *cmd);
int dnet_notify_remove(struct dnet_net_state *st, struct dnet_cmd *cmd);

int dnet_notify_init(struct dnet_node *n);
void dnet_notify_exit(struct dnet_node *n);

struct dnet_group
{
	struct rb_node		group_entry;

	unsigned int		group_id;
	struct dnet_node	*node;

	struct list_head	idc_list;

	atomic_t		refcnt;

	int			id_num;
	struct dnet_state_id	*ids;
};

static inline struct dnet_group *dnet_group_get(struct dnet_group *g)
{
	atomic_inc(&g->refcnt);
	return g;
}

void dnet_group_destroy(struct dnet_group *g);
static inline void dnet_group_put(struct dnet_group *g)
{
	if (g && atomic_dec_and_test(&g->refcnt))
		dnet_group_destroy(g);
}

struct dnet_transform
{
	void			*priv;

	int 			(* transform)(void *priv, struct dnet_session *s, const void *src, uint64_t size,
					void *dst, unsigned int *dsize, unsigned int flags);
	int 			(* transform_file)(void *priv, struct dnet_session *s, int fd, uint64_t offset,
					uint64_t size, void *dst, unsigned int *dsize, unsigned int flags);
};

int dnet_crypto_init(struct dnet_node *n);
void dnet_crypto_cleanup(struct dnet_node *n);

struct dnet_net_io {
	int			epoll_fd;
	pthread_t		tid;
	struct dnet_node	*n;
};

enum dnet_work_io_mode {
	DNET_WORK_IO_MODE_BLOCKING = 0,
	DNET_WORK_IO_MODE_NONBLOCKING,
	DNET_WORK_IO_MODE_LIFO,
};

struct dnet_work_pool;
struct dnet_work_io {
	struct list_head	reply_list;
	struct list_head	request_list;
	int			thread_index;
	uint64_t		trans;
	pthread_t		tid;
	int			joined;
	struct dnet_work_pool	*pool;
};

struct list_stat {
	uint64_t		list_size;
};

static inline void list_stat_init(struct list_stat *st) {
	st->list_size = 0ULL;
}

static inline void list_stat_size_increase(struct list_stat *st, int num) {
	st->list_size += num;
}

static inline void list_stat_size_decrease(struct list_stat *st, int num) {
	st->list_size -= num;
}

struct dnet_request_queue;
struct dnet_work_pool {
	struct dnet_node		*n;
	char				pool_id[6];  // reserve 10 bytes for thread_index from 16 bytes limit
					             // (http://man7.org/linux/man-pages/man3/pthread_setname_np.3.html)
	int				need_exit;
	int				mode;
	int				num;
	pthread_mutex_t			lock;
	struct dnet_work_io		*wio_list;

	struct dnet_request_queue	*request_queue;
};

struct dnet_work_pool_place
{
	pthread_mutex_t		lock;
	pthread_cond_t		wait;
	struct dnet_work_pool	*pool;
};

void dnet_work_pool_exit(struct dnet_work_pool_place *place);
int dnet_work_pool_alloc(struct dnet_work_pool_place *place,
                         struct dnet_node *n,
                         int num,
                         int mode,
                         size_t queue_limit,
                         const char *pool_id,
                         void *(*process)(void *));
int dnet_work_pool_place_init(struct dnet_work_pool_place *pool);
void dnet_work_pool_stop(struct dnet_work_pool_place *place);
void dnet_work_pool_place_cleanup(struct dnet_work_pool_place *pool);

struct dnet_io_pool {
	struct dnet_work_pool_place	recv_pool;
	struct dnet_work_pool_place	recv_pool_nb;
};

void dnet_check_io_pool(struct dnet_io_pool *io, uint64_t *queue_size, uint64_t *threads_count);

struct dnet_backends_manager;
struct dnet_io_pools_manager;
struct dnet_io {
	int			need_exit;

	int			net_thread_num, net_thread_pos;
	struct dnet_net_io	*net;

	struct dnet_backends_manager	*backends_manager;

	struct dnet_io_pool	pool;

	struct dnet_io_pools_manager	*pools_manager;

	// condition variable for waiting when io pools are able to process packets
	pthread_mutex_t		full_lock;
	pthread_cond_t		full_wait;
	int			blocked;

	struct list_stat	output_stats;
};

int dnet_state_accept_process(struct dnet_net_state *st, struct epoll_event *ev);
int dnet_io_init(struct dnet_node *n, struct dnet_config *cfg);
void *dnet_io_process(void *data_);
/* Set need_exit flag, stop and join pool threads */
void dnet_io_stop(struct dnet_node *n);
/* Free pool resources of node. Must be called after dnet_io_stop() */
void dnet_io_cleanup(struct dnet_node *n);

void dnet_io_req_free(struct dnet_io_req *r);

struct dnet_config_data {
	int cfg_addr_num;
	struct dnet_addr *cfg_addrs;

	struct dnet_config cfg_state;
};

void dnet_config_data_destroy(struct dnet_config_data *config_data);

struct dnet_route_list;
struct dnet_node {
	struct dnet_transform	transform;

	int			need_exit;

	int			flags;
	int			ro;

	pthread_attr_t		attr;

	int			addr_num;
	struct dnet_addr	*addrs;

	pthread_mutex_t		state_lock;
	struct rb_root		group_root;

	/* hosts client states by addresses, i.e. those who didn't join network */
	struct rb_root		empty_state_root;
	/* hosts server states by addresses, i.e. those who joined network */
	struct rb_root		dht_state_root;

	/* hosts all states added to given node */
	struct list_head	storage_state_list;

	atomic_t		trans;

	struct dnet_route_list	*route;
	struct dnet_net_state	*st;

	int			error;

	int			keep_cnt;
	int			keep_interval;
	int			keep_idle;

	dnet_logger		*log;
	dnet_logger		*access_log;

	struct timespec		wait_ts;

	struct dnet_io		*io;

	long			check_timeout;

	pthread_t		check_tid;
	pthread_t		reconnect_tid;
	long			stall_count;

	unsigned int		notify_hash_size;
	struct dnet_notify_bucket	*notify_hash;

	pthread_mutex_t		reconnect_lock;
	struct list_head	reconnect_list;
	int			reconnect_num;

	/*
	 * When user (client or server) adds new nodes via dnet_add_state()
	 * and helper functions, we put those addresses into this array.
	 *
	 * Periodic route request thread asks for route table random X groups
	 * plus all this addresses.
	 *
	 * It is needed to speed up large (several thousands of nodes) cluster
	 * convergence - usually in such big clusters 'remote' server config option
	 * contains the same nodes for simplicity. Thus the same nodes will always
	 * be the first who receive information about new nodes and thus the first
	 * to update route table, which in turn will be requested by newly connected
	 * clients/servers.
	 *
	 * @route_addrs are protected by @reconnect_lock. This array can not be shrunk,
	 * it will only grow.
	 */
	struct dnet_addr	*route_addr;
	size_t			route_addr_num;

	struct dnet_lock	counters_lock;
	struct dnet_stat_count	counters[__DNET_CMD_MAX * 2];

	int			bg_ionice_class;
	int			bg_ionice_prio;
	int			removal_delay;

	char			cookie[DNET_AUTH_COOKIE_SIZE];

	int			server_prio;
	int			client_prio;

	/*
	 * List of dnet_iterator.
	 * Used for iterator management e.g. pause/continue actions.
	 */
	struct list_head	iterator_list;
	/*
	 * Lock used for list management
	 */
	pthread_mutex_t		iterator_lock;

	void			*monitor;

	struct dnet_config_data *config_data;

	/*
	 * Test settings allows injection of leverages to control some
	 * low-level elliptics behaviour for testing purposes only
	 */
	struct dnet_test_settings *test_settings;
	/* Lock for test_settings */
	pthread_rwlock_t	test_settings_lock;

	/* Maximum number of packets sent to one state in a row. It is quota for fast connections
	 * after which net thread will switch to next ready connection.
	 */
	uint32_t		send_limit;
};


struct dnet_session {
	struct dnet_node	*node;

	int			group_num;
	int			*groups;

	struct timespec		wait_ts;

	struct dnet_time	ts;
	struct dnet_time	json_ts;

	uint64_t		cflags;
	uint64_t		user_flags;
	trace_id_t		trace_id;
	uint32_t		ioflags;
	uint64_t		cache_lifetime;

	/*
	 * If DNET_FLAGS_DIRECT is set then direct_id is used for sticking
	 * requests to the node which is responsible for a particular
	 * direct_id.id.
	 */
	struct dnet_id		direct_id;
	struct dnet_addr	direct_addr;
	int			direct_backend;

	/*
	 * If DNET_FLAGS_FORWARD is set then forward_addr is used for sticking
	 * requests to the node.
	 */
	struct dnet_addr	forward_addr;

	/* Namespace */
	char			*ns;
	int			nsize;
};

static inline int dnet_counter_init(struct dnet_node *n)
{
	memset(&n->counters, 0, __DNET_CMD_MAX * 2 * sizeof(struct dnet_stat_count));
	return dnet_lock_init(&n->counters_lock);
}

static inline void dnet_counter_destroy(struct dnet_node *n)
{
	return dnet_lock_destroy(&n->counters_lock);
}

static inline void dnet_counter_inc(struct dnet_node *n, int counter, int err)
{
	if (counter >= __DNET_CMD_MAX * 2)
		counter = DNET_CMD_UNKNOWN + __DNET_CMD_MAX;

	dnet_lock_lock(&n->counters_lock);
	if (!err)
		n->counters[counter].count++;
	else
		n->counters[counter].err++;
	dnet_lock_unlock(&n->counters_lock);
}

static inline void dnet_counter_set(struct dnet_node *n, int counter, int err, int64_t val)
{
	if (counter >= __DNET_CMD_MAX * 2)
		counter = DNET_CMD_UNKNOWN + __DNET_CMD_MAX;

	dnet_lock_lock(&n->counters_lock);
	if (!err)
		n->counters[counter].count = val;
	else
		n->counters[counter].err = val;
	dnet_lock_unlock(&n->counters_lock);
}

struct dnet_trans;
struct dnet_access_context;
int __attribute__((weak)) dnet_process_cmd_raw(struct dnet_net_state *st,
                                               struct dnet_cmd *cmd,
                                               void *data,
                                               int recursive,
                                               long queue_time,
                                               struct dnet_access_context *context);
int dnet_process_recv(struct dnet_net_state *st, struct dnet_io_req *r);
void dnet_trans_update_timestamp(struct dnet_trans *t);

int dnet_sendfile(struct dnet_net_state *st, int fd, uint64_t *offset, uint64_t size);

int dnet_send_request(struct dnet_net_state *st, struct dnet_io_req *r);


int __attribute__((weak)) dnet_send_ack(struct dnet_net_state *st,
                                        struct dnet_cmd *cmd,
                                        int err,
                                        int recursive,
                                        struct dnet_access_context *context);
void dnet_schedule_io(struct dnet_node *n, struct dnet_io_req *r);

struct dnet_config;

int dnet_socket_create_listening(struct dnet_node *node, const struct dnet_addr *addr);

void dnet_set_sockopt(struct dnet_node *n, int s);
void dnet_sock_close(struct dnet_node *n, int s);

enum dnet_join_state {
	DNET_JOIN = 1,			/* Node joined the network */
	DNET_WANT_RECONNECT,		/* State must be reconnected, when remote peer failed */
};

int __attribute__((weak)) dnet_state_join(struct dnet_net_state *st);

struct dnet_trans_stats {
	uint64_t	send_time;		/* cumulative time spent on sending a request */
	uint64_t	send_queue_time;	/* time the request spent in send queue */
	size_t		recv_replies;		/* number of received replies */
	uint64_t	recv_size;		/* cumulative size of all received replies */
	uint64_t	recv_queue_time;	/* cumulative time spent by all received replies in io queue */
	uint64_t	recv_time;		/* cumulative time spent on receiving all replies */
};

struct dnet_trans
{
	struct rb_node			trans_entry;
	struct rb_node			timer_entry;

	/* is used when checking thread moves transaction out of the above trees because of timeout */
	struct list_head		trans_list_entry;

	struct timespec			start_ts;
	struct timespec			time_ts;
	struct timespec			wait_ts;

	struct dnet_net_state		*orig; /* only for forward */
	size_t				alloc_size;

	struct dnet_node		*n;
	struct dnet_net_state		*st;
	uint64_t			trans, rcv_trans;
	struct dnet_cmd			cmd;

	atomic_t			refcnt;

	int				command; /* main command this transaction carries */

	void				*priv;
	int				(* complete)(struct dnet_addr *addr,
						     struct dnet_cmd *cmd,
						     void *priv);

	struct dnet_trans_stats		stats;
};

void dnet_trans_destroy(struct dnet_trans *t);
int dnet_trans_send_fail(struct dnet_session *s, struct dnet_addr *addr, struct dnet_trans_control *ctl, int err, int destroy);
struct dnet_trans *dnet_trans_alloc(struct dnet_node *n, uint64_t size);
int dnet_trans_alloc_send_state(struct dnet_session *s, struct dnet_net_state *st, struct dnet_trans_control *ctl);
int dnet_trans_timer_setup(struct dnet_trans *t);

static inline struct dnet_trans *dnet_trans_get(struct dnet_trans *t)
{
	atomic_inc(&t->refcnt);
	return t;
}

static inline void dnet_trans_put(struct dnet_trans *t)
{
	if (t && atomic_dec_and_test(&t->refcnt))
		dnet_trans_destroy(t);
}

int dnet_trans_insert_nolock(struct dnet_net_state *st, struct dnet_trans *a);
void dnet_trans_remove_nolock(struct dnet_net_state *st, struct dnet_trans *t);
struct dnet_trans *dnet_trans_search(struct dnet_net_state *st, uint64_t trans);

int dnet_trans_insert_timer_nolock(struct dnet_net_state *st, struct dnet_trans *a);
void dnet_trans_remove_timer_nolock(struct dnet_net_state *st, struct dnet_trans *t);

void dnet_trans_remove(struct dnet_trans *t);

void dnet_trans_clean_list(struct list_head *head, int error);
int dnet_trans_iterate_move_transaction(struct dnet_net_state *st, struct list_head *head);
int dnet_state_reset_nolock_noclean(struct dnet_net_state *st, int error, struct list_head *head);

int dnet_trans_send(struct dnet_trans *t, struct dnet_io_req *req);

int dnet_trans_forward(struct dnet_io_req *r, struct dnet_net_state *orig, struct dnet_net_state *forward);

int dnet_recv_list(struct dnet_node *n, struct dnet_net_state *st);

ssize_t dnet_send_fd(struct dnet_net_state *st, void *header, uint64_t hsize,
		int fd, uint64_t offset, uint64_t dsize, int on_exit, struct dnet_access_context *context);
ssize_t dnet_send_data(struct dnet_net_state *st,
                       void *header,
                       uint64_t hsize,
                       void *data,
                       uint64_t dsize,
                       struct dnet_access_context *context);
ssize_t dnet_send(struct dnet_net_state *st, void *data, uint64_t size, struct dnet_access_context *context);
ssize_t dnet_send_nolock(struct dnet_net_state *st, void *data, uint64_t size);

struct dnet_addr_storage
{
	int				reconnect_time, reconnect_time_max;
	struct list_head		reconnect_entry;
	struct dnet_addr		addr;
	unsigned int			__join_state;
};

int dnet_check_thread_start(struct dnet_node *n);
void dnet_check_thread_stop(struct dnet_node *n);
void dnet_reconnect_and_check_route_table(struct dnet_node *node);

int dnet_set_name(const char *format, ...);

struct dnet_map_fd {
	int			fd;
	uint64_t		offset, size;

	void			*data;

	uint64_t		mapped_size;
	void			*mapped_data;
};

/* Read only mapping wrapper */
int dnet_data_map(struct dnet_map_fd *map);
/* Read-write mapping wrapper */
int dnet_data_map_rw(struct dnet_map_fd *map);
void dnet_data_unmap(struct dnet_map_fd *map);

int dnet_ids_update(struct dnet_node *n, int update_local, const char *file, struct dnet_addr *cfg_addrs, uint32_t backend_id);

/*
 * Internal iterator state
 */
struct dnet_iterator {
	uint64_t			id;		/* Iterator's unique id */
	enum dnet_iterator_action	state;		/* Desired state of iterator */
	struct list_head		list;		/* List of all iterators */
	pthread_mutex_t			lock;		/* Lock for iterator manipulation */
	pthread_cond_t			wait;		/* We wait here in case we stopped */
};

/*
 * Public iterator API
 */
struct dnet_iterator *dnet_iterator_create(struct dnet_node *n);
void dnet_iterator_destroy(struct dnet_node *n, struct dnet_iterator *it);
int dnet_iterator_set_state(struct dnet_node *n,
		enum dnet_iterator_action action, uint64_t id);
void dnet_iterator_cancel_all(struct dnet_node *n);

int dnet_iterator_flow_control(struct dnet_iterator *it);

/*
 * Low level iterator API
 * TODO: make static?
 */

/* Allocate and init iterator */
struct dnet_iterator *dnet_iterator_alloc(uint64_t id);
/* Free previously allocated iterator */
void dnet_iterator_free(struct dnet_iterator *it);
/* Iterator list management routines */
int dnet_iterator_list_insert_nolock(struct dnet_node *n, struct dnet_iterator *it);
struct dnet_iterator *dnet_iterator_list_lookup_nolock(struct dnet_node *n, uint64_t id);
int dnet_iterator_list_remove(struct dnet_node *n, uint64_t id);
/* Misc routines */
uint64_t dnet_iterator_list_next_id_nolock(struct dnet_node *n);

/*
 * Common private data:
 * Request + next callback and it's argument.
 */
struct dnet_iterator_common_private {
	struct dnet_iterator_request	*req;		/* Original request */
	struct dnet_iterator_range	*range;		/* Original ranges */
	struct dnet_iterator		*it;		/* Iterator control structure */

	/* This callback will be invoked by dnet_iterator_callback_common(), which is invoked by low-level backend iterator
	 * @priv - callback specific private data, @next_private below, like @dnet_iterator_send_private
	 * @data - @dnet_iterator_response + data read from the backend @fd (only if DNET_IFLAGS_DATA is set in @req->flags)
	 * @dsize - total size of @data, will only be equal to size of the response if DNET_IFLAGS_DATA is not set
	 * @fd - low-level backend fd (if supported)
	 * @data_offset - offset of the data for each key within @fd
	 */
	int				(*next_callback)(void *priv, void *data, uint64_t dsize, int fd, uint64_t data_offset);
	/* Private data for callback */
	void				*next_private;

	uint64_t			total_keys;	/* number of keys that will be iterated */
	atomic_t			iterated_keys;	/* number of keys that have been already iterated */
	atomic_t			skipped_keys;	/* number of keys that have been skipped */
};

/*
 * Send over network callback private.
 */
struct dnet_iterator_send_private {
	struct dnet_net_state		*st;		/* State to send data to */
	struct dnet_cmd			*cmd;		/* Command */
};

/*
 * Save to file callback private.
 */
struct dnet_iterator_file_private {
	int				fd;		/* Append mode file descriptor */
};

static inline void dnet_version_encode(struct dnet_id *id)
{
	int *ids = (int *)(id->id);

	ids[0] = dnet_bswap32(ELLIPTICS_PROTOCOL_VERSION_0);
	ids[1] = dnet_bswap32(ELLIPTICS_PROTOCOL_VERSION_1);
	ids[2] = dnet_bswap32(ELLIPTICS_PROTOCOL_VERSION_2);
	ids[3] = dnet_bswap32(ELLIPTICS_PROTOCOL_VERSION_3);
}

static inline void dnet_version_decode(struct dnet_id *id, int version[4])
{
	int *ids = (int *)(id->id);
	unsigned int i;

	for (i = 0; i < 4; ++i)
		version[i] = dnet_bswap32(ids[i]);
}

static inline int dnet_empty_addr(struct dnet_addr *addr)
{
	static struct dnet_addr __empty;

	return memcmp(addr, &__empty, addr->addr_len) == 0;
}

/**
 * dnet_read_ll() - interruption-safe wrapper for pread(2)
 */
static inline int dnet_read_ll(int fd, char *data, size_t size, off_t offset)
{
	ssize_t bytes;

	while (size) {
again:
		bytes = pread(fd, data, size, offset);
		if (bytes == -1) {
			if (errno == -EINTR)
				goto again;
			return -errno;
		} else if (bytes == 0)
			return -ESPIPE;
		data += bytes;
		size -= bytes;
		offset += bytes;
	}
	return 0;
}

/**
 * dnet_write_ll() - interruption-safe wrapper for pwrite(2)
 */
static inline int dnet_write_ll(int fd, const char *data, size_t size, off_t offset)
{
	int err = 0;
	ssize_t bytes;

	while (size) {
again:
		bytes = pwrite(fd, data, size, offset);
		if (bytes == -1) {
			if (errno == -EINTR)
				goto again;
			err = -errno;
			goto err_out_exit;
		}
		data += bytes;
		size -= bytes;
		offset += bytes;
	}
err_out_exit:
	return err;
}

/*
 * Watermarks for number of bytes written into the wire
 */
#define DNET_SERVER_SEND_WATERMARK_HIGH		(100*1024*1024L)

/*
 * Send data over network to another server as set of WRITE commands
 */
struct dnet_server_send_ctl {
	void				*state;		/* Client connection used to send progress status
							 * As void* to allow low-level backends to set it up
							 */
	struct dnet_cmd			cmd;		/* Original client's command */

	uint64_t			iflags;		/* Iterator flags */

	int				backend_id;	/* Source backend_id */
	int				*groups;	/* Groups to send WRITE commands */
	int				group_num;

	int				timeout;	/* write timeout */

	pthread_mutex_t			write_lock;	/* Lock for @write_wait */
	pthread_cond_t			write_wait;	/* Waiting for pending writes */
	long				bytes_pending_max;	/* maximum size of the 'queue' of write requests */
	atomic_t			bytes_pending;	/* Number of bytes in-flight to remote servers */

	int				write_error;	/* Set to the first error occurred during write
							 * This will stop iterator. */


	atomic_t			refcnt;		/* Reference counter which will be increased for every
							 * async WRITE operation. get/put methods should be used
							 * if structure will be provided to async routings.
							 */
};

static inline const char* dnet_print_trans(const struct dnet_trans *t) {
	static __thread char __dnet_print_trans[256];
	snprintf(__dnet_print_trans, sizeof(__dnet_print_trans),
	         "trans: %llu, st: %s/%d, cflags: %s, wait-ts: %ld",
	         (unsigned long long)t->trans,
	         dnet_state_dump_addr(t->st), t->cmd.backend_id,
	         dnet_flags_dump_cflags(t->cmd.flags),
	         t->wait_ts.tv_sec);
	return __dnet_print_trans;
}

/*
 * Statistics about handled command
 */
struct dnet_cmd_stats {
	long queue_time;	// time that the command spent in queue
	int handled_in_cache;	// whether the command handled by cache
	long handle_time;	// time spent on the command handle
	uint64_t size;		// size of data received or sent by command
};


#ifdef __cplusplus
}
#endif

#endif /* __DNET_ELLIPTICS_H */
