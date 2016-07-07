/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2015 Vladimir Medvedkin <medvedkinv@gmail.com>
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _STATEFUL_H_
#define _STATEFUL_H_

#define GC_INTERVAL		1000
#define GC_BUCKETS		128 /* 3 * 4kb in cache ~ 100 packet @ 14.88mpps*/

#define TCP_CONN_HASH_SIZE	(1 << 22) /* 184.5Mb for 2^19 buckets; 1,5G for 2^22*/
#define TCP_CONN_HASH_MASK	((TCP_CONN_HASH_SIZE) - 1)
#define KEYS_PER_BUCKET		4
#define NB_TCP_ENT		1048575

#define TCPHDR_FIN		0x01
#define TCPHDR_SYN		0x02
#define TCPHDR_RST		0x04
#define TCPHDR_PSH		0x08
#define TCPHDR_ACK		0x10
#define TCPHDR_URG		0x20
#define TCPHDR_ECE		0x40
#define TCPHDR_CWR		0x80

#define TCP_SYN_SET		0
#define TCP_SYNACK_SET		1
#define TCP_FIN_SET		2
#define TCP_ACK_SET		3

#define TCP_STATE_NONE		0
#define TCP_STATE_SYN_SENT	1
#define TCP_STATE_SYN_RCV	2
#define TCP_STATE_ESTABL	3
#define TCP_STATE_FIN_WAIT	4
#define TCP_STATE_CLOSE_WAIT	5
#define TCP_STATE_LAST_ACK	6
#define TCP_STATE_TIME_WAIT	7
#define TCP_STATE_NB_STATES	8

#define TCP_IV		TCP_STATE_NONE
#define TCP_SS		TCP_STATE_SYN_SENT
#define TCP_SR		TCP_STATE_SYN_RCV
#define TCP_ES		TCP_STATE_ESTABL
#define TCP_FW		TCP_STATE_FIN_WAIT
#define TCP_CW		TCP_STATE_CLOSE_WAIT
#define TCP_LA		TCP_STATE_LAST_ACK
#define TCP_TW		TCP_STATE_TIME_WAIT

struct prf_lcore_conf;

static const uint8_t tcp_valid_flags[(TCPHDR_FIN|TCPHDR_SYN|TCPHDR_RST|TCPHDR_ACK|TCPHDR_URG) + 1]__rte_cache_aligned;
static const uint8_t tcp_valid_flags[(TCPHDR_FIN|TCPHDR_SYN|TCPHDR_RST|TCPHDR_ACK|TCPHDR_URG) + 1] = {
	[TCPHDR_SYN]				= 1,
	[TCPHDR_SYN|TCPHDR_ACK]			= 1,
	[TCPHDR_RST]				= 1,
	[TCPHDR_RST|TCPHDR_ACK]			= 1,
	[TCPHDR_FIN|TCPHDR_ACK]			= 1,
	[TCPHDR_FIN|TCPHDR_ACK|TCPHDR_URG]	= 1,
	[TCPHDR_ACK]				= 1,
	[TCPHDR_ACK|TCPHDR_URG]			= 1,
};

static const uint8_t tcp_trans_table[2][4][TCP_STATE_NB_STATES] __rte_cache_aligned;
static const uint8_t tcp_trans_table[2][4][TCP_STATE_NB_STATES] = {
	{
/* ORIGINAL DIRECTION*/
/*			TCP_IV  TCP_SS  TCP_SR  TCP_ES  TCP_FW  TCP_CW  TCP_LA  TCP_TW */
/*syn*/		{	TCP_SS, TCP_SS, TCP_IV, TCP_IV, TCP_IV, TCP_IV, TCP_IV, TCP_SS },

/*			TCP_IV  TCP_SS  TCP_SR  TCP_ES  TCP_FW  TCP_CW  TCP_LA  TCP_TW */
/*syn ack*/	{	TCP_IV, TCP_IV, TCP_IV, TCP_IV, TCP_IV, TCP_IV, TCP_IV, TCP_IV },

/*			TCP_IV  TCP_SS  TCP_SR  TCP_ES  TCP_FW  TCP_CW  TCP_LA  TCP_TW */
/*fin*/		{	TCP_IV, TCP_IV, TCP_FW, TCP_FW, TCP_LA, TCP_LA, TCP_LA, TCP_TW },

/*			TCP_IV  TCP_SS  TCP_SR  TCP_ES  TCP_FW  TCP_CW  TCP_LA  TCP_TW */
/*ack*/		{	TCP_IV, TCP_IV, TCP_ES, TCP_ES, TCP_CW, TCP_CW, TCP_TW, TCP_TW }
	},
	{
/* REPLY DIRECTION*/
/*			TCP_IV  TCP_SS  TCP_SR  TCP_ES  TCP_FW  TCP_CW  TCP_LA  TCP_TW */
/*syn*/		{	TCP_IV, TCP_IV, TCP_IV, TCP_IV, TCP_IV, TCP_IV, TCP_IV, TCP_IV },

/*			TCP_IV  TCP_SS  TCP_SR  TCP_ES  TCP_FW  TCP_CW  TCP_LA  TCP_TW */
/*syn ack*/	{	TCP_IV, TCP_SR, TCP_SR, TCP_IV, TCP_IV, TCP_IV, TCP_IV, TCP_IV },

/*			TCP_IV  TCP_SS  TCP_SR  TCP_ES  TCP_FW  TCP_CW  TCP_LA  TCP_TW */
/*fin*/		{	TCP_IV, TCP_IV, TCP_FW, TCP_FW, TCP_LA, TCP_LA, TCP_LA, TCP_TW },

/*			TCP_IV  TCP_SS  TCP_SR  TCP_ES  TCP_FW  TCP_CW  TCP_LA  TCP_TW*/
/*ack*/		{	TCP_IV, TCP_IV, TCP_SR, TCP_ES, TCP_CW, TCP_CW, TCP_TW, TCP_TW }
	}
};

#define TCPOPT_EOL		0
#define TCPOPT_NOP		1
#define TCPOPT_MSS		2
#define TCPOPT_WINDOW		3
#define TCPOPT_SACK_PERM	4
#define TCPOPT_SACK		5
#define TCPOPT_TIMESTAMP	8

#define TCPOLEN_MSS		4
#define TCPOLEN_WINDOW		3
#define TCPOLEN_SACK_PERM	2
#define TCPOLEN_TIMESTAMP	10

#define TCP_MAX_WINSHIFT	14
/*td_flags defines*/
#define TCP_FLAG_WSCALE		0x1
#define TCP_FLAG_SACK_PERM	0x2
#define TCP_FLAG_CLOSE_INIT     0x4	/*For future use to avoid closing after FIN retransmit*/

#define SEQ_LEQ(a, b)		((int)((a)-(b)) <= 0)
#define SEQ_GEQ(a, b)		((int)((a)-(b)) >= 0)
#define SEQ_GT(a, b)		((int)((a)-(b)) > 0)

#define DIR_ORIG		0
#define DIR_REV			1
#define DIR_NO_MATCH		2

extern uint64_t tcp_timer_table[TCP_STATE_NB_STATES] __rte_cache_aligned;
extern uint32_t hash_initval;

struct tcpopts {
	uint16_t	mss;
	uint8_t		wscale;
	uint8_t		sackok;
};


struct conn_tuple {
	uint32_t	src_addr;
	uint32_t	dst_addr;
	uint16_t	src_port;
	uint16_t	dst_port;
};

struct tcp_conn_state {
	uint32_t	packets;
	uint32_t	bytes;
	uint32_t	td_end;
	uint32_t	td_maxend;
	uint16_t	td_maxwin;
	uint8_t		td_flags;
	uint8_t		td_wscale;
} __attribute__((__packed__));

struct src_track_node;

struct tcp_conn {
	struct tcp_conn_state	dir[2];
	uint32_t		seq_diff;
	uint16_t		state;
	uint16_t		flags;
	struct src_track_node	*src_track_node;
	struct rte_mbuf		*m;
} __attribute__((__packed__));

struct tcp_ent {
	struct tcp_ent		*next;
	uint64_t		idle_timer;
	struct conn_tuple	key;
	struct tcp_conn		tcp_conn __rte_cache_aligned;
};

struct tcp_key_bucket {
	struct conn_tuple	key[KEYS_PER_BUCKET];
	uint64_t		pad;
	struct tcp_ent		*tp;
} __rte_cache_aligned;

struct timer_bucket {
	uint64_t		idle_timer[KEYS_PER_BUCKET];
};

struct tcp_conn_bucket {
	struct tcp_conn		tcp_conn[KEYS_PER_BUCKET];
} __rte_cache_aligned;

struct ipv4_tcp_hash {
	struct tcp_key_bucket	tcp_key_bucket[TCP_CONN_HASH_SIZE];
	struct timer_bucket	timer_bucket[TCP_CONN_HASH_SIZE]__rte_cache_aligned;
	struct tcp_conn_bucket	tcp_conn_bucket[TCP_CONN_HASH_SIZE];
};

/* For bulk lookup */
struct tcp_lookup {
	int		dir;
	struct rte_mbuf	*m;
	uint64_t	*timer;
	struct tcp_conn	*tcp_conn;
};

struct ipv4_tcp_hash *ipv4_tcp_hash_init(unsigned lcore_id);

void process_tcp_seg(struct prf_lcore_conf *conf, struct rte_mbuf *m, struct tcp_conn *tcp_conn, uint64_t *timer, uint64_t time, int dir);

int ipv4_tcp_conn_add(struct prf_lcore_conf *conf, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint64_t **timer, struct tcp_conn **tcp_conn);

void ipv4_tcp_conn_del_key(struct prf_lcore_conf *conf, uint64_t bucket, int index);

int ipv4_tcp_conn_lookup(struct prf_lcore_conf *conf, struct conn_tuple *key, uint64_t **timer, struct tcp_conn **tcp_conn);

int ipv4_tcp_conn_lookup_burst(struct prf_lcore_conf *conf, struct rte_mbuf **mb_arr, struct rte_mbuf **mb_new, int nb_pkt, uint64_t time);

void ipv4_tcp_garbage_collect(struct prf_lcore_conf *conf, uint64_t time);

inline uint32_t tcp_seq_plus_len(uint32_t seq, uint32_t len, uint8_t flags);

int tcp_get_event(uint8_t flags);

int get_opts(uint8_t *ptr, int length, struct tcpopts *options);

#endif
