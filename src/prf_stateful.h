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

#ifndef _PRF_STATEFUL_H_
#define _PRF_STATEFUL_H_

#define PRF_GC_INTERVAL		1000
#define PRF_GC_BUCKETS		128 /* 3 * 4kb in cache ~ 100 packet @ 14.88mpps*/

#define PRF_TCP_CONN_HASH_SIZE	(1 << 22) /* 184.5Mb for 2^19 buckets; 1,5G for 2^22*/
#define PRF_TCP_CONN_HASH_MASK	((PRF_TCP_CONN_HASH_SIZE) - 1)
#define PRF_KEYS_PER_BUCKET		4
#define PRF_NB_TCP_ENT		1048575

#define PRF_TCPHDR_FIN		0x01
#define PRF_TCPHDR_SYN		0x02
#define PRF_TCPHDR_RST		0x04
#define PRF_TCPHDR_PSH		0x08
#define PRF_TCPHDR_ACK		0x10
#define PRF_TCPHDR_URG		0x20
#define PRF_TCPHDR_ECE		0x40
#define PRF_TCPHDR_CWR		0x80

#define PRF_TCP_SYN_SET		0
#define PRF_TCP_SYNACK_SET		1
#define PRF_TCP_FIN_SET		2
#define PRF_TCP_ACK_SET		3

#define PRF_TCP_STATE_NONE		0
#define PRF_TCP_STATE_SYN_SENT	1
#define PRF_TCP_STATE_SYN_RCV	2
#define PRF_TCP_STATE_ESTABL	3
#define PRF_TCP_STATE_FIN_WAIT	4
#define PRF_TCP_STATE_CLOSE_WAIT	5
#define PRF_TCP_STATE_LAST_ACK	6
#define PRF_TCP_STATE_TIME_WAIT	7
#define PRF_TCP_STATE_NB_STATES	8

#define PRF_TCP_IV		PRF_TCP_STATE_NONE
#define PRF_TCP_SS		PRF_TCP_STATE_SYN_SENT
#define PRF_TCP_SR		PRF_TCP_STATE_SYN_RCV
#define PRF_TCP_ES		PRF_TCP_STATE_ESTABL
#define PRF_TCP_FW		PRF_TCP_STATE_FIN_WAIT
#define PRF_TCP_CW		PRF_TCP_STATE_CLOSE_WAIT
#define PRF_TCP_LA		PRF_TCP_STATE_LAST_ACK
#define PRF_TCP_TW		PRF_TCP_STATE_TIME_WAIT

struct prf_lcore_conf;

static const uint8_t prf_tcp_valid_flags[(PRF_TCPHDR_FIN|PRF_TCPHDR_SYN|PRF_TCPHDR_RST|PRF_TCPHDR_ACK|PRF_TCPHDR_URG) + 1]__rte_cache_aligned;
static const uint8_t prf_tcp_valid_flags[(PRF_TCPHDR_FIN|PRF_TCPHDR_SYN|PRF_TCPHDR_RST|PRF_TCPHDR_ACK|PRF_TCPHDR_URG) + 1] = {
	[PRF_TCPHDR_SYN]				= 1,
	[PRF_TCPHDR_SYN|PRF_TCPHDR_ACK]			= 1,
	[PRF_TCPHDR_RST]				= 1,
	[PRF_TCPHDR_RST|PRF_TCPHDR_ACK]			= 1,
	[PRF_TCPHDR_FIN|PRF_TCPHDR_ACK]			= 1,
	[PRF_TCPHDR_FIN|PRF_TCPHDR_ACK|PRF_TCPHDR_URG]	= 1,
	[PRF_TCPHDR_ACK]				= 1,
	[PRF_TCPHDR_ACK|PRF_TCPHDR_URG]			= 1,
};

static const uint8_t prf_tcp_trans_table[2][4][PRF_TCP_STATE_NB_STATES] __rte_cache_aligned;
static const uint8_t prf_tcp_trans_table[2][4][PRF_TCP_STATE_NB_STATES] = {
	{
/* ORIGINAL DIRECTION*/
/*			PRF_TCP_IV  PRF_TCP_SS  PRF_TCP_SR  PRF_TCP_ES  PRF_TCP_FW  PRF_TCP_CW  PRF_TCP_LA  PRF_TCP_TW */
/*syn*/		{	PRF_TCP_SS, PRF_TCP_SS, PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_SS },

/*			PRF_TCP_IV  PRF_TCP_SS  PRF_TCP_SR  PRF_TCP_ES  PRF_TCP_FW  PRF_TCP_CW  PRF_TCP_LA  PRF_TCP_TW */
/*syn ack*/	{	PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_IV },

/*			PRF_TCP_IV  PRF_TCP_SS  PRF_TCP_SR  PRF_TCP_ES  PRF_TCP_FW  PRF_TCP_CW  PRF_TCP_LA  PRF_TCP_TW */
/*fin*/		{	PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_FW, PRF_TCP_FW, PRF_TCP_LA, PRF_TCP_LA, PRF_TCP_LA, PRF_TCP_TW },

/*			PRF_TCP_IV  PRF_TCP_SS  PRF_TCP_SR  PRF_TCP_ES  PRF_TCP_FW  PRF_TCP_CW  PRF_TCP_LA  PRF_TCP_TW */
/*ack*/		{	PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_ES, PRF_TCP_ES, PRF_TCP_CW, PRF_TCP_CW, PRF_TCP_TW, PRF_TCP_TW }
	},
	{
/* REPLY DIRECTION*/
/*			PRF_TCP_IV  PRF_TCP_SS  PRF_TCP_SR  PRF_TCP_ES  PRF_TCP_FW  PRF_TCP_CW  PRF_TCP_LA  PRF_TCP_TW */
/*syn*/		{	PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_IV },

/*			PRF_TCP_IV  PRF_TCP_SS  PRF_TCP_SR  PRF_TCP_ES  PRF_TCP_FW  PRF_TCP_CW  PRF_TCP_LA  PRF_TCP_TW */
/*syn ack*/	{	PRF_TCP_IV, PRF_TCP_SR, PRF_TCP_SR, PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_IV },

/*			PRF_TCP_IV  PRF_TCP_SS  PRF_TCP_SR  PRF_TCP_ES  PRF_TCP_FW  PRF_TCP_CW  PRF_TCP_LA  PRF_TCP_TW */
/*fin*/		{	PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_FW, PRF_TCP_FW, PRF_TCP_LA, PRF_TCP_LA, PRF_TCP_LA, PRF_TCP_TW },

/*			PRF_TCP_IV  PRF_TCP_SS  PRF_TCP_SR  PRF_TCP_ES  PRF_TCP_FW  PRF_TCP_CW  PRF_TCP_LA  PRF_TCP_TW*/
/*ack*/		{	PRF_TCP_IV, PRF_TCP_IV, PRF_TCP_SR, PRF_TCP_ES, PRF_TCP_CW, PRF_TCP_CW, PRF_TCP_TW, PRF_TCP_TW }
	}
};

#define PRF_TCPOPT_EOL		0
#define PRF_TCPOPT_NOP		1
#define PRF_TCPOPT_MSS		2
#define PRF_TCPOPT_WINDOW		3
#define PRF_TCPOPT_SACK_PERM	4
#define PRF_TCPOPT_SACK		5
#define PRF_TCPOPT_TIMESTAMP	8

#define PRF_TCPOLEN_MSS		4
#define PRF_TCPOLEN_WINDOW		3
#define PRF_TCPOLEN_SACK_PERM	2
#define PRF_TCPOLEN_TIMESTAMP	10

#define PRF_TCP_MAX_WINSHIFT	14
/*td_flags defines*/
#define PRF_TCP_FLAG_WSCALE	0x1
#define PRF_TCP_FLAG_SACK_PERM	0x2
#define PRF_TCP_FLAG_CLOSE_INIT	0x4	/*For future use to avoid closing after FIN retransmit*/

#define PRF_SEQ_LEQ(a, b)		((int)((a)-(b)) <= 0)
#define PRF_SEQ_GEQ(a, b)		((int)((a)-(b)) >= 0)
#define PRF_SEQ_GT(a, b)		((int)((a)-(b)) > 0)

#define PRF_DIR_ORIG		0
#define PRF_DIR_REV			1
#define PRF_DIR_NO_MATCH		2

extern uint64_t prf_tcp_timer_table[PRF_TCP_STATE_NB_STATES] __rte_cache_aligned;
extern uint32_t prf_hash_initval;

struct prf_tcpopts {
	uint16_t	mss;
	uint8_t		wscale;
	uint8_t		sackok;
};


struct prf_conn_tuple {
	uint32_t	src_addr;
	uint32_t	dst_addr;
	uint16_t	src_port;
	uint16_t	dst_port;
};

struct prf_tcp_conn_state {
	uint32_t	packets;
	uint32_t	bytes;
	uint32_t	td_end;
	uint32_t	td_maxend;
	uint16_t	td_maxwin;
	uint8_t		td_flags;
	uint8_t		td_wscale;
} __attribute__((__packed__));

struct prf_src_track_node;

struct prf_tcp_conn {
	struct prf_tcp_conn_state	dir[2];
	uint32_t		seq_diff;
	uint16_t		state;
	uint16_t		flags;
	struct prf_src_track_node	*prf_src_track_node;
	struct rte_mbuf		*m;
} __attribute__((__packed__));

struct prf_tcp_ent {
	struct prf_tcp_ent		*next;
	uint64_t		idle_timer;
	struct prf_conn_tuple	key;
	struct prf_tcp_conn		prf_tcp_conn __rte_cache_aligned;
};

struct prf_tcp_key_bucket {
	struct prf_conn_tuple	key[PRF_KEYS_PER_BUCKET];
	uint64_t		pad;
	struct prf_tcp_ent		*tp;
} __rte_cache_aligned;

struct prf_timer_bucket {
	uint64_t		idle_timer[PRF_KEYS_PER_BUCKET];
};

struct prf_tcp_conn_bucket {
	struct prf_tcp_conn		prf_tcp_conn[PRF_KEYS_PER_BUCKET];
} __rte_cache_aligned;

struct prf_ipv4_tcp_hash {
	struct prf_tcp_key_bucket	prf_tcp_key_bucket[PRF_TCP_CONN_HASH_SIZE];
	struct prf_timer_bucket	prf_timer_bucket[PRF_TCP_CONN_HASH_SIZE]__rte_cache_aligned;
	struct prf_tcp_conn_bucket	prf_tcp_conn_bucket[PRF_TCP_CONN_HASH_SIZE];
};

/* For bulk lookup */
struct prf_tcp_lookup {
	int			dir;
	struct rte_mbuf		*m;
	uint64_t		*timer;
	struct prf_tcp_conn	*prf_tcp_conn;
};

struct prf_ipv4_tcp_hash *prf_ipv4_tcp_hash_init(unsigned lcore_id);

void prf_process_tcp_seg(struct prf_lcore_conf *conf, struct rte_mbuf *m, struct prf_tcp_conn *prf_tcp_conn, uint64_t *timer, uint64_t time, int dir);

int prf_ipv4_tcp_conn_add(struct prf_lcore_conf *conf, uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint64_t **timer, struct prf_tcp_conn **prf_tcp_conn);

void prf_ipv4_tcp_conn_del_key(struct prf_lcore_conf *conf, uint64_t bucket, int index);

int prf_ipv4_tcp_conn_lookup(struct prf_lcore_conf *conf, struct prf_conn_tuple *key, uint64_t **timer, struct prf_tcp_conn **prf_tcp_conn);

int prf_ipv4_tcp_conn_lookup_burst(struct prf_lcore_conf *conf, struct rte_mbuf **mb_arr, struct rte_mbuf **mb_new, int nb_pkt, uint64_t time);

void prf_ipv4_tcp_garbage_collect(struct prf_lcore_conf *conf, uint64_t time);

uint32_t prf_tcp_seq_plus_len(uint32_t seq, uint32_t len, uint8_t flags);

int prf_tcp_get_event(uint8_t flags);

int prf_get_opts(uint8_t *ptr, int length, struct prf_tcpopts *options);

#endif /* _PRF_STATEFUL_H_ */
