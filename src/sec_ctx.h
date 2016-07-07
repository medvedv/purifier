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

#ifndef _SEC_CTX_H_
#define _SEC_CTX_H_

#define COOKIEBITS			24
#define COOKIEMASK			(((uint32_t)1 << COOKIEBITS) - 1)
#define MAX_SYNPROXY_MBUF_CHAIN		4

#define SRC_TRACK_HASH_SIZE		(1 << 16) /* 128Mb for 2^18 buckets */
#define SRC_TRACK_HASH_MASK		((SRC_TRACK_HASH_SIZE) - 1)
#define SRC_TRACK_PRF_KEYS_PER_BUCKET	14
#define NB_SRC_TRACK_ENT		131071

#define NB_IPSET_KEYS			16
#define IPSET_HASH_SIZE			(1 << 12) /* 12.6 Mb for 2^12 buckets */
#define IPSET_HASH_MASK			((IPSET_HASH_SIZE) - 1)
#define IPSET_UPDATE_TIMER		1
#define IPSET_WHITE_LIST_DEF_TIMER	604800	/* 1 week*/
#define IPSET_BLACK_LIST_DEF_TIMER	3600	/* 1 hour*/


#define TCP_STATE_SYNPROXY_INIT		(1 << 14)
#define TCP_STATE_SYNPROXY		(1 << 15)

/* src_track flags defines */
#define SRC_TRACK_CONN_FLAG		0x1
#define SRC_TRACK_RATE_FLAG		0x2
#define SYN_PROXY_SACK_PERM		0x4
#define SYN_PROXY_WSCALE_PERM		0x8
#define WHITE_LIST_CHECK		0x10
#define BLACK_LIST_CHECK		0x20
#define SRC_TRACK_BAN			0x40
#define HTTP_CHECK			0x80

#define DEFAULT_MSS			536
#define MAX_TCP_WINDOW			32767

struct prf_lcore_conf;

extern uint32_t embrionic_threshold;
extern uint32_t syn_proxy_secret[2];

static const uint16_t msstab[] = {
	536,
	1024,
	1436,
	1460
};

struct src_track_hash;

struct sec_ctx_rule {
	rte_atomic64_t		ref_cnt;
	uint64_t		bucket_size;		/* for src rate tracking */
	uint64_t		period;			/* for src rate tracking */
	uint32_t		max_states;		/* for src count tracking */
	uint16_t		syn_proxy_mss;		/* protected server MSS */
	uint8_t			syn_proxy_wscale;	/* protected server wscale factor */
	uint8_t			flags;			/* conn and/or rate flags */
	struct src_track_hash	*hash_table;
	struct ipset_hash	*white_list;
	struct ipset_hash	*black_list;
} __rte_cache_aligned;

struct src_track_node {
	uint32_t		key;
	uint32_t		counter;
	uint64_t		time;
	uint64_t		bucket;
	struct sec_ctx_rule	*rule;
};

struct src_track_ent {
	struct src_track_ent	*next;
	struct src_track_node	node;
} __rte_cache_aligned;

struct src_track_key_bucket {
	uint32_t		key[SRC_TRACK_PRF_KEYS_PER_BUCKET];
	struct src_track_ent	*head;
} __rte_cache_aligned;

struct src_track_node_bucket {
	struct src_track_node	node[SRC_TRACK_PRF_KEYS_PER_BUCKET];
} __rte_cache_aligned;

struct src_track_hash {
	struct src_track_key_bucket	key_bucket[SRC_TRACK_HASH_SIZE];
	struct src_track_node_bucket	node_bucket[SRC_TRACK_HASH_SIZE];
} __rte_cache_aligned;


struct ipset_bucket {
	uint32_t	key[NB_IPSET_KEYS];
	uint64_t	timer[NB_IPSET_KEYS];
} __rte_cache_aligned;

struct ipset_hash {
	uint64_t		ban_timer;
	uint64_t		flags;
	struct ipset_bucket	bucket[IPSET_HASH_SIZE];
};

struct src_track_hash *src_track_hash_init(unsigned lcore_id, int idx);

struct ipset_hash *ipset_hash_init(unsigned lcore_id, int idx);

#endif
