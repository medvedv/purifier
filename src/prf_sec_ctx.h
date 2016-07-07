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

#ifndef _PRF_SEC_CTX_H_
#define _PRF_SEC_CTX_H_

#define PRF_COOKIEBITS				24
#define PRF_COOKIEMASK				(((uint32_t)1 << PRF_COOKIEBITS) - 1)
#define PRF_MAX_SYNPROXY_MBUF_CHAIN		4

#define PRF_SRC_TRACK_HASH_SIZE			(1 << 16) /* 128Mb for 2^18 buckets */
#define PRF_SRC_TRACK_HASH_MASK			((PRF_SRC_TRACK_HASH_SIZE) - 1)
#define PRF_SRC_TRACK_PRF_KEYS_PER_BUCKET	14
#define PRF_NB_SRC_TRACK_ENT			131071

#define PRF_NB_IPSET_KEYS			16
#define PRF_IPSET_HASH_SIZE			(1 << 12) /* 12.6 Mb for 2^12 buckets */
#define PRF_IPSET_HASH_MASK			((PRF_IPSET_HASH_SIZE) - 1)
#define PRF_IPSET_UPDATE_TIMER			1
#define PRF_IPSET_WL_DEF_TIMER			604800	/* 1 week*/
#define PRF_IPSET_BL_DEF_TIMER			3600	/* 1 hour*/


#define PRF_TCP_STATE_SYNPROXY_INIT		(1 << 14)
#define PRF_TCP_STATE_SYNPROXY			(1 << 15)

/* src_track flags defines */
#define PRF_SRC_TRACK_CONN_FLAG			0x1
#define PRF_SRC_TRACK_RATE_FLAG			0x2
#define PRF_SYN_PROXY_SACK_PERM			0x4
#define PRF_SYN_PROXY_WSCALE_PERM		0x8
#define PRF_WHITE_LIST_CHECK			0x10
#define PRF_BLACK_LIST_CHECK			0x20
#define PRF_SRC_TRACK_BAN			0x40
#define PRF_HTTP_CHECK				0x80

#define PRF_DEFAULT_MSS				536
#define PRF_MAX_TCP_WINDOW			32767

struct prf_lcore_conf;

extern uint32_t prf_embrionic_threshold;
extern uint32_t prf_syn_proxy_secret[2];

static const uint16_t prf_msstab[] = {
	536,
	1024,
	1436,
	1460
};

struct prf_src_track_hash;

struct prf_sec_ctx_rule {
	rte_atomic64_t		ref_cnt;
	uint64_t		bucket_size;		/* for src rate tracking */
	uint64_t		period;			/* for src rate tracking */
	uint32_t		max_states;		/* for src count tracking */
	uint16_t		syn_proxy_mss;		/* protected server MSS */
	uint8_t			syn_proxy_wscale;	/* protected server wscale factor */
	uint8_t			flags;			/* conn and/or rate flags */
	struct prf_src_track_hash	*hash_table;
	struct prf_ipset_hash	*white_list;
	struct prf_ipset_hash	*black_list;
} __rte_cache_aligned;

struct prf_src_track_node {
	uint32_t		key;
	uint32_t		counter;
	uint64_t		time;
	uint64_t		bucket;
	struct prf_sec_ctx_rule	*rule;
};

struct prf_src_track_ent {
	struct prf_src_track_ent	*next;
	struct prf_src_track_node	node;
} __rte_cache_aligned;

struct prf_src_track_key_bucket {
	uint32_t			key[PRF_SRC_TRACK_PRF_KEYS_PER_BUCKET];
	struct prf_src_track_ent	*head;
} __rte_cache_aligned;

struct prf_src_track_node_bucket {
	struct prf_src_track_node	node[PRF_SRC_TRACK_PRF_KEYS_PER_BUCKET];
} __rte_cache_aligned;

struct prf_src_track_hash {
	struct prf_src_track_key_bucket		key_bucket[PRF_SRC_TRACK_HASH_SIZE];
	struct prf_src_track_node_bucket	node_bucket[PRF_SRC_TRACK_HASH_SIZE];
} __rte_cache_aligned;


struct prf_ipset_bucket {
	uint32_t	key[PRF_NB_IPSET_KEYS];
	uint64_t	timer[PRF_NB_IPSET_KEYS];
} __rte_cache_aligned;

struct prf_ipset_hash {
	uint64_t		ban_timer;
	uint64_t		flags;
	struct prf_ipset_bucket	bucket[PRF_IPSET_HASH_SIZE];
};

struct prf_src_track_hash *prf_src_track_hash_init(unsigned lcore_id, int idx);

struct prf_ipset_hash *prf_ipset_hash_init(unsigned lcore_id, int idx);

#endif /* _PRF_SEC_CTX_H_ */
