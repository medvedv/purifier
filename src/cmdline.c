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

#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <termios.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <sys/queue.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_atomic.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline.h>

#include "acl.h"
#include "sec_ctx.h"
#include "stateful.h"
#include "main.h"

struct cmdline_head {
	cmdline_fixed_string_t action;
	cmdline_fixed_string_t target;
};

cmdline_parse_token_string_t cmd_show =
	TOKEN_STRING_INITIALIZER(struct cmdline_head,
				action, "show");
cmdline_parse_token_string_t cmd_show_del =
	TOKEN_STRING_INITIALIZER(struct cmdline_head,
				action, "show#del");
cmdline_parse_token_string_t cmd_del =
	TOKEN_STRING_INITIALIZER(struct cmdline_head,
				action, "del");
cmdline_parse_token_string_t cmd_create =
	TOKEN_STRING_INITIALIZER(struct cmdline_head,
				action, "create");
cmdline_parse_token_string_t cmd_set =
	TOKEN_STRING_INITIALIZER(struct cmdline_head,
				action, "set");

cmdline_parse_token_string_t cmd_sec_ctx =
	TOKEN_STRING_INITIALIZER(struct cmdline_head,
				target, "sec_ctx");
cmdline_parse_token_string_t cmd_policy =
	TOKEN_STRING_INITIALIZER(struct cmdline_head,
				target, "policy");
cmdline_parse_token_string_t cmd_embrio =
	TOKEN_STRING_INITIALIZER(struct cmdline_head,
				target, "embrionic_threshold");
cmdline_parse_token_string_t cmd_timer =
	TOKEN_STRING_INITIALIZER(struct cmdline_head,
				target, "timer");
cmdline_parse_token_string_t cmd_acl =
	TOKEN_STRING_INITIALIZER(struct cmdline_head,
				target, "acl");

#ifndef NIPQUAD
#define NIPQUAD_FMT "%u.%u.%u.%u"
#define NIPQUAD(addr)				\
	(unsigned)((unsigned char *)&addr)[0],	\
	(unsigned)((unsigned char *)&addr)[1],	\
	(unsigned)((unsigned char *)&addr)[2],	\
	(unsigned)((unsigned char *)&addr)[3]
#endif

#define TCP_STATE_NAME_MAX	32
#define SEC_CTX_NAME_LEN_MAX	64

#define COLLECT_STAT(counter, field)	do {			\
	counter = 0;						\
	RTE_LCORE_FOREACH_SLAVE(i) {				\
		counter += prf_lcore_conf[i].stats.field;		\
	}							\
} while (0)

#define ACL_CNT_BITMAP_BITS_IN_WORD		3

struct sec_ctx_entry {
	SLIST_ENTRY(sec_ctx_entry) next;
	char		name[SEC_CTX_NAME_LEN_MAX];
	int		num;
	uint32_t	acl_ref_counter;
};

struct acl_entry {
	LIST_ENTRY(acl_entry)	next;
	uint32_t		idx;
	int32_t			cnt_idx;
	uint32_t		src_ip;
	uint32_t		dst_ip;
	uint16_t		sport_low;
	uint16_t		sport_hi;
	uint16_t		dport_low;
	uint16_t		dport_hi;
	uint8_t			sprefixlen;
	uint8_t			dprefixlen;
	uint8_t			action;
	struct sec_ctx_entry	*sec_ctx;
};

/* define struct sec_ctx_list */
SLIST_HEAD(sec_ctx_list, sec_ctx_entry);

/* define struct acl_list */
LIST_HEAD(acl_list, acl_entry);

int default_policy = ACCEPT;

struct sec_ctx_list global_sec_ctx_list;
struct acl_list global_acl_list;
uint8_t acl_cnt_bitmap[(1 << (ACL_MAX_RULES_BITS - ACL_CNT_BITMAP_BITS_IN_WORD))] = {0};

static inline void
free_acl_cnt_idx(int idx)
{
	idx--;
	acl_cnt_bitmap[(idx >> ACL_CNT_BITMAP_BITS_IN_WORD)] &=
		~(1 << (idx & ((1 << ACL_CNT_BITMAP_BITS_IN_WORD) - 1)));

}

static inline int
get_acl_cnt_idx(void)
{
	uint32_t i, j;

	for (i = 0; i < sizeof(acl_cnt_bitmap); i++) {
		for (j = 0; j < 8; j++) {
			if (!(acl_cnt_bitmap[i] & (1 << j))) {
				acl_cnt_bitmap[i] |= (1 << j);
				return (i << ACL_CNT_BITMAP_BITS_IN_WORD | j) + 1;
			}
		}
	}
	return -ENOENT;
}

static void
cmdline_build_acl(void)
{
	int sec_ctx_idx, ret;
	int i = 0;
	struct acl4_rule *rules;
	struct acl_entry *ent;
	struct rte_acl_ctx *new_ctx, *tmp_ctx;
	uint32_t gc_arr[RTE_MAX_LCORE];

	LIST_FOREACH(ent, &global_acl_list, next) {
		i++;
	}
	if (i == 0) {
		build_empty_acl(&new_ctx);
		goto init_acl;
	}

	rules = rte_calloc(NULL, i, sizeof(struct acl4_rule), 0);
	i = 0;
	LIST_FOREACH(ent, &global_acl_list, next) {
		rules[i].data.category_mask			= 1;
		rules[i].data.priority				= RTE_ACL_MAX_PRIORITY - ent->idx;
		sec_ctx_idx = (ent->action == SEC_CTX) ? ent->sec_ctx->num : 0;
		rules[i].data.userdata = ent->action | (sec_ctx_idx << ACL_SEC_CTX_RESULT_SHIFT)|
							(ent->cnt_idx << ACL_RESULT_RULE_SHIFT);
		rules[i].field[PROTO_FIELD_IPV4].value.u8	= IPPROTO_TCP;
		rules[i].field[PROTO_FIELD_IPV4].mask_range.u8	= 0xff;
		rules[i].field[SRC_FIELD_IPV4].value.u32	= rte_be_to_cpu_32(ent->src_ip);
		rules[i].field[SRC_FIELD_IPV4].mask_range.u32	= ent->sprefixlen;
		rules[i].field[DST_FIELD_IPV4].value.u32	= rte_be_to_cpu_32(ent->dst_ip);
		rules[i].field[DST_FIELD_IPV4].mask_range.u32	= ent->dprefixlen;
		rules[i].field[SRCP_FIELD_IPV4].value.u16	= ent->sport_low;
		rules[i].field[SRCP_FIELD_IPV4].mask_range.u16	= ent->sport_hi;
		rules[i].field[DSTP_FIELD_IPV4].value.u16	= ent->dport_low;
		rules[i].field[DSTP_FIELD_IPV4].mask_range.u16	= ent->dport_hi;
		i++;
	}
	ret = acl_create((struct rte_acl_rule *)rules, i, &new_ctx);
	if (ret != 0)
		rte_exit(EXIT_FAILURE, "Failed to create ACL context\n");
	rte_free(rules);

init_acl:
	tmp_ctx = acl_ctx;
	rte_mb();
	acl_ctx = new_ctx;
	rte_mb();

	RTE_LCORE_FOREACH_SLAVE(i) {
		if (i == prf_primarycore_id)
			continue;
		gc_arr[i] = prf_lcore_conf[i].bucket_pair_nb;
	}
	i = 1;
	rte_mb();
	while (i != 0) {
		i = 0;
		if ((i == prf_mastercore_id) || (i == prf_primarycore_id))
			continue;
		if (gc_arr[i] == prf_lcore_conf[i].bucket_pair_nb)
			i += 1;
	}
	rte_acl_free(tmp_ctx);
}

static void
dump_states(struct cmdline *cl)
{
	int i, j, k;
	struct prf_conn_tuple tuple;
	uint64_t timer, ttl_time;
	struct prf_tcp_conn prf_tcp_conn;
	char tcp_state[TCP_STATE_NAME_MAX];

	RTE_LCORE_FOREACH_SLAVE(i) {
		if (i == prf_primarycore_id)
			continue;
		for (j = 0; j < PRF_TCP_CONN_HASH_SIZE; j++) {
			for (k = 0; k < PRF_KEYS_PER_BUCKET; k++) {
				if (prf_lcore_conf[i].tcp_hash->prf_tcp_key_bucket[j].key[k].src_addr == 0)
					continue;
				memcpy((uint8_t *)&tuple, (uint8_t *)&prf_lcore_conf[i].tcp_hash->prf_tcp_key_bucket[j].key[k], sizeof(struct prf_conn_tuple));
				memcpy((uint8_t *)&prf_tcp_conn, (uint8_t *)&prf_lcore_conf[i].tcp_hash->prf_tcp_conn_bucket[j].prf_tcp_conn[k], sizeof(struct prf_tcp_conn));
				timer = prf_lcore_conf[i].tcp_hash->prf_timer_bucket[j].idle_timer[k];
				rte_wmb();
				if ((prf_lcore_conf[i].tcp_hash->prf_tcp_key_bucket[j].key[k].src_addr == 0) || (timer <= prf_lcore_conf[i].timer))
					continue;
				switch (prf_tcp_conn.state) {
				case PRF_TCP_IV:
					snprintf(tcp_state, sizeof(tcp_state), "PRF_TCP_STATE_NONE");
					break;
				case PRF_TCP_SS:
					snprintf(tcp_state, sizeof(tcp_state), "PRF_TCP_STATE_SYN_SENT");
					break;
				case PRF_TCP_SR:
					snprintf(tcp_state, sizeof(tcp_state), "PRF_TCP_STATE_SYN_RCV");
					break;
				case PRF_TCP_ES:
					snprintf(tcp_state, sizeof(tcp_state), "PRF_TCP_STATE_ESTABL");
					break;
				case PRF_TCP_FW:
					snprintf(tcp_state, sizeof(tcp_state), "PRF_TCP_STATE_FIN_WAIT");
					break;
				case PRF_TCP_CW:
					snprintf(tcp_state, sizeof(tcp_state), "PRF_TCP_STATE_CLOSE_WAIT");
					break;
				case PRF_TCP_LA:
					snprintf(tcp_state, sizeof(tcp_state), "PRF_TCP_STATE_LAST_ACK");
					break;
				case PRF_TCP_TW:
					snprintf(tcp_state, sizeof(tcp_state), "PRF_TCP_STATE_TIME_WAIT");
					break;
				default:
					snprintf(tcp_state, sizeof(tcp_state), "ERROR");
					break;
				}
				ttl_time = (timer - prf_lcore_conf[i].timer) / prf_tsc_hz;
				cmdline_printf(cl,	"%d pkts %d bytes"
							"[%s]"
							" Src ip " NIPQUAD_FMT
							" Dst ip " NIPQUAD_FMT
							" Src port %u Dst port %u"
							" TTL %"PRIu64"\t\n",
							prf_tcp_conn.dir[0].packets + prf_tcp_conn.dir[1].packets, prf_tcp_conn.dir[0].bytes + prf_tcp_conn.dir[1].bytes,
							tcp_state,
							NIPQUAD(tuple.src_addr),
							NIPQUAD(tuple.dst_addr),
							rte_be_to_cpu_16(tuple.src_port), rte_be_to_cpu_16(tuple.dst_port),
							ttl_time);
			}
		}
	}
}

/* *** TOKEN SEC_CTX *** */
struct token_sec_ctx_list_data {
	struct sec_ctx_list	*list;
};

struct token_sec_ctx_list {
	struct cmdline_token_hdr	hdr;
	struct token_sec_ctx_list_data	sec_ctx_list_data;
};

typedef struct token_sec_ctx_list parse_token_sec_ctx_list_t;

struct cmdline_token_ops token_sec_ctx_list_ops;

static int parse_sec_ctx_list(cmdline_parse_token_hdr_t *tk, const char *srcbuf, void *res);
static int complete_get_nb_sec_ctx_list(cmdline_parse_token_hdr_t *tk);
static int complete_get_elt_sec_ctx_list(cmdline_parse_token_hdr_t *tk, int idx,
						char *dstbuf, unsigned int size);
static int get_help_sec_ctx_list(cmdline_parse_token_hdr_t *tk, char *dstbuf, unsigned int size);

#define TOKEN_SEC_CTX_LIST_INITIALIZER(structure, field, sec_ctx_list_ptr)	\
{										\
	.hdr = {								\
		.ops = &token_sec_ctx_list_ops,				\
		.offset = offsetof(structure, field),				\
	},									\
		.sec_ctx_list_data = {						\
		.list = sec_ctx_list_ptr,					\
	},									\
}

struct cmdline_token_ops token_sec_ctx_list_ops = {
	.parse = parse_sec_ctx_list,
	.complete_get_nb = complete_get_nb_sec_ctx_list,
	.complete_get_elt = complete_get_elt_sec_ctx_list,
	.get_help = get_help_sec_ctx_list,
};

int
parse_sec_ctx_list(cmdline_parse_token_hdr_t *tk, const char *buf, void *res)
{
	struct token_sec_ctx_list *tk2 = (struct token_sec_ctx_list *)tk;
	struct token_sec_ctx_list_data *tkd = &tk2->sec_ctx_list_data;
	struct sec_ctx_entry *ent;
	unsigned int token_len = 0;

	if (*buf == 0)
		return -1;

	while (!cmdline_isendoftoken(buf[token_len]))
		token_len++;

	SLIST_FOREACH(ent, tkd->list, next) {
		if (token_len != strnlen(ent->name, SEC_CTX_NAME_LEN_MAX))
			continue;
		if (strncmp(buf, ent->name, token_len))
			continue;
		break;
	}
	if (ent == NULL)
		return -1;

	if (res != NULL)
		*(struct sec_ctx_entry **)res = ent;

	return token_len;
}

int complete_get_nb_sec_ctx_list(cmdline_parse_token_hdr_t *tk)
{
	struct token_sec_ctx_list *tk2 = (struct token_sec_ctx_list *)tk;
	struct token_sec_ctx_list_data *tkd = &tk2->sec_ctx_list_data;
	struct sec_ctx_entry *ent;
	int ret = 0;

	SLIST_FOREACH(ent, tkd->list, next) {
		ret++;
	}
	return ret;
}

int complete_get_elt_sec_ctx_list(cmdline_parse_token_hdr_t *tk,
				int idx, char *dstbuf, unsigned int size)
{
	struct token_sec_ctx_list *tk2 = (struct token_sec_ctx_list *)tk;
	struct token_sec_ctx_list_data *tkd = &tk2->sec_ctx_list_data;
	struct sec_ctx_entry *ent;
	int i = 0;
	unsigned len;

	SLIST_FOREACH(ent, tkd->list, next) {
		if (i++ == idx)
			break;
	}
	if (ent == NULL)
		return -1;

	len = strnlen(ent->name, SEC_CTX_NAME_LEN_MAX);
	if ((len + 1) > size)
		return -1;

	if (dstbuf != NULL)
		snprintf(dstbuf, size, "%s", ent->name);

	return 0;
}

int get_help_sec_ctx_list(__attribute__((unused)) cmdline_parse_token_hdr_t *tk,
				char *dstbuf, unsigned int size)
{
	snprintf(dstbuf, size, "Sec-ctx-List");
	return 0;
}

/* *** END OF TOKEN SEC_CTX *** */

/* *** SHOW ALL *** */
static void cmd_show_all_parsed(__attribute__((unused)) void *parsed_result,
				struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmdline_head *res = parsed_result;
	struct sec_ctx_entry *ent;
	struct sec_ctx_rule *rule;
	struct acl_entry *acl;
	uint64_t counter = 0;
	int i;

	struct rte_eth_stats stats;

	if (strcmp(res->target, "sec_ctx") == 0) {
		SLIST_FOREACH(ent, &global_sec_ctx_list, next) {
			RTE_LCORE_FOREACH_SLAVE(i) {
				if (i == prf_primarycore_id)
					continue;
				break;
			}
			rule = &prf_lcore_conf[i].rules[ent->num];

			cmdline_printf(cl,	"\t\n Sec context %s :\t\n"
						"\t Syn proxy mss %d\t\n", ent->name, rule->syn_proxy_mss);
			if (rule->flags & SYN_PROXY_WSCALE_PERM) {
				cmdline_printf(cl,
						"\t Syn proxy wscale %d\t\n", rule->syn_proxy_wscale);
			}
			if (rule->flags & SYN_PROXY_SACK_PERM) {
				cmdline_printf(cl,
						"\t Syn proxy window scale permit\t\n");
			}
			if (rule->flags & SRC_TRACK_CONN_FLAG) {
				cmdline_printf(cl,
						"\t Src track max states %d\t\n", rule->max_states);
			}
			if ((rule->flags & SRC_TRACK_RATE_FLAG) && (rule->period != 0)) {
				cmdline_printf(cl,
						"\t Src track rate %"PRIu64" pre second\t\n"
						"\t Src track bucket size %"PRIu64"\t\n",
						prf_tsc_hz / rule->period, rule->bucket_size);
			}
			if (rule->flags & WHITE_LIST_CHECK) {
				cmdline_printf(cl,
						"\t White list on\t\n"
						"\t White list timer %"PRIu64"\t\n", rule->white_list->ban_timer / prf_tsc_hz);
			}
			if (rule->flags & BLACK_LIST_CHECK) {
				cmdline_printf(cl,
						"\t Black list on\t\n"
						"\t Black list ban time %"PRIu64"\t\n", rule->black_list->ban_timer / prf_tsc_hz);
				if (rule->flags & SRC_TRACK_BAN) {
						cmdline_printf(cl,
						"\t Src track overload ban\t\n");
				}
				if (rule->black_list->flags & IPSET_UPDATE_TIMER) {
						cmdline_printf(cl,
						"\t Black list update timer\t\n");
				}
			}
		}
	} else if (strcmp(res->target, "statistics") == 0) {
		cmdline_printf(cl,	"\t\n Statistic: \t\n");
		COLLECT_STAT(counter, rx_pkts);
		cmdline_printf(cl,	"\t Rx pkts %"PRIu64"\t\n", counter);
		COLLECT_STAT(counter, tx_pkts);
		cmdline_printf(cl,	"\t Tx pkts %"PRIu64"\t\n", counter);
		COLLECT_STAT(counter, malformed);
		cmdline_printf(cl,	"\t malformed %"PRIu64"\t\n", counter);
		COLLECT_STAT(counter, bad_csum);
		cmdline_printf(cl,	"\t bad_csum %"PRIu64"\t\n", counter);
		COLLECT_STAT(counter, frags);
		cmdline_printf(cl,	"\t frags %"PRIu64"\t\n", counter);
		COLLECT_STAT(counter, bad_flags);
		cmdline_printf(cl,	"\t bad_flags %"PRIu64"\t\n", counter);
		COLLECT_STAT(counter, rst_set);
		cmdline_printf(cl,	"\t rst_set %"PRIu64"\t\n", counter);
		COLLECT_STAT(counter, state_match);
		cmdline_printf(cl,	"\t state_match %"PRIu64"\t\n", counter);
		COLLECT_STAT(counter, state_mismatch);
		cmdline_printf(cl,	"\t state_mismatch %"PRIu64"\t\n", counter);
		COLLECT_STAT(counter, cookies_sent);
		cmdline_printf(cl,	"\t cookies_sent %"PRIu64"\t\n", counter);
		COLLECT_STAT(counter, cookies_rcv);
		cmdline_printf(cl,	"\t cookies_rcv %"PRIu64"\t\n", counter);
		COLLECT_STAT(counter, src_track_overflow);
		cmdline_printf(cl,	"\t src_track_overflow %"PRIu64"\t\n", counter);
		COLLECT_STAT(counter, inserts);
		cmdline_printf(cl,	"\t inserts %"PRIu64"\t\n", counter);
		COLLECT_STAT(counter, removals);
		cmdline_printf(cl,	"\t removals %"PRIu64"\t\n", counter);
		COLLECT_STAT(counter, tw_reuse);
		cmdline_printf(cl,	"\t tw_reuse %"PRIu64"\t\n", counter);
		COLLECT_STAT(counter, bad_seq_ack);
		cmdline_printf(cl,	"\t bad_seq_ack %"PRIu64"\t\n", counter);
		COLLECT_STAT(counter, chained_lookup);
		cmdline_printf(cl,	"\t chained_lookup %"PRIu64"\t\n", counter);
		COLLECT_STAT(counter, chained_states);
		cmdline_printf(cl,	"\t chained_states %"PRIu64"\t\n", counter);
		COLLECT_STAT(counter, no_mem_pool);
		cmdline_printf(cl,	"\t no_mem_pool %"PRIu64"\t\n", counter);
		COLLECT_STAT(counter, states_counter);
		cmdline_printf(cl,	"\t states_counter %"PRIu64"\t\n", counter);
		COLLECT_STAT(counter, embrionic_counter);
		cmdline_printf(cl,	"\t embrionic_counter %"PRIu64"\t\n", counter);
	} else if (strcmp(res->target, "timers") == 0) {
		cmdline_printf(cl, "TCP Timers:\t\n");
		cmdline_printf(cl, "\t Syn sent : %"PRIu64"\t\n", prf_tcp_timer_table[PRF_TCP_STATE_SYN_SENT] / prf_tsc_hz);
		cmdline_printf(cl, "\t Syn rcv : %"PRIu64"\t\n", prf_tcp_timer_table[PRF_TCP_STATE_SYN_RCV] / prf_tsc_hz);
		cmdline_printf(cl, "\t Established : %"PRIu64"\t\n", prf_tcp_timer_table[PRF_TCP_STATE_ESTABL] / prf_tsc_hz);
		cmdline_printf(cl, "\t Fin wait :  %"PRIu64"\t\n", prf_tcp_timer_table[PRF_TCP_STATE_FIN_WAIT] / prf_tsc_hz);
		cmdline_printf(cl, "\t Close wait :  %"PRIu64"\t\n", prf_tcp_timer_table[PRF_TCP_STATE_CLOSE_WAIT] / prf_tsc_hz);
		cmdline_printf(cl, "\t Last ACK :  %"PRIu64"\t\n", prf_tcp_timer_table[PRF_TCP_STATE_LAST_ACK] / prf_tsc_hz);
		cmdline_printf(cl, "\t Time wait :  %"PRIu64"\t\n", prf_tcp_timer_table[PRF_TCP_STATE_TIME_WAIT] / prf_tsc_hz);
	} else if (strcmp(res->target, "connections") == 0) {
		dump_states(cl);
	} else if (strcmp(res->target, "acl") == 0) {
		cmdline_printf(cl, "\tCounter\tRule Index\tAccess list\t\n");
		LIST_FOREACH(acl, &global_acl_list, next) {
			COLLECT_STAT(counter, acl_stat[acl->cnt_idx]);
			cmdline_printf(cl, "\t%"PRIu64"", counter);
			cmdline_printf(cl, "\t%d src "NIPQUAD_FMT"/%d", acl->idx, NIPQUAD(acl->src_ip), acl->sprefixlen);
			cmdline_printf(cl, " dst "NIPQUAD_FMT"/%d", NIPQUAD(acl->dst_ip), acl->dprefixlen);
			cmdline_printf(cl, " sport_range %d %d", acl->sport_low, acl->sport_hi);
			cmdline_printf(cl, " dport_range %d %d", acl->dport_low, acl->dport_hi);
			if (acl->action == DROP) {
				cmdline_printf(cl, " drop\t\n");
			} else if (acl->action == ACCEPT) {
				 cmdline_printf(cl, " accept\t\n");
			} else if (acl->action == SEC_CTX) {
				cmdline_printf(cl, " sec_ctx %s\t\n", acl->sec_ctx->name);
			}
		}
	} else if (strcmp(res->target, "embrionic_threshold") == 0) {
		cmdline_printf(cl, "embrionic_threshold %d\t\n", embrionic_threshold);
	} else if (strcmp(res->target, "policy") == 0) {
		COLLECT_STAT(counter, acl_stat[0]);
		switch (default_policy) {
		case DROP:
			cmdline_printf(cl, "\t %"PRIu64"\t DROP policy\t\n", counter);
			break;
		case ACCEPT:
			cmdline_printf(cl, "\t %"PRIu64"\t ACCEPT policy\t\n", counter);
			break;
		default:
			cmdline_printf(cl, "\t Unknown policy\t\n");
			break;
		}
	} else if (strcmp(res->target, "interface_stats") == 0) {
		for (i = 0; i < PRF_MAX_PORTS; i++) {
			rte_eth_stats_get(i, &stats);
			cmdline_printf(cl,      "Port %d :\t\n", i);
			cmdline_printf(cl,      "\tRX pkts %"PRIu64" :\t\n", stats.ipackets);
			cmdline_printf(cl,      "\tTX pkts %"PRIu64" :\t\n", stats.opackets);
			cmdline_printf(cl,      "\tRX bytes %"PRIu64" :\t\n", stats.ibytes);
			cmdline_printf(cl,      "\tTX bytes %"PRIu64" :\t\n", stats.obytes);
			cmdline_printf(cl,      "\tRX missed %"PRIu64" :\t\n", stats.imissed);
			cmdline_printf(cl,      "\tBad CRC %"PRIu64" :\t\n", stats.ibadcrc);
			cmdline_printf(cl,      "\tBad len %"PRIu64" :\t\n", stats.ibadlen);
			cmdline_printf(cl,      "\tRX errors %"PRIu64" :\t\n", stats.ierrors);
			cmdline_printf(cl,      "\tTX errors %"PRIu64" :\t\n", stats.oerrors);
			cmdline_printf(cl,      "\tRX mcast %"PRIu64" :\t\n", stats.imcasts);
			cmdline_printf(cl,      "\tRX no mbuf %"PRIu64" :\t\n", stats.rx_nombuf);
		}
	}
}

cmdline_parse_token_string_t cmd_all_target =
	TOKEN_STRING_INITIALIZER(struct cmdline_head, target,
		"sec_ctx#statistics#timers#connections#acl#embrionic_threshold#policy#interface_stats");

cmdline_parse_inst_t cmd_show_all = {
	.f = cmd_show_all_parsed,
	.data = NULL,
	.help_str = "Show system information",
	.tokens = {
		(void *)&cmd_show,
		(void *)&cmd_all_target,
		NULL,
	},
};

/* *** END OF SHOW SEC_CTX ALL *** */

/* *** CREATE SEC CTX *** */
struct cmd_create_sec_ctx {
	struct cmdline_head head;
	cmdline_fixed_string_t sec_ctx_name;
};

static void cmd_create_sec_ctx_parsed(__attribute__((unused)) void *parsed_result,
					struct cmdline *cl,
					__attribute__((unused)) void *data)
{
	struct cmd_create_sec_ctx *res = parsed_result;
	struct sec_ctx_entry *ent, *new_ent;
	int i, j = 0;

	SLIST_FOREACH(ent, &global_sec_ctx_list, next) {
		if (!strcmp(res->sec_ctx_name, ent->name)) {
			cmdline_printf(cl, "\tSecurity context %s already exist\t\n", res->sec_ctx_name);
			return;
		}
		j++;
	}
	if (j >= PRF_SEC_CTX_MAX_RULES) {
		cmdline_printf(cl, "\tSecurity context number exhaused\t\n");
		return;
	}
	new_ent = rte_zmalloc(NULL, sizeof(*new_ent), CACHE_LINE_SIZE);
	if (new_ent == NULL) {
		cmdline_printf(cl, "\tmem error\t\n");
		return;
	}
	snprintf(new_ent->name, sizeof(new_ent->name), "%s", res->sec_ctx_name);
	/*lookup free index*/
	for (i = 0; i < PRF_SEC_CTX_MAX_RULES; i++) {
		SLIST_FOREACH(ent, &global_sec_ctx_list, next) {
			if (i == ent->num)
				goto next_rule;
		}
		/*We find first free index, lets check for free ctx*/
		RTE_LCORE_FOREACH_SLAVE(j) {
			if (j == prf_primarycore_id)
				continue;
			if (rte_atomic64_read(&prf_lcore_conf[j].rules[i].ref_cnt) != 0)
				goto next_rule;
		}
		/*Free context found, init*/
		new_ent->num = i;
/* TODO: fix possible memory leak */
		RTE_LCORE_FOREACH_SLAVE(j) {
			prf_lcore_conf[j].rules[i].flags = 0;
			prf_lcore_conf[j].rules[i].syn_proxy_mss = DEFAULT_MSS;
			prf_lcore_conf[j].rules[i].syn_proxy_wscale = 0xf;
			if (j == prf_primarycore_id)
				continue;
			/*check src track hash*/
			if (prf_lcore_conf[j].rules[i].hash_table == NULL) {
				if ((prf_lcore_conf[j].rules[i].hash_table = src_track_hash_init(j, i)) == NULL) {
					cmdline_printf(cl, "\t Not enough memory\t\n");
					rte_free(new_ent);
					return;
				}
			} else {
				memset(prf_lcore_conf[j].rules[i].hash_table, 0, sizeof(struct src_track_hash));
			}
			/*check white list*/
			if (prf_lcore_conf[j].rules[i].white_list == NULL) {
				if ((prf_lcore_conf[j].rules[i].white_list = ipset_hash_init(j, i)) == NULL) {
					cmdline_printf(cl, "\t Not enough memory\t\n");
					rte_free(new_ent);
					return;
				}
			} else {
				memset(prf_lcore_conf[j].rules[i].white_list, 0, sizeof(struct ipset_hash));
			}
			/*check black list*/
			if (prf_lcore_conf[j].rules[i].black_list == NULL) {
				if ((prf_lcore_conf[j].rules[i].black_list = ipset_hash_init(j, i)) == NULL) {
					cmdline_printf(cl, "\t Not enough memory\t\n");
					rte_free(new_ent);
					return;
				}
			} else {
				memset(prf_lcore_conf[j].rules[i].black_list, 0, sizeof(struct ipset_hash));
			}
		}
		SLIST_INSERT_HEAD(&global_sec_ctx_list, new_ent, next);
		cmdline_printf(cl, "\tSec_ctx %s added, index=%d\t\n", new_ent->name, new_ent->num);
		return;
next_rule:;
	}
	rte_free(new_ent);
	cmdline_printf(cl, "\tNot enough memory \t\n");
}

cmdline_parse_token_string_t cmd_sec_ctx_name =
	TOKEN_STRING_INITIALIZER(struct cmd_create_sec_ctx,
		sec_ctx_name, NULL);

cmdline_parse_inst_t cmd_create_sec_ctx = {
	.f = cmd_create_sec_ctx_parsed,
	.data = NULL,
	.help_str = "Create security context with defaul settings",
	.tokens = {
		(void *)&cmd_create,
		(void *)&cmd_sec_ctx,
		(void *)&cmd_sec_ctx_name,
		NULL,
	},
};
/* *** END OF CREATE SEC CTX *** */

/* *** SHOW/DEL SEC CTX %ctxneame%*** */
struct cmd_show_del_sec_ctx_one {
	struct cmdline_head	head;
	struct sec_ctx_entry	*ent;
};

static void cmd_show_del_sec_ctx_parsed(void *parsed_result,
				struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_show_del_sec_ctx_one *res = parsed_result;
	struct sec_ctx_entry *ent = res->ent;
	struct sec_ctx_rule *rule;
	int i;

	RTE_LCORE_FOREACH_SLAVE(i) {
		if (i == prf_primarycore_id)
			continue;
		break;
	}
	rule = &prf_lcore_conf[i].rules[ent->num];

	if (strcmp(res->head.action, "show") == 0) {
		cmdline_printf(cl,      "\t\n Sec context %s :\t\n"
					"\t Syn proxy mss %d\t\n", ent->name, rule->syn_proxy_mss);
		if (rule->flags & SYN_PROXY_WSCALE_PERM) {
			cmdline_printf(cl,
					"\t Syn proxy wscale %d\t\n", rule->syn_proxy_wscale);
		}
		if (rule->flags & SYN_PROXY_SACK_PERM) {
			cmdline_printf(cl,
					"\t Syn proxy window scale permit\t\n");
		}
		if (rule->flags & SRC_TRACK_CONN_FLAG) {
			cmdline_printf(cl,
					"\t Src track max states %d\t\n", rule->max_states);
		}
		if ((rule->flags & SRC_TRACK_RATE_FLAG) && (rule->period != 0)) {
			cmdline_printf(cl,
					"\t Src track rate %"PRIu64"\t\n"
					"\t Src track bucket size %"PRIu64"\t\n",
					prf_tsc_hz / rule->period, rule->bucket_size);
		}
		if (rule->flags & WHITE_LIST_CHECK) {
			cmdline_printf(cl,
					"\t White list on\t\n"
					"\t White list timer %"PRIu64"\t\n", rule->white_list->ban_timer / prf_tsc_hz);
		}
		if (rule->flags & BLACK_LIST_CHECK) {
			cmdline_printf(cl,
					"\t Black list on\t\n"
					"\t Black list ban time %"PRIu64"\t\n", rule->black_list->ban_timer / prf_tsc_hz);
			if (rule->flags & SRC_TRACK_BAN) {
				cmdline_printf(cl,
					"\t Src track overload ban\t\n");
			}
			if (rule->black_list->flags & IPSET_UPDATE_TIMER) {
				cmdline_printf(cl,
					"\t Black list update timer\t\n");
			}
		}
		return;
	} else if (strcmp(res->head.action, "del") == 0) {
		if (ent->acl_ref_counter != 0) {
			cmdline_printf(cl, "can not delet context, %d ACL use this context\t\n", ent->acl_ref_counter);
			return;
		}
		SLIST_REMOVE(&global_sec_ctx_list, res->ent, sec_ctx_entry, next);
		cmdline_printf(cl, "\tSec context %s deleted\t\n", ent->name);
		rte_free(ent);
	}
}

parse_token_sec_ctx_list_t cmd_sec_ctx_object =
	TOKEN_SEC_CTX_LIST_INITIALIZER(struct cmd_show_del_sec_ctx_one,
					ent, &global_sec_ctx_list);

cmdline_parse_inst_t cmd_show_del_sec_ctx = {
	.f = cmd_show_del_sec_ctx_parsed,
	.data = NULL,
	.help_str = "Show/delete security context",
	.tokens = {
		(void *)&cmd_show_del,
		(void *)&cmd_sec_ctx,
		(void *)&cmd_sec_ctx_object,
		NULL,
	},
};
/* *** END OF SHOW/DEL SEC CTX %ctxneame%*** */

/* *** SET DEFAULT ACL POLICY *** */
struct cmd_set_acl_policy {
	struct cmdline_head	head;
	cmdline_fixed_string_t	policy;
};

static void cmd_set_acl_policy_parsed(void *parsed_result,
				struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_set_acl_policy *res = parsed_result;

	if (strcmp(res->policy, "accept") == 0) {
		default_policy = ACCEPT;
		acl_callbacks[0] = acl_accept;
		cmdline_printf(cl, "\tDefault ACL policy ACCEPT\t\n");
		return;
	} else if (strcmp(res->policy, "drop") == 0) {
		default_policy = DROP;
		acl_callbacks[0] = acl_drop;
		cmdline_printf(cl, "\tDefault ACL policy DROP\t\n");
		return;
	}
}

cmdline_parse_token_string_t cmd_set_policy =
	TOKEN_STRING_INITIALIZER(struct cmd_set_acl_policy,
				policy, "accept#drop");

cmdline_parse_inst_t cmd_set_acl_policy = {
	.f = cmd_set_acl_policy_parsed,
	.data = NULL,
	.help_str = "Set default ACL policy",
	.tokens = {
		(void *)&cmd_set,
		(void *)&cmd_policy,
		(void *)&cmd_set_policy,
		NULL,
	},
};

/* *** END OF DEFAULT ACL POLICY *** */

/* *** SET EMBRIONIC THRESHOLD *** */
struct cmd_set_embrio_num {
	struct cmdline_head	head;
	uint32_t		num;
};

static void cmd_set_embrio_parsed(void *parsed_result,
				struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_set_embrio_num *res = parsed_result;

	embrionic_threshold = res->num;
	cmdline_printf(cl, "\tembrionic_threshold changed to %u\t\n", embrionic_threshold);
}

cmdline_parse_token_num_t cmd_embrio_num =
	TOKEN_NUM_INITIALIZER(struct cmd_set_embrio_num, num, UINT32);

cmdline_parse_inst_t cmd_set_embrio_num = {
	.f = cmd_set_embrio_parsed,
	.data = NULL,
	.help_str = "Set Embrionic connections threshold",
	.tokens = {
		(void *)&cmd_set,
		(void *)&cmd_embrio,
		(void *)&cmd_embrio_num,
		NULL,
	},
};

/* *** END OF SET EMBRIONIC THRESHOLD *** */

/* *** SET TIMERS *** */
struct cmd_set_timer {
	struct cmdline_head	head;
	cmdline_fixed_string_t	name;
	uint16_t		value;
};

static void cmd_set_timer_parsed(void *parsed_result,
				struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_set_timer *res = parsed_result;
	uint64_t timer_tsc = res->value * prf_tsc_hz;

	if (strcmp(res->name, "tcp_syn_sent") == 0) {
		prf_tcp_timer_table[PRF_TCP_STATE_SYN_SENT] = timer_tsc;
		cmdline_printf(cl, "\t Syn sent timer set to %"PRIu64"\t\n", prf_tcp_timer_table[PRF_TCP_STATE_SYN_SENT] / prf_tsc_hz);
		return;
	} else if (strcmp(res->name, "tcp_syn_rcvd") == 0) {
		prf_tcp_timer_table[PRF_TCP_STATE_SYN_RCV] = timer_tsc;
		cmdline_printf(cl, "\t Syn rcv timer set to %"PRIu64"\t\n", prf_tcp_timer_table[PRF_TCP_STATE_SYN_RCV] / prf_tsc_hz);
		return;
	} else if (strcmp(res->name, "tcp_established") == 0) {
		prf_tcp_timer_table[PRF_TCP_STATE_ESTABL] = timer_tsc;
		cmdline_printf(cl, "\t TCP Established timer set to %"PRIu64"\t\n", prf_tcp_timer_table[PRF_TCP_STATE_ESTABL] / prf_tsc_hz);
		return;
	} else if (strcmp(res->name, "tcp_fin_wait") == 0) {
		prf_tcp_timer_table[PRF_TCP_STATE_FIN_WAIT] = timer_tsc;
		cmdline_printf(cl, "\t Fin wait timer set to %"PRIu64"\t\n", prf_tcp_timer_table[PRF_TCP_STATE_FIN_WAIT] / prf_tsc_hz);
		return;
	} else if (strcmp(res->name, "tcp_close_wait") == 0) {
		prf_tcp_timer_table[PRF_TCP_STATE_CLOSE_WAIT] = timer_tsc;
		cmdline_printf(cl, "\t Close wait timer set to %"PRIu64"\t\n", prf_tcp_timer_table[PRF_TCP_STATE_CLOSE_WAIT] / prf_tsc_hz);
		return;
	} else if (strcmp(res->name, "tcp_last_ack") == 0) {
		prf_tcp_timer_table[PRF_TCP_STATE_LAST_ACK] = timer_tsc;
		cmdline_printf(cl, "\t Last ACK timer set to %"PRIu64"\t\n", prf_tcp_timer_table[PRF_TCP_STATE_LAST_ACK] / prf_tsc_hz);
		return;
	} else if (strcmp(res->name, "tcp_time_wait") == 0) {
		prf_tcp_timer_table[PRF_TCP_STATE_TIME_WAIT] = timer_tsc;
		cmdline_printf(cl, "\t Time wait timer set to %"PRIu64"\t\n", prf_tcp_timer_table[PRF_TCP_STATE_TIME_WAIT] / prf_tsc_hz);
		return;
	}
}

cmdline_parse_token_string_t cmd_timer_name =
	TOKEN_STRING_INITIALIZER(struct cmd_set_timer,
				name, "tcp_syn_sent#tcp_syn_rcvd#tcp_established#tcp_fin_wait#tcp_close_wait#tcp_last_ack#tcp_time_wait");
cmdline_parse_token_num_t cmd_timer_value =
	TOKEN_NUM_INITIALIZER(struct cmd_set_timer, value, UINT16);

cmdline_parse_inst_t cmd_set_timer = {
	.f = cmd_set_timer_parsed,
	.data = NULL,
	.help_str = "Set Timer for different TCP states",
	.tokens = {
		(void *)&cmd_set,
		(void *)&cmd_timer,
		(void *)&cmd_timer_name,
		(void *)&cmd_timer_value,
		NULL,
	},
};

/* *** END OF SET TIMERS *** */

/* *** SET SEC CTX PARAMS *** */
struct cmd_set_sec_ctx_params {
	struct cmdline_head	head;
	struct sec_ctx_entry	*ent;
	cmdline_fixed_string_t	param;
	uint16_t		value;
	cmdline_fixed_string_t	arg;
};

parse_token_sec_ctx_list_t cmd_set_sec_ctx_param_name =
	TOKEN_SEC_CTX_LIST_INITIALIZER(struct cmd_set_sec_ctx_params,
					ent, &global_sec_ctx_list);
cmdline_parse_token_num_t cmd_set_sec_ctx_value =
	TOKEN_NUM_INITIALIZER(struct cmd_set_sec_ctx_params, value, UINT16);

/* *** SET SEC CTX PARAMS *** */

/* *** SET SEC CTX PARAMS 1 *** */
static void cmd_set_sec_ctx_params_1_parsed(void *parsed_result,
				struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_set_sec_ctx_params *res = parsed_result;
	struct sec_ctx_rule *rule;
	uint64_t period;
	int i;


	if (strcmp(res->arg, "pkts_in_bucket") == 0) {
		RTE_LCORE_FOREACH_SLAVE(i) {
			rule = &prf_lcore_conf[i].rules[res->ent->num];
			rule->bucket_size = res->value;
		}
		cmdline_printf(cl, "\t Sec context %s bucket size %d\t\n", res->ent->name, res->value);
		return;
	} else if (strcmp(res->arg, "per_second") == 0) {
		period = prf_tsc_hz / res->value;
		RTE_LCORE_FOREACH_SLAVE(i) {
			rule = &prf_lcore_conf[i].rules[res->ent->num];
			rule->period = period;
		}
		cmdline_printf(cl, "\t Sec context %s rate %d new connections per second\t\n", res->ent->name, res->value);
		return;
	} else if (strcmp(res->arg, "per_minute") == 0) {
		period = (prf_tsc_hz * 60) / res->value;
		RTE_LCORE_FOREACH_SLAVE(i) {
			rule = &prf_lcore_conf[i].rules[res->ent->num];
			rule->period = period;
		}
		cmdline_printf(cl, "\t Sec context %s rate %d new connections per minute\t\n", res->ent->name, res->value);
		return;
	} else if (strcmp(res->arg, "per_hour") == 0) {
		period = (prf_tsc_hz * 3600) / res->value;
		RTE_LCORE_FOREACH_SLAVE(i) {
			rule = &prf_lcore_conf[i].rules[res->ent->num];
			rule->period = period;
		}
		cmdline_printf(cl, "\t Sec context %s rate %d new connections per hour\t\n", res->ent->name, res->value);
		return;
	}
}

cmdline_parse_token_string_t cmd_set_sec_ctx_param_rate =
	TOKEN_STRING_INITIALIZER(struct cmd_set_sec_ctx_params,
				param, "rate");

cmdline_parse_token_string_t cmd_param_rate_arg =
	TOKEN_STRING_INITIALIZER(struct cmd_set_sec_ctx_params,
				arg, "per_second#per_minute#per_hour#pkts_in_bucket");


cmdline_parse_inst_t cmd_set_sec_ctx_params_1 = {
	.f = cmd_set_sec_ctx_params_1_parsed,
	.data = NULL,
	.help_str = "Set security context params",
	.tokens = {
		(void *)&cmd_set,
		(void *)&cmd_sec_ctx,
		(void *)&cmd_set_sec_ctx_param_name,
		(void *)&cmd_set_sec_ctx_param_rate,
		(void *)&cmd_set_sec_ctx_value,
		(void *)&cmd_param_rate_arg,
		NULL,
	},
};
/* *** END OF SET SEC CTX PARAMS 1*** */

/* *** SET SEC CTX PARAMS 2 *** */
static void cmd_set_sec_ctx_params_2_parsed(void *parsed_result,
				struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_set_sec_ctx_params *res = parsed_result;
	struct sec_ctx_rule *rule;
	uint16_t mss;
	int i;

	if (strcmp(res->param, "max_connections") == 0) {
		RTE_LCORE_FOREACH_SLAVE(i) {
			rule = &prf_lcore_conf[i].rules[res->ent->num];
			rule->max_states = res->value;
		}
		cmdline_printf(cl, "\t Sec context %s %d maximum connections per source ip\t\n", res->ent->name, res->value);
		return;
	} else if (strcmp(res->param, "syn_proxy_mss") == 0) {
		for (i = PRF_ARRAY_SIZE(msstab) - 1; i ; i--) {
			if (res->value >= msstab[i])
				break;
		}
		mss = msstab[i];
		RTE_LCORE_FOREACH_SLAVE(i) {
			rule = &prf_lcore_conf[i].rules[res->ent->num];
			rule->syn_proxy_mss = mss;
		}
		cmdline_printf(cl, "\t MSS for protected server in sec context %s set to %d\t\n", res->ent->name, mss);
		return;
	} else if (strcmp(res->param, "syn_proxy_wscale") == 0) {
		if (res->value > 15) {
			cmdline_printf(cl, "\t Invalid value for wscale factor, must be within 0 - 15 (15 for disable wscaling) range\t\n");
			return;
		}
		if (res->value == 15) {
			RTE_LCORE_FOREACH_SLAVE(i) {
				rule = &prf_lcore_conf[i].rules[res->ent->num];
				rule->flags &= ~SYN_PROXY_WSCALE_PERM;
				rule->syn_proxy_wscale = 0xf;
			}
			cmdline_printf(cl, "\t Window scaling turned off\t\n");
			return;
		}
		RTE_LCORE_FOREACH_SLAVE(i) {
			rule = &prf_lcore_conf[i].rules[res->ent->num];
			rule->flags |= SYN_PROXY_WSCALE_PERM;
			rule->syn_proxy_wscale = res->value;
		}
		cmdline_printf(cl, "\t Window scaling factor for sec context %s set in %d\t\n", res->ent->name, res->value);
		return;
	}
}

cmdline_parse_token_string_t cmd_set_sec_ctx_param_1 =
	TOKEN_STRING_INITIALIZER(struct cmd_set_sec_ctx_params,
			param, "max_connections#syn_proxy_mss#syn_proxy_wscale");

cmdline_parse_inst_t cmd_set_sec_ctx_params_2 = {
	.f = cmd_set_sec_ctx_params_2_parsed,
	.data = NULL,
	.help_str = "Set security context params",
	.tokens = {
		(void *)&cmd_set,
		(void *)&cmd_sec_ctx,
		(void *)&cmd_set_sec_ctx_param_name,
		(void *)&cmd_set_sec_ctx_param_1,
		(void *)&cmd_set_sec_ctx_value,
		NULL,
	},
};

/* *** END OF SET SEC CTX PARAMS 2*** */

/* *** SET SEC CTX PARAMS 3 *** */
static void cmd_set_sec_ctx_params_3_parsed(void *parsed_result,
				struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_set_sec_ctx_params *res = parsed_result;
	struct sec_ctx_rule *rule;
	int i;

	if (strcmp(res->param, "white_list") == 0) {
		if (strcmp(res->arg, "on") == 0) {
			RTE_LCORE_FOREACH_SLAVE(i) {
				if (i == prf_primarycore_id)
					continue;
				rule = &prf_lcore_conf[i].rules[res->ent->num];
				rule->flags |= WHITE_LIST_CHECK;
				rule->white_list->ban_timer = IPSET_WHITE_LIST_DEF_TIMER * prf_tsc_hz;
			}
			cmdline_printf(cl, "\tSec context %s white list check on\t\n", res->ent->name);
			return;
		} else if (strcmp(res->arg, "off") == 0) {
			RTE_LCORE_FOREACH_SLAVE(i) {
				rule = &prf_lcore_conf[i].rules[res->ent->num];
				rule->flags &= ~WHITE_LIST_CHECK;
			}
			cmdline_printf(cl, "\tSec context %s white list check off\t\n", res->ent->name);
			return;
		}
		return;
	} else if (strcmp(res->param, "black_list") == 0) {
		if (strcmp(res->arg, "on") == 0) {
			RTE_LCORE_FOREACH_SLAVE(i) {
				if ((i == prf_mastercore_id) || (i == prf_primarycore_id))
					continue;
				rule = &prf_lcore_conf[i].rules[res->ent->num];
				rule->flags |= BLACK_LIST_CHECK;
				rule->black_list->ban_timer = IPSET_BLACK_LIST_DEF_TIMER * prf_tsc_hz;
			}
			cmdline_printf(cl, "\tSec context %s black list check on\t\n", res->ent->name);
			return;
		} else if (strcmp(res->arg, "off") == 0) {
			RTE_LCORE_FOREACH_SLAVE(i) {
				rule = &prf_lcore_conf[i].rules[res->ent->num];
				rule->flags &= ~BLACK_LIST_CHECK;
			}
			cmdline_printf(cl, "\tSec context %s black list check off\t\n", res->ent->name);
			return;
		}
		return;
	} else if (strcmp(res->param, "src_track_overflow_ban") == 0) {
		if (strcmp(res->arg, "on") == 0) {
			RTE_LCORE_FOREACH_SLAVE(i) {
				rule = &prf_lcore_conf[i].rules[res->ent->num];
				rule->flags |= SRC_TRACK_BAN;
			}
			cmdline_printf(cl, "\tSec context %s src track overflow ban on\t\n", res->ent->name);
			return;
		} else if (strcmp(res->arg, "off") == 0) {
			RTE_LCORE_FOREACH_SLAVE(i) {
				rule = &prf_lcore_conf[i].rules[res->ent->num];
				rule->flags &= ~SRC_TRACK_BAN;
			}
			cmdline_printf(cl, "\tSec context %s src track overflow ban off\t\n", res->ent->name);
			return;
		}
		return;
	} else if (strcmp(res->param, "syn_proxy_sack") == 0) {
		if (strcmp(res->arg, "on") == 0) {
			RTE_LCORE_FOREACH_SLAVE(i) {
				rule = &prf_lcore_conf[i].rules[res->ent->num];
				rule->flags |= SYN_PROXY_SACK_PERM;
			}
			cmdline_printf(cl, "\tSec context %s selective ACK permited for syn proxy\t\n", res->ent->name);
			return;
		} else if (strcmp(res->arg, "off") == 0) {
			RTE_LCORE_FOREACH_SLAVE(i) {
				rule = &prf_lcore_conf[i].rules[res->ent->num];
				rule->flags &= ~SYN_PROXY_SACK_PERM;
			}
			cmdline_printf(cl, "\tSec context %s selective ACK ignored for syn proxy\t\n", res->ent->name);
			return;
		}
		return;
	} else if (strcmp(res->param, "src_track_rate_check") == 0) {
		if (strcmp(res->arg, "on") == 0) {
			RTE_LCORE_FOREACH_SLAVE(i) {
				rule = &prf_lcore_conf[i].rules[res->ent->num];
				if (rule->period == 0) {
					cmdline_printf(cl, "\t Current Src track rate = 0, aborted\t\n");
					return;
				}
			}
			RTE_LCORE_FOREACH_SLAVE(i) {
				rule = &prf_lcore_conf[i].rules[res->ent->num];
				rule->flags |= SRC_TRACK_RATE_FLAG;
			}
			cmdline_printf(cl, "\tSec context %s rate for new tcp sessions check on\t\n", res->ent->name);
			return;
		} else if (strcmp(res->arg, "off") == 0) {
			RTE_LCORE_FOREACH_SLAVE(i) {
				rule = &prf_lcore_conf[i].rules[res->ent->num];
				rule->flags &= ~SRC_TRACK_RATE_FLAG;
			}
			cmdline_printf(cl, "\tSec context %s rate for new tcp sessions check off\t\n", res->ent->name);
			return;
		}
		return;
	} else if (strcmp(res->param, "src_track_maxconn_check") == 0) {
		if (strcmp(res->arg, "on") == 0) {
			RTE_LCORE_FOREACH_SLAVE(i) {
				rule = &prf_lcore_conf[i].rules[res->ent->num];
				rule->flags |= SRC_TRACK_CONN_FLAG;
			}
			cmdline_printf(cl, "\tSec context %s max concurent TCP sessions check on\t\n", res->ent->name);
			return;
		} else if (strcmp(res->arg, "off") == 0) {
			RTE_LCORE_FOREACH_SLAVE(i) {
				rule = &prf_lcore_conf[i].rules[res->ent->num];
				rule->flags &= ~SRC_TRACK_CONN_FLAG;
			}
			cmdline_printf(cl, "\tSec context %s max concurent TCP sessions check off\t\n", res->ent->name);
			return;
		}
		return;
	}
}

cmdline_parse_token_string_t cmd_set_sec_ctx_param_2 =
	TOKEN_STRING_INITIALIZER(struct cmd_set_sec_ctx_params,
			param, "white_list#black_list#src_track_overflow_ban#syn_proxy_sack#src_track_rate_check#src_track_maxconn_check");

cmdline_parse_token_string_t cmd_param_arg =
	TOKEN_STRING_INITIALIZER(struct cmd_set_sec_ctx_params,
				arg, "on#off");

cmdline_parse_inst_t cmd_set_sec_ctx_params_3 = {
	.f = cmd_set_sec_ctx_params_3_parsed,
	.data = NULL,
	.help_str = "Set security context params",
	.tokens = {
		(void *)&cmd_set,
		(void *)&cmd_sec_ctx,
		(void *)&cmd_set_sec_ctx_param_name,
		(void *)&cmd_set_sec_ctx_param_2,
		(void *)&cmd_param_arg,
		NULL,
	},
};

/* *** END OF SET SEC CTX PARAMS 3*** */

/* *** SET ACL *** */
struct cmd_set_acl_params {
	struct cmdline_head	head;
	uint16_t		idx;
	cmdline_fixed_string_t	src_ip;
	cmdline_fixed_string_t	dst_ip;
	cmdline_fixed_string_t	sport_range;
	cmdline_fixed_string_t	dport_range;
	cmdline_fixed_string_t	action;
	struct sec_ctx_entry   *ent;
	cmdline_ipaddr_t	sprefix;
	cmdline_ipaddr_t	dprefix;
	uint16_t                sport_low;
	uint16_t                sport_hi;
	uint16_t                dport_low;
	uint16_t                dport_hi;
};

static void cmd_set_acl_parsed(void *parsed_result,
				struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_set_acl_params *res = parsed_result;
	struct acl_entry *ent, *prev, *new_ent = NULL;

	if ((res->sport_low > res->sport_hi) || (res->dport_low > res->dport_hi)) {
		cmdline_printf(cl, "Bad arguments\t\n");
		return;
	}
	new_ent = rte_zmalloc(NULL, sizeof(*new_ent), CACHE_LINE_SIZE);
	if (new_ent == NULL) {
		cmdline_printf(cl, "\tNot enough memory\t\n");
		return;
	}
	if ((new_ent->cnt_idx = get_acl_cnt_idx()) < 0) {
		cmdline_printf(cl, "\tNo counter space\t\n");
		rte_free(new_ent);
		return;
	}
	if LIST_EMPTY(&global_acl_list) {
		LIST_INSERT_HEAD(&global_acl_list, new_ent, next);
	} else {
		LIST_FOREACH(ent, &global_acl_list, next) {
			prev = ent;
			if (ent->idx == res->idx) {
				cmdline_printf(cl, "\tACL index %d is occupied\t\n", res->idx);
				free_acl_cnt_idx(new_ent->cnt_idx);
				rte_free(new_ent);
				return;
			}
			if (ent->idx > res->idx) {
				LIST_INSERT_BEFORE(ent, new_ent, next);
				goto init_new_ent;
			}
		}
		LIST_INSERT_AFTER(prev, new_ent, next);
	}

init_new_ent:
	new_ent->idx		= res->idx;
	new_ent->src_ip		= (res->sprefix.addr.ipv4.s_addr) & ~(rte_cpu_to_be_32((uint32_t)(((1ULL << (32 - res->sprefix.prefixlen)) - 1))));
	new_ent->dst_ip		= (res->dprefix.addr.ipv4.s_addr) & ~(rte_cpu_to_be_32((uint32_t)(((1ULL << (32 - res->dprefix.prefixlen)) - 1))));
	new_ent->sport_low	= res->sport_low;
	new_ent->sport_hi	= res->sport_hi;
	new_ent->dport_low	= res->dport_low;
	new_ent->dport_hi	= res->dport_hi;
	new_ent->sprefixlen	= res->sprefix.prefixlen;
	new_ent->dprefixlen	= res->dprefix.prefixlen;
	if (strcmp(res->action, "drop") == 0) {
		new_ent->action		= DROP;
	} else if (strcmp(res->action, "accept") == 0) {
		new_ent->action		= ACCEPT;
	} else if (strcmp(res->action, "sec_ctx") == 0) {
		new_ent->action		= SEC_CTX;
		new_ent->sec_ctx	= res->ent;
		new_ent->sec_ctx->acl_ref_counter++;
	}
	cmdline_build_acl();
}

cmdline_parse_token_num_t cmd_set_acl_idx =
	TOKEN_NUM_INITIALIZER(struct cmd_set_acl_params, idx, UINT16);

cmdline_parse_token_string_t cmd_set_acl_src_ip =
	TOKEN_STRING_INITIALIZER(struct cmd_set_acl_params,
				src_ip, "src");

cmdline_parse_token_string_t cmd_set_acl_dst_ip =
	TOKEN_STRING_INITIALIZER(struct cmd_set_acl_params,
				dst_ip, "dst");

cmdline_parse_token_string_t cmd_set_acl_sport_range =
	TOKEN_STRING_INITIALIZER(struct cmd_set_acl_params,
				sport_range, "sport_range");

cmdline_parse_token_string_t cmd_set_acl_dport_range =
	TOKEN_STRING_INITIALIZER(struct cmd_set_acl_params,
				dport_range, "dport_range");

cmdline_parse_token_string_t cmd_set_acl_action =
	TOKEN_STRING_INITIALIZER(struct cmd_set_acl_params,
				action, "accept#drop");

cmdline_parse_token_ipaddr_t cmd_set_acl_sprefix =
	TOKEN_IPV4NET_INITIALIZER(struct cmd_set_acl_params, sprefix);

cmdline_parse_token_ipaddr_t cmd_set_acl_dprefix =
	TOKEN_IPV4NET_INITIALIZER(struct cmd_set_acl_params, dprefix);

cmdline_parse_token_num_t cmd_set_acl_sport_low =
	TOKEN_NUM_INITIALIZER(struct cmd_set_acl_params, sport_low, UINT16);

cmdline_parse_token_num_t cmd_set_acl_sport_hi =
	TOKEN_NUM_INITIALIZER(struct cmd_set_acl_params, sport_hi, UINT16);

cmdline_parse_token_num_t cmd_set_acl_dport_low =
	TOKEN_NUM_INITIALIZER(struct cmd_set_acl_params, dport_low, UINT16);

cmdline_parse_token_num_t cmd_set_acl_dport_hi =
	TOKEN_NUM_INITIALIZER(struct cmd_set_acl_params, dport_hi, UINT16);

cmdline_parse_inst_t cmd_set_acl = {
	.f = cmd_set_acl_parsed,
	.data = NULL,
	.help_str = "Set ACL entry",
	.tokens = {
		(void *)&cmd_set,
		(void *)&cmd_acl,
		(void *)&cmd_set_acl_idx,
		(void *)&cmd_set_acl_src_ip,
		(void *)&cmd_set_acl_sprefix,
		(void *)&cmd_set_acl_dst_ip,
		(void *)&cmd_set_acl_dprefix,
		(void *)&cmd_set_acl_sport_range,
		(void *)&cmd_set_acl_sport_low,
		(void *)&cmd_set_acl_sport_hi,
		(void *)&cmd_set_acl_dport_range,
		(void *)&cmd_set_acl_dport_low,
		(void *)&cmd_set_acl_dport_hi,
		(void *)&cmd_set_acl_action,
		NULL,
	},
};

cmdline_parse_token_string_t cmd_set_acl_action_sec_ctx =
	TOKEN_STRING_INITIALIZER(struct cmd_set_acl_params,
				action, "sec_ctx");
parse_token_sec_ctx_list_t cmd_set_acl_sec_ctx_name =
	TOKEN_SEC_CTX_LIST_INITIALIZER(struct cmd_set_acl_params,
					ent, &global_sec_ctx_list);

cmdline_parse_inst_t cmd_set_acl_sec_ctx = {
	.f = cmd_set_acl_parsed,
	.data = NULL,
	.help_str = "Set ACL entry",
	.tokens = {
		(void *)&cmd_set,
		(void *)&cmd_acl,
		(void *)&cmd_set_acl_idx,
		(void *)&cmd_set_acl_src_ip,
		(void *)&cmd_set_acl_sprefix,
		(void *)&cmd_set_acl_dst_ip,
		(void *)&cmd_set_acl_dprefix,
		(void *)&cmd_set_acl_sport_range,
		(void *)&cmd_set_acl_sport_low,
		(void *)&cmd_set_acl_sport_hi,
		(void *)&cmd_set_acl_dport_range,
		(void *)&cmd_set_acl_dport_low,
		(void *)&cmd_set_acl_dport_hi,
		(void *)&cmd_set_acl_action_sec_ctx,
		(void *)&cmd_set_acl_sec_ctx_name,
		NULL,
	},
};

/* *** END OF SET ACL *** */

/* *** DEL ACL *** */
struct cmd_del_acl_params {
	struct cmdline_head	head;
	uint16_t		idx;
};

static void cmd_del_acl_parsed(void *parsed_result,
				struct cmdline *cl,
				__attribute__((unused)) void *data)
{
	struct cmd_del_acl_params *res = parsed_result;
	struct acl_entry *ent;
	int i;

	if LIST_EMPTY(&global_acl_list) {
		cmdline_printf(cl, "\tACL index %d not exist\t\n", res->idx);
		return;
	}
	LIST_FOREACH(ent, &global_acl_list, next) {
		if (ent->idx == res->idx) {
			LIST_REMOVE(ent, next);
			RTE_LCORE_FOREACH_SLAVE(i) {
				if (i == prf_primarycore_id)
					continue;
				prf_lcore_conf[i].stats.acl_stat[ent->cnt_idx] = 0;
			}
			free_acl_cnt_idx(ent->cnt_idx);
			if (ent->action == SEC_CTX)
				ent->sec_ctx->acl_ref_counter--;
			rte_free(ent);
			cmdline_build_acl();
			cmdline_printf(cl, "\tACL index %d deleted\t\n", res->idx);
			return;
		}
	}
	cmdline_printf(cl, "\tACL index %d not found\t\n", res->idx);
}

cmdline_parse_token_num_t cmd_del_acl_idx =
	TOKEN_NUM_INITIALIZER(struct cmd_del_acl_params, idx, UINT16);

cmdline_parse_inst_t cmd_del_acl = {
	.f = cmd_del_acl_parsed,
	.data = NULL,
	.help_str = "Delete ACL entry",
	.tokens = {
		(void *)&cmd_del,
		(void *)&cmd_acl,
		(void *)&cmd_del_acl_idx,
		NULL,
	},
};

/* *** END OF DEL ACL *** */

/* *** MAIN CONTEXT *** */

cmdline_parse_ctx_t main_ctx[] = {
	(cmdline_parse_inst_t *)&cmd_show_all,
	(cmdline_parse_inst_t *)&cmd_create_sec_ctx,
	(cmdline_parse_inst_t *)&cmd_show_del_sec_ctx,
	(cmdline_parse_inst_t *)&cmd_set_acl_policy,
	(cmdline_parse_inst_t *)&cmd_set_embrio_num,
	(cmdline_parse_inst_t *)&cmd_set_timer,
	(cmdline_parse_inst_t *)&cmd_set_sec_ctx_params_1,
	(cmdline_parse_inst_t *)&cmd_set_sec_ctx_params_2,
	(cmdline_parse_inst_t *)&cmd_set_sec_ctx_params_3,
	(cmdline_parse_inst_t *)&cmd_set_acl,
	(cmdline_parse_inst_t *)&cmd_set_acl_sec_ctx,
	(cmdline_parse_inst_t *)&cmd_del_acl,
	NULL,
};

