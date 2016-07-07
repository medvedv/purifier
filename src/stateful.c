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

#include <rte_malloc.h>
#include <rte_jhash.h>
#include <rte_random.h>
#include <rte_atomic.h>
#include <rte_prefetch.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_mbuf.h>

#include "stateful.h"
#include "acl.h"
#include "sec_ctx.h"
#include "sec_ctx_api.h"
#include "main.h"
#include "prf_csum.h"

uint32_t prf_hash_initval = 0;
uint64_t prf_tcp_timer_table[PRF_TCP_STATE_NB_STATES] __rte_cache_aligned;

void
process_tcp_seg(struct prf_lcore_conf *conf, struct rte_mbuf *m,
	struct tcp_conn *tcp_conn, uint64_t *timer, uint64_t time, int dir)
{
	uint8_t tcpflags;
	uint16_t win;
	int i, tcp_event, newstate, ret;
	uint32_t seq, ack, end, tcplen;
	struct rte_mbuf *oldmbuf = NULL;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ip_hdr;
	struct tcp_hdr *tcp_hdr;
	struct tcpopts tcpopts;

	ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, struct ether_hdr *) + 1);
	tcp_hdr = (struct tcp_hdr *)((unsigned char *) ip_hdr +
				(ip_hdr->version_ihl & 0xf)*4);
	tcplen = rte_be_to_cpu_16(ip_hdr->total_length) -
		((ip_hdr->version_ihl & 0xf) << 2) - (tcp_hdr->data_off >> 2);
	tcpflags = (tcp_hdr->tcp_flags & ~(PRF_TCPHDR_ECE|PRF_TCPHDR_CWR|PRF_TCPHDR_PSH));
	seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);
	ack = rte_be_to_cpu_32(tcp_hdr->recv_ack);
	end = tcp_seq_plus_len(seq, tcplen, tcpflags);
	win = rte_be_to_cpu_16(tcp_hdr->rx_win);

	if (!(tcpflags & PRF_TCPHDR_ACK))
		ack = tcp_conn->dir[!dir].td_end;

	if (unlikely((tcpflags == PRF_TCPHDR_SYN) &&
		(tcp_conn->state == PRF_TCP_STATE_TIME_WAIT))) {
		ret = get_opts((uint8_t *)(tcp_hdr + 1), (tcp_hdr->data_off >> 2) -
					sizeof(struct tcp_hdr), &tcpopts);
		if (ret) {
			++conf->stats.malformed;
			rte_pktmbuf_free(m);
			return;
		}
		++conf->stats.tw_reuse;
		if (tcpopts.wscale != 0xf)
			tcp_conn->dir[dir].td_flags |= PRF_TCP_FLAG_WSCALE;
		tcp_conn->dir[dir].packets = 0;
		tcp_conn->dir[dir].bytes = 0;
		tcp_conn->dir[dir].td_maxend =
		tcp_conn->dir[dir].td_end = end;
		tcp_conn->dir[dir].td_maxwin = RTE_MAX(win, 1);
		tcp_conn->dir[dir].td_wscale = tcpopts.wscale;
		tcp_conn->dir[dir].packets++;
		tcp_conn->dir[dir].bytes += m->pkt.pkt_len;
		*timer = time + prf_tcp_timer_table[PRF_TCP_STATE_SYN_SENT];
		++conf->stats.embrionic_counter;
		tcp_conn->state = PRF_TCP_STATE_SYN_SENT;
		memset(&tcp_conn->dir[!dir], 0, sizeof(struct tcp_conn_state));
		prf_send_packet(m, conf, prf_dst_ports[m->pkt.in_port]);
		return;
	}

	if (unlikely(tcpflags & PRF_TCPHDR_RST)) {
		++conf->stats.rst_set;
		if ((seq == 0) && (tcp_conn->state == PRF_TCP_STATE_SYN_SENT) &&
					(dir == PRF_DIR_REV)) {
			seq = tcp_conn->dir[dir].td_end;
		}

		if (((tcpflags & (PRF_TCPHDR_RST|PRF_TCPHDR_ACK)) ==
				(PRF_TCPHDR_RST|PRF_TCPHDR_ACK)) && (ack == 0))
			ack = tcp_conn->dir[!dir].td_end;
		if ((tcp_conn->flags & TCP_STATE_SYNPROXY) &&
				(dir == PRF_DIR_ORIG)) {
			tcp_hdr->recv_ack =
				rte_cpu_to_be_32(rte_be_to_cpu_32(tcp_hdr->recv_ack) -
				tcp_conn->seq_diff);
			ack -= tcp_conn->seq_diff;
			ip_hdr->hdr_checksum  = 0;
			tcp_hdr->cksum          = prf_get_ipv4_psd_sum(ip_hdr);
			m->ol_flags = PKT_TX_IP_CKSUM|PKT_TX_TCP_CKSUM;
		}

		if (!(PRF_SEQ_LEQ(end, tcp_conn->dir[dir].td_maxend) &&
			PRF_SEQ_GEQ(seq, tcp_conn->dir[dir].td_end -
			RTE_MAX((tcp_conn->dir[!dir].td_maxwin <<
			tcp_conn->dir[!dir].td_wscale), 1)) &&
			PRF_SEQ_LEQ(ack, tcp_conn->dir[!dir].td_end) &&
			PRF_SEQ_GEQ(ack, tcp_conn->dir[!dir].td_end -
			(tcp_conn->dir[dir].td_maxwin << tcp_conn->dir[dir].td_wscale)))) {
				++conf->stats.bad_seq_ack;
				rte_pktmbuf_free(m);
				return;
		}
		if ((tcp_conn->flags & TCP_STATE_SYNPROXY) &&
				(dir == PRF_DIR_REV)) {
			if ((rte_be_to_cpu_32(tcp_hdr->sent_seq) == 0) &&
				(tcp_conn->state == PRF_TCP_STATE_SYN_SENT))
				tcp_hdr->sent_seq =
					rte_cpu_to_be_32(rte_be_to_cpu_32(tcp_hdr->sent_seq) + 1);
			tcp_hdr->sent_seq =
					rte_cpu_to_be_32(rte_be_to_cpu_32(tcp_hdr->sent_seq) +
					tcp_conn->seq_diff);
			ip_hdr->hdr_checksum  = 0;
			tcp_hdr->cksum          = prf_get_ipv4_psd_sum(ip_hdr);
			m->ol_flags = PKT_TX_IP_CKSUM|PKT_TX_TCP_CKSUM;
		}
		if (tcp_conn->state < PRF_TCP_STATE_ESTABL)
			--conf->stats.embrionic_counter;
		tcp_conn->state = PRF_TCP_STATE_TIME_WAIT;
		*timer = time + prf_tcp_timer_table[PRF_TCP_STATE_TIME_WAIT];
		prf_send_packet(m, conf, prf_dst_ports[m->pkt.in_port]);
		return;
	}

	tcp_event = tcp_get_event(tcpflags);
	newstate = prf_tcp_trans_table[dir][tcp_event][tcp_conn->state];
	if (newstate == PRF_TCP_STATE_NONE) {
		++conf->stats.bad_flags;
		rte_pktmbuf_free(m);
		return;
	}

	if (tcp_conn->dir[dir].td_maxwin == 0) {
		if (((tcpflags & (PRF_TCPHDR_SYN|PRF_TCPHDR_ACK)) != (PRF_TCPHDR_SYN|PRF_TCPHDR_ACK)) ||
				(ack != tcp_conn->dir[!dir].td_end)) {
			++conf->stats.bad_seq_ack;
			rte_pktmbuf_free(m);
			return;
		}
		ret = get_opts((uint8_t *)(tcp_hdr + 1), (tcp_hdr->data_off >> 2) -
				sizeof(struct tcp_hdr), &tcpopts);
		if (ret) {
			++conf->stats.malformed;
			rte_pktmbuf_free(m);
			return;
		}
		if (tcpopts.wscale != 0xf)
			tcp_conn->dir[dir].td_flags |= PRF_TCP_FLAG_WSCALE;
		tcp_conn->dir[dir].td_wscale = tcpopts.wscale;
		if (!(tcp_conn->dir[dir].td_flags & PRF_TCP_FLAG_WSCALE) &&
				(tcp_conn->dir[!dir].td_flags & PRF_TCP_FLAG_WSCALE)) {
			tcp_conn->dir[dir].td_flags &= ~PRF_TCP_FLAG_WSCALE;
			tcp_conn->dir[!dir].td_flags &= ~PRF_TCP_FLAG_WSCALE;
			tcp_conn->dir[dir].td_wscale = 0;
			tcp_conn->dir[!dir].td_wscale = 0;
		}
		tcp_conn->dir[dir].td_maxend =
		tcp_conn->dir[dir].td_end = end;
		tcp_conn->dir[dir].td_maxwin = RTE_MAX(win, 1);
		tcp_conn->dir[dir].packets++;
		tcp_conn->dir[dir].bytes += m->pkt.pkt_len;
		if (tcp_conn->flags & TCP_STATE_SYNPROXY) {
			tcp_conn->seq_diff -=
				rte_be_to_cpu_32(tcp_hdr->sent_seq);
			tcp_conn->flags &= ~TCP_STATE_SYNPROXY_INIT;
			tcp_conn->dir[dir].td_maxwin = RTE_MAX(win, 1);
			if (PRF_SEQ_GT(ack + (win << tcp_conn->dir[dir].td_wscale),
					tcp_conn->dir[!dir].td_maxend))
				tcp_conn->dir[!dir].td_maxend =
					ack + (win << tcp_conn->dir[dir].td_wscale);
			*timer = time + prf_tcp_timer_table[newstate];
			tcp_conn->state = newstate;

			rte_pktmbuf_free(m);
			oldmbuf = tcp_conn->m;
			while (oldmbuf != NULL) {
				eth_hdr = rte_pktmbuf_mtod(oldmbuf, struct ether_hdr *);
				ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
				process_tcp_seg(conf, oldmbuf, tcp_conn, timer, time, !dir);
				oldmbuf = (struct rte_mbuf *)oldmbuf->metadata64[0];
			}
			return;
		}
	}

	if (unlikely((((tcp_conn->state == PRF_TCP_STATE_SYN_SENT) && (dir == 0)
		&& ((tcpflags & PRF_TCPHDR_SYN) == PRF_TCPHDR_SYN)) ||
		((tcp_conn->state == PRF_TCP_STATE_SYN_RCV) && (dir == 1)
		&&  ((tcpflags & (PRF_TCPHDR_SYN|PRF_TCPHDR_ACK)) == (PRF_TCPHDR_SYN|PRF_TCPHDR_ACK))))
		&& PRF_SEQ_GT(seq, tcp_conn->dir[dir].td_end))) {
			ret = get_opts((uint8_t *)(tcp_hdr + 1), (tcp_hdr->data_off >> 2) -
					sizeof(struct tcp_hdr), &tcpopts);
			if (ret) {
				++conf->stats.malformed;
				rte_pktmbuf_free(m);
				return;
			}
			if (tcpopts.wscale != 0xf)
				tcp_conn->dir[dir].td_flags |= PRF_TCP_FLAG_WSCALE;
			tcp_conn->dir[dir].td_wscale = tcpopts.wscale;
			tcp_conn->dir[dir].td_maxend =
			tcp_conn->dir[dir].td_end = end;
			tcp_conn->dir[dir].td_maxwin = RTE_MAX(win, 1);
	}

	if ((tcp_conn->flags & TCP_STATE_SYNPROXY) && (dir == 0)) {
		if (unlikely(tcp_conn->flags & TCP_STATE_SYNPROXY_INIT)) {
			m->metadata64[0] = 0;
			oldmbuf = tcp_conn->m;
			i = 0;
			while (oldmbuf->metadata64[0]) {
				oldmbuf = (struct rte_mbuf *)oldmbuf->metadata64[0];
				++i;
			}
			if (i >= MAX_SYNPROXY_MBUF_CHAIN) {
				rte_pktmbuf_free(m);
				return;
			}
			oldmbuf->metadata64[0] = (uint64_t)m;
			return;
		}
		tcp_hdr->recv_ack =
			rte_cpu_to_be_32(rte_be_to_cpu_32(tcp_hdr->recv_ack) -
			tcp_conn->seq_diff);
		ack -= tcp_conn->seq_diff;
		ip_hdr->hdr_checksum  = 0;
		tcp_hdr->cksum          = prf_get_ipv4_psd_sum(ip_hdr);
		m->ol_flags = PKT_TX_IP_CKSUM|PKT_TX_TCP_CKSUM;
	}

	if (PRF_SEQ_LEQ(end, tcp_conn->dir[dir].td_maxend) &&
			PRF_SEQ_GEQ(seq, tcp_conn->dir[dir].td_end -
			RTE_MAX((tcp_conn->dir[!dir].td_maxwin <<
			tcp_conn->dir[!dir].td_wscale), 1)) &&
			PRF_SEQ_LEQ(ack, tcp_conn->dir[!dir].td_end) &&
			PRF_SEQ_GEQ(ack, tcp_conn->dir[!dir].td_end -
			(tcp_conn->dir[dir].td_maxwin <<
			tcp_conn->dir[dir].td_wscale))) {
		if (tcp_conn->dir[dir].td_maxwin < win)
			tcp_conn->dir[dir].td_maxwin = win;
		if (PRF_SEQ_GT(end, tcp_conn->dir[dir].td_end))
			tcp_conn->dir[dir].td_end = end;
		if (PRF_SEQ_GT(ack + (win << tcp_conn->dir[dir].td_wscale),
				tcp_conn->dir[!dir].td_maxend))
			tcp_conn->dir[!dir].td_maxend =
				ack + (win << tcp_conn->dir[dir].td_wscale);
		*timer = time + prf_tcp_timer_table[newstate];
		tcp_conn->dir[dir].packets++;
		tcp_conn->dir[dir].bytes += m->pkt.pkt_len;
		if ((newstate > PRF_TCP_STATE_SYN_RCV) &&
				(tcp_conn->state < PRF_TCP_STATE_ESTABL))
			--conf->stats.embrionic_counter;
		tcp_conn->state = newstate;

		if ((tcp_conn->flags & TCP_STATE_SYNPROXY) && (dir == 1)) {
			tcp_hdr->sent_seq =
				rte_cpu_to_be_32(rte_be_to_cpu_32(tcp_hdr->sent_seq) +
							tcp_conn->seq_diff);
			ip_hdr->hdr_checksum  = 0;
			tcp_hdr->cksum          = prf_get_ipv4_psd_sum(ip_hdr);
			m->ol_flags = PKT_TX_IP_CKSUM|PKT_TX_TCP_CKSUM;
		}
		prf_send_packet(m, conf, prf_dst_ports[m->pkt.in_port]);
		return;
	}
	++conf->stats.bad_seq_ack;
	rte_pktmbuf_free(m);
}

struct ipv4_tcp_hash *
ipv4_tcp_hash_init(unsigned lcore_id)
{
	struct ipv4_tcp_hash *hash = NULL;
	char buf[PRF_TCP_HASH_NAMESIZE];

	if (!prf_hash_initval)
		prf_hash_initval = (uint32_t)rte_rand();

	snprintf(buf, sizeof(buf), "tcp_hash_%u", lcore_id);
	hash = (struct ipv4_tcp_hash *)rte_zmalloc_socket(buf,
			sizeof(struct ipv4_tcp_hash), CACHE_LINE_SIZE, 0);
	return hash;
}

int
ipv4_tcp_conn_add(struct prf_lcore_conf *conf, uint32_t sip, uint32_t dip,
		uint16_t sport, uint16_t dport, uint64_t **timer,
		struct tcp_conn **tcp_conn)
{
	int ret = 0, i;
	uint32_t bucket;
	struct tcp_ent *ent;
	struct tcp_ent *cur;
	struct ipv4_tcp_hash *hash_table = conf->tcp_hash;

	if ((sip == 0) || (dip == 0) || (sport == 0) || (dport == 0))
		return -EINVAL;

	if (sip < dip)
		bucket = rte_jhash_3words(sip, dip, (sport << 16)|dport,
				prf_hash_initval) & PRF_TCP_CONN_HASH_MASK;
	else
		bucket = rte_jhash_3words(dip, sip, (dport << 16)|sport,
				prf_hash_initval) & PRF_TCP_CONN_HASH_MASK;
	for (i = 0; i <  PRF_KEYS_PER_BUCKET; i++) {
		if (hash_table->tcp_key_bucket[bucket].key[i].src_addr == 0) {
			hash_table->tcp_key_bucket[bucket].key[i].src_addr = sip;
			hash_table->tcp_key_bucket[bucket].key[i].dst_addr = dip;
			hash_table->tcp_key_bucket[bucket].key[i].src_port = sport;
			hash_table->tcp_key_bucket[bucket].key[i].dst_port = dport;
			*timer = &hash_table->timer_bucket[bucket].idle_timer[i];
			*tcp_conn = &hash_table->tcp_conn_bucket[bucket].tcp_conn[i];
			return 0;
		}
	}
	ret = rte_mempool_mc_get(prf_tcp_ent_pool, (void *)&ent);
	if (ret != 0) {
		return -ENOENT;
	}
	++conf->stats.chained_states;
	ent->next = NULL;
	ent->key.src_addr = sip;
	ent->key.dst_addr = dip;
	ent->key.src_port = sport;
	ent->key.dst_port = dport;
	*timer = &ent->idle_timer;
	*tcp_conn = &ent->tcp_conn;

	if (hash_table->tcp_key_bucket[bucket].tp == NULL) {
		hash_table->tcp_key_bucket[bucket].tp = ent;
		return 0;
	}

	cur = hash_table->tcp_key_bucket[bucket].tp;
	while (cur->next != NULL) {
		cur = cur->next;
	}
	cur->next = ent;
	return 0;
}

void
ipv4_tcp_conn_del_key(struct prf_lcore_conf *conf, uint64_t bucket, int i)
{
	struct ipv4_tcp_hash *hash_table = conf->tcp_hash;
	struct src_track_node *node =
		hash_table->tcp_conn_bucket[bucket].tcp_conn[i].src_track_node;
	struct rte_mbuf *tmp_mbuf, *tmp_nxt;

	if (unlikely(hash_table->tcp_conn_bucket[bucket].tcp_conn[i].state <
				PRF_TCP_STATE_ESTABL))
		--conf->stats.embrionic_counter;
	if (unlikely(hash_table->tcp_conn_bucket[bucket].tcp_conn[i].m != 0)) {
		tmp_mbuf = hash_table->tcp_conn_bucket[bucket].tcp_conn[i].m;
		while (tmp_mbuf) {
			tmp_nxt = (struct rte_mbuf *)tmp_mbuf->metadata64[0];
			rte_pktmbuf_free(tmp_mbuf);
			tmp_mbuf = tmp_nxt;
		}
	}
	if (likely(node != NULL)) {
		--node->counter;
		if (unlikely(node->counter == 0)) {
			rte_atomic64_dec(&node->rule->ref_cnt);
			src_track_node_del(node->rule->hash_table, node->key);
		}
	}
	--conf->stats.states_counter;
	++conf->stats.removals;
	memset(&hash_table->tcp_key_bucket[bucket].key[i], 0,
			sizeof(struct conn_tuple));
	hash_table->timer_bucket[bucket].idle_timer[i] = 0;
	memset(&hash_table->tcp_conn_bucket[bucket].tcp_conn[i], 0,
			sizeof(struct tcp_conn));
}

int
ipv4_tcp_conn_lookup_burst(struct prf_lcore_conf *conf, struct rte_mbuf **mb_arr,
		struct rte_mbuf **mb_new, int nb_pkt, uint64_t time)
{
	int i, j, k = 0, l = 0;
	uint32_t bucket[PRF_MAX_PKT_BURST];
	struct tcp_ent *cur;
	struct ipv4_hdr *ip_hdr;
	struct tcp_hdr *tcp_hdr;
	struct tcp_lookup tcp_lookup[PRF_MAX_PKT_BURST];
	struct ipv4_tcp_hash *hash_table = conf->tcp_hash;

	for (i = 0; i < nb_pkt; i++) {
		ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(mb_arr[i],
				struct ether_hdr *) + 1);
		tcp_hdr = (struct tcp_hdr *)((unsigned char *)ip_hdr +
				(ip_hdr->version_ihl & 0xf)*4);
		if (ip_hdr->src_addr < ip_hdr->dst_addr) {
			bucket[i] = rte_jhash_3words(ip_hdr->src_addr,
				ip_hdr->dst_addr, (tcp_hdr->src_port << 16) |
				tcp_hdr->dst_port, prf_hash_initval) & PRF_TCP_CONN_HASH_MASK;
		} else {
			bucket[i] = rte_jhash_3words(ip_hdr->dst_addr,
				ip_hdr->src_addr, (tcp_hdr->dst_port << 16) |
				tcp_hdr->src_port, prf_hash_initval) & PRF_TCP_CONN_HASH_MASK;
		}
		rte_prefetch0((void *)&hash_table->tcp_key_bucket[(bucket[i])]);
	}
	i = 0;
nxt_pkt:
	for (; i < nb_pkt;) {
		ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(mb_arr[i],
				struct ether_hdr *) + 1);
		tcp_hdr = (struct tcp_hdr *)((unsigned char *) ip_hdr +
				(ip_hdr->version_ihl & 0xf)*4);
		for (j = 0; j < PRF_KEYS_PER_BUCKET; j++) {
			if ((hash_table->tcp_key_bucket[bucket[i]].key[j].src_addr == ip_hdr->src_addr) &&
				(hash_table->tcp_key_bucket[bucket[i]].key[j].dst_addr == ip_hdr->dst_addr) &&
				(hash_table->tcp_key_bucket[bucket[i]].key[j].src_port == tcp_hdr->src_port) &&
				(hash_table->tcp_key_bucket[bucket[i]].key[j].dst_port == tcp_hdr->dst_port)) {
					tcp_lookup[k].timer = &hash_table->timer_bucket[bucket[i]].idle_timer[j];
					tcp_lookup[k].tcp_conn = &hash_table->tcp_conn_bucket[bucket[i]].tcp_conn[j];
					tcp_lookup[k].dir = PRF_DIR_ORIG;
					tcp_lookup[k].m = mb_arr[i];
					k++;
					i++;
					goto nxt_pkt;
			} else if ((hash_table->tcp_key_bucket[bucket[i]].key[j].src_addr == ip_hdr->dst_addr) &&
				(hash_table->tcp_key_bucket[bucket[i]].key[j].dst_addr == ip_hdr->src_addr) &&
				(hash_table->tcp_key_bucket[bucket[i]].key[j].src_port == tcp_hdr->dst_port) &&
				(hash_table->tcp_key_bucket[bucket[i]].key[j].dst_port == tcp_hdr->src_port)) {
					tcp_lookup[k].timer = &hash_table->timer_bucket[bucket[i]].idle_timer[j];
					tcp_lookup[k].tcp_conn = &hash_table->tcp_conn_bucket[bucket[i]].tcp_conn[j];
					tcp_lookup[k].m = mb_arr[i];
					tcp_lookup[k].dir = PRF_DIR_REV;
					k++;
					i++;
					goto nxt_pkt;
			}
		}
		cur = hash_table->tcp_key_bucket[bucket[i]].tp;
		while (cur != NULL) {
			++conf->stats.chained_lookup;
			if ((cur->key.src_addr == ip_hdr->src_addr) &&
				(cur->key.dst_addr == ip_hdr->dst_addr) &&
				(cur->key.src_port == tcp_hdr->src_port) &&
				(cur->key.dst_port == tcp_hdr->dst_port)) {
				tcp_lookup[k].timer = &cur->idle_timer;
				tcp_lookup[k].tcp_conn = &cur->tcp_conn;
				tcp_lookup[k].m = mb_arr[i];
				tcp_lookup[k].dir = PRF_DIR_ORIG;
				k++;
				i++;
				goto nxt_pkt;
			} else if ((cur->key.src_addr == ip_hdr->dst_addr) &&
					(cur->key.dst_addr == ip_hdr->src_addr) &&
					(cur->key.src_port == tcp_hdr->dst_port) &&
					(cur->key.dst_port == tcp_hdr->src_port)) {
					tcp_lookup[k].timer = &cur->idle_timer;
					tcp_lookup[k].tcp_conn = &cur->tcp_conn;
					tcp_lookup[k].m = mb_arr[i];
					tcp_lookup[k].dir = PRF_DIR_REV;
					k++;
					i++;
					goto nxt_pkt;
			}
			cur = cur->next;
		}
		mb_new[l++] = mb_arr[i];
		i++;
	}

	for (i = 0; i < k; i++) {
		rte_prefetch0((void *)tcp_lookup[i].timer);
		rte_prefetch0((void *)tcp_lookup[i].tcp_conn);
	}

	conf->stats.state_match += k;
	for (i = 0; i < k; i++) {
		process_tcp_seg(conf, tcp_lookup[i].m, tcp_lookup[i].tcp_conn,
				tcp_lookup[i].timer, time, tcp_lookup[i].dir);
	}
	return l;
}

int
ipv4_tcp_conn_lookup(struct prf_lcore_conf *conf, struct conn_tuple *key,
			uint64_t **timer, struct tcp_conn **tcp_conn)
{
	int i;
	uint32_t bucket;
	struct tcp_ent *cur;
	struct ipv4_tcp_hash *hash_table = conf->tcp_hash;

	if (key->src_addr < key->dst_addr) {
		bucket = rte_jhash_3words(*((uint32_t *)key), *((uint32_t *)key + 1),
			*((uint32_t *)key + 2), prf_hash_initval) & PRF_TCP_CONN_HASH_MASK;
	} else {
		bucket = rte_jhash_3words(*((uint32_t *)key + 3), *((uint32_t *)key + 4),
			*((uint32_t *)key + 5), prf_hash_initval) & PRF_TCP_CONN_HASH_MASK;
	}
	for (i = 0; i <  PRF_KEYS_PER_BUCKET; i++) {
		if ((hash_table->tcp_key_bucket[bucket].key[i].src_addr == key->src_addr) &&
			(hash_table->tcp_key_bucket[bucket].key[i].dst_addr == key->dst_addr) &&
			(hash_table->tcp_key_bucket[bucket].key[i].src_port == key->src_port) &&
			(hash_table->tcp_key_bucket[bucket].key[i].dst_port == key->dst_port)) {
			*timer = &hash_table->timer_bucket[bucket].idle_timer[i];
			*tcp_conn = &hash_table->tcp_conn_bucket[bucket].tcp_conn[i];
			return 0;
		} else if ((hash_table->tcp_key_bucket[bucket].key[i].src_addr == key->dst_addr) &&
			(hash_table->tcp_key_bucket[bucket].key[i].dst_addr == key->src_addr) &&
			(hash_table->tcp_key_bucket[bucket].key[i].src_port == key->dst_port) &&
			(hash_table->tcp_key_bucket[bucket].key[i].dst_port == key->src_port)) {
			*timer = &hash_table->timer_bucket[bucket].idle_timer[i];
			*tcp_conn = &hash_table->tcp_conn_bucket[bucket].tcp_conn[i];
			return 1;
		}
	}
	cur = hash_table->tcp_key_bucket[bucket].tp;
	while (cur) {
		++conf->stats.chained_lookup;
		if ((cur->key.src_addr == key->src_addr) &&
			(cur->key.dst_addr == key->dst_addr) &&
			(cur->key.src_port == key->src_port) &&
			(cur->key.dst_port == key->dst_port)) {
			*timer = &cur->idle_timer;
			*tcp_conn = &cur->tcp_conn;
			return 0;
		} else if ((cur->key.src_addr == key->dst_addr) &&
				(cur->key.dst_addr == key->src_addr) &&
				(cur->key.src_port == key->dst_port) &&
				(cur->key.dst_port == key->src_port)) {
				*timer = &cur->idle_timer;
				*tcp_conn = &cur->tcp_conn;
				return 1;
		}
		cur = cur->next;
	}
	return -ENOENT;
}

inline uint32_t
tcp_seq_plus_len(uint32_t seq, uint32_t len, uint8_t flags)
{
	return (seq + len + (flags & PRF_TCPHDR_SYN ? 1 : 0) +
			(flags & PRF_TCPHDR_FIN ? 1 : 0));
}

int
tcp_get_event(uint8_t flags) {
	if ((flags & (PRF_TCPHDR_SYN|PRF_TCPHDR_ACK)) == (PRF_TCPHDR_SYN|PRF_TCPHDR_ACK))
		return PRF_TCP_SYNACK_SET;
	else if ((flags & PRF_TCPHDR_SYN) == PRF_TCPHDR_SYN)
		return PRF_TCP_SYN_SET;
	else if ((flags & PRF_TCPHDR_FIN) == PRF_TCPHDR_FIN)
		return PRF_TCP_FIN_SET;
	return PRF_TCP_ACK_SET;
}

int
get_opts(uint8_t *ptr, int length, struct tcpopts *options)
{
	options->mss = 0;
	options->wscale = 0xf;
	options->sackok = 0;
	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case PRF_TCPOPT_EOL:
			return 0;
		case PRF_TCPOPT_NOP:
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2) /* "silly options" */
				return 1;
			if (opsize > length)
				return 1; /* don't parse partial options */
			switch (opcode) {
			case PRF_TCPOPT_MSS:
				if (opsize == PRF_TCPOLEN_MSS) {
					options->mss = *ptr << 8 | *(ptr + 1);
					if (options->mss < DEFAULT_MSS)
						return 1;
				}
				break;
			case PRF_TCPOPT_WINDOW:
				if (opsize == PRF_TCPOLEN_WINDOW) {
					options->wscale = *ptr;
					if (options->wscale > 14)
						options->wscale = 14;
				}
				break;
			case PRF_TCPOPT_SACK_PERM:
				if (opsize == PRF_TCPOLEN_SACK_PERM) {
					options->sackok = 1;
				}
				break;
			}
			ptr += opsize-2;
			length -= opsize;
		}
	}
	return 0;
}

void
ipv4_tcp_garbage_collect(struct prf_lcore_conf *conf, uint64_t time)
{
	uint32_t bucket;
	int  i, j;
	struct tcp_ent **head;
	struct tcp_ent *tmp;
	struct src_track_node *node = NULL;
	struct rte_mbuf *tmp_mbuf, *tmp_nxt;
	struct ipv4_tcp_hash *hash_table = conf->tcp_hash;

	bucket = (conf->bucket_pair_nb << 1) & PRF_TCP_CONN_HASH_MASK;

	for (i = 0; i < PRF_GC_BUCKETS; i++) {
		rte_prefetch0((void *)&hash_table->timer_bucket[bucket + i]);
		rte_prefetch0((void *)&hash_table->tcp_key_bucket[bucket + i]);
		i++;
		rte_prefetch0((void *)&hash_table->tcp_key_bucket[bucket + i]);
	}

	for (j = 0; j < PRF_GC_BUCKETS; j++) {
		for (i = 0; i < PRF_KEYS_PER_BUCKET; i++) {
			if (unlikely((hash_table->timer_bucket[bucket].idle_timer[i] != 0) &&
				(hash_table->timer_bucket[bucket].idle_timer[i] < time))) {
				ipv4_tcp_conn_del_key(conf, bucket, i);
			}
		}
		head = &hash_table->tcp_key_bucket[bucket].tp;
		while (unlikely((*head) != NULL)) {
			if (unlikely(((*head)->idle_timer != 0) &&
					((*head)->idle_timer < time))) {
				if (unlikely((*head)->tcp_conn.state < PRF_TCP_STATE_ESTABL))
					--conf->stats.embrionic_counter;
				--conf->stats.states_counter;
				++conf->stats.removals;
				--conf->stats.chained_states;
				if (unlikely((*head)->tcp_conn.m != NULL)) {
					tmp_mbuf = (*head)->tcp_conn.m;
					while (tmp_mbuf != NULL) {
						tmp_nxt = (struct rte_mbuf *)tmp_mbuf->metadata64[0];
						rte_pktmbuf_free(tmp_mbuf);
						tmp_mbuf = tmp_nxt;
					}
				}
				node = (*head)->tcp_conn.src_track_node;
				if (likely(node != NULL)) {
					--node->counter;
					if (unlikely(node->counter == 0)) {
						rte_atomic64_dec(&node->rule->ref_cnt);
						src_track_node_del(node->rule->hash_table, node->key);
					}
				}
				tmp = (*head);
				(*head) = (*head)->next;
				memset(tmp, 0, sizeof(struct tcp_ent));
				rte_mempool_mp_put(prf_tcp_ent_pool, tmp);
				continue;
			}
			head = &(*head)->next;
		}
		bucket = (bucket + 1) & PRF_TCP_CONN_HASH_MASK;
	}
	conf->bucket_pair_nb = bucket >> 1;
}
