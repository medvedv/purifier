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

#include "prf_stateful.h"
#include "prf_acl.h"
#include "prf_sec_ctx.h"
#include "prf_sec_ctx_api.h"
#include "main.h"
#include "prf_csum.h"

uint32_t prf_hash_initval = 0;
uint64_t prf_tcp_timer_table[PRF_TCP_STATE_NB_STATES] __rte_cache_aligned;

void
prf_process_tcp_seg(struct prf_lcore_conf *conf, struct rte_mbuf *m,
	struct prf_tcp_conn *prf_tcp_conn, uint64_t *timer, uint64_t time, int dir)
{
	uint8_t tcpflags;
	uint16_t win;
	int i, tcp_event, newstate, ret;
	uint32_t seq, ack, end, tcplen;
	struct rte_mbuf *tmpmbuf, *oldmbuf = NULL;
	struct ipv4_hdr *ip_hdr;
	struct tcp_hdr *tcp_hdr;
	struct prf_tcpopts prf_tcpopts;

	ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, struct ether_hdr *) + 1);
	tcp_hdr = (struct tcp_hdr *)((unsigned char *) ip_hdr +
				(ip_hdr->version_ihl & 0xf)*4);
	tcplen = rte_be_to_cpu_16(ip_hdr->total_length) -
		((ip_hdr->version_ihl & 0xf) << 2) - (tcp_hdr->data_off >> 2);
	tcpflags = (tcp_hdr->tcp_flags & ~(PRF_TCPHDR_ECE|PRF_TCPHDR_CWR|PRF_TCPHDR_PSH));
	seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);
	ack = rte_be_to_cpu_32(tcp_hdr->recv_ack);
	end = prf_tcp_seq_plus_len(seq, tcplen, tcpflags);
	win = rte_be_to_cpu_16(tcp_hdr->rx_win);

	if (!(tcpflags & PRF_TCPHDR_ACK))
		ack = prf_tcp_conn->dir[!dir].td_end;

	if (unlikely((tcpflags == PRF_TCPHDR_SYN) &&
		(prf_tcp_conn->state == PRF_TCP_STATE_TIME_WAIT))) {
		ret = prf_get_opts((uint8_t *)(tcp_hdr + 1), (tcp_hdr->data_off >> 2) -
					sizeof(struct tcp_hdr), &prf_tcpopts);
		if (ret) {
			++conf->stats.malformed;
			rte_pktmbuf_free(m);
			return;
		}
		++conf->stats.tw_reuse;
		prf_tcp_conn->dir[dir].packets = 0;
		prf_tcp_conn->dir[dir].bytes = 0;
		prf_tcp_conn->dir[dir].td_maxend =
		prf_tcp_conn->dir[dir].td_end = end;
		prf_tcp_conn->dir[dir].td_maxwin = RTE_MAX((win >> prf_tcpopts.wscale) + ((prf_tcpopts.wscale == 0) ? 0 : 1), 1);
		prf_tcp_conn->dir[dir].td_wscale = prf_tcpopts.wscale;
		prf_tcp_conn->dir[dir].packets++;
		prf_tcp_conn->dir[dir].bytes += m->pkt_len;
		*timer = time + prf_tcp_timer_table[PRF_TCP_STATE_SYN_SENT];
		++conf->stats.embrionic_counter;
		prf_tcp_conn->state = PRF_TCP_STATE_SYN_SENT;
		memset(&prf_tcp_conn->dir[!dir], 0, sizeof(struct prf_tcp_conn_state));
		prf_send_packet(m, conf, prf_dst_ports[m->port]);
		return;
	}

	if (unlikely((prf_tcp_conn->flags & PRF_TCP_STATE_SYNPROXY_INIT) && (dir == PRF_DIR_ORIG))) {
		m->userdata = 0;
		oldmbuf = prf_tcp_conn->m;
		i = 0;
		while (oldmbuf->userdata) {
			oldmbuf = (struct rte_mbuf *)oldmbuf->userdata;
			++i;
		}
		if ((i >= PRF_MAX_SYNPROXY_MBUF_CHAIN) || (conf->stats.stored_mbuf_cnt >= PRF_STORED_MBUF_THRSH)) {
			rte_pktmbuf_free(m);
			return;
		}
		++conf->stats.stored_mbuf_cnt;
		oldmbuf->userdata = m;
		return;
	}

	if (unlikely(tcpflags & PRF_TCPHDR_RST)) {
		++conf->stats.rst_set;
		if ((seq == 0) && (prf_tcp_conn->state == PRF_TCP_STATE_SYN_SENT) &&
					(dir == PRF_DIR_REV)) {
			seq = prf_tcp_conn->dir[dir].td_end;
		}

		if (((tcpflags & (PRF_TCPHDR_RST|PRF_TCPHDR_ACK)) ==
				(PRF_TCPHDR_RST|PRF_TCPHDR_ACK)) && (ack == 0))
			ack = prf_tcp_conn->dir[!dir].td_end;
		if ((prf_tcp_conn->flags & PRF_TCP_STATE_SYNPROXY) &&
				(dir == PRF_DIR_ORIG)) {
			tcp_hdr->recv_ack =
				rte_cpu_to_be_32(rte_be_to_cpu_32(tcp_hdr->recv_ack) -
				prf_tcp_conn->seq_diff);
			ack -= prf_tcp_conn->seq_diff;
			if (!(tcpflags & PRF_TCPHDR_ACK))
				ack = prf_tcp_conn->dir[!dir].td_end;
			ip_hdr->hdr_checksum  = 0;
			tcp_hdr->cksum          = prf_get_ipv4_psd_sum(ip_hdr);
			m->ol_flags = PKT_TX_IP_CKSUM|PKT_TX_TCP_CKSUM;
		}

		if (!(PRF_SEQ_LEQ(end, prf_tcp_conn->dir[dir].td_maxend) &&
			PRF_SEQ_GEQ(seq, prf_tcp_conn->dir[dir].td_end -
			RTE_MAX((prf_tcp_conn->dir[!dir].td_maxwin <<
			prf_tcp_conn->dir[!dir].td_wscale), 1)) &&
			PRF_SEQ_LEQ(ack, prf_tcp_conn->dir[!dir].td_end) &&
			PRF_SEQ_GEQ(ack, prf_tcp_conn->dir[!dir].td_end -
			(prf_tcp_conn->dir[dir].td_maxwin << prf_tcp_conn->dir[dir].td_wscale)))) {
				++conf->stats.bad_seq_ack;
				rte_pktmbuf_free(m);
				return;
		}
		if ((prf_tcp_conn->flags & PRF_TCP_STATE_SYNPROXY) &&
				(dir == PRF_DIR_REV)) {
			if ((rte_be_to_cpu_32(tcp_hdr->sent_seq) == 0) &&
				(prf_tcp_conn->state == PRF_TCP_STATE_SYN_SENT))
				tcp_hdr->sent_seq =
					rte_cpu_to_be_32(rte_be_to_cpu_32(tcp_hdr->sent_seq) + 1);
			tcp_hdr->sent_seq =
					rte_cpu_to_be_32(rte_be_to_cpu_32(tcp_hdr->sent_seq) +
					prf_tcp_conn->seq_diff);
			ip_hdr->hdr_checksum  = 0;
			tcp_hdr->cksum          = prf_get_ipv4_psd_sum(ip_hdr);
			m->ol_flags = PKT_TX_IP_CKSUM|PKT_TX_TCP_CKSUM;
		}
		if (prf_tcp_conn->state < PRF_TCP_STATE_ESTABL)
			--conf->stats.embrionic_counter;
		prf_tcp_conn->state = PRF_TCP_STATE_TIME_WAIT;
		*timer = time + prf_tcp_timer_table[PRF_TCP_STATE_TIME_WAIT];
		prf_send_packet(m, conf, prf_dst_ports[m->port]);
		return;
	}

	tcp_event = prf_tcp_get_event(tcpflags);
	newstate = prf_tcp_trans_table[dir][tcp_event][prf_tcp_conn->state];
	if (newstate == PRF_TCP_STATE_NONE) {
		++conf->stats.bad_flags;
		rte_pktmbuf_free(m);
		return;
	}

	if (prf_tcp_conn->dir[dir].td_maxwin == 0) {
		if (((tcpflags & (PRF_TCPHDR_SYN|PRF_TCPHDR_ACK)) != (PRF_TCPHDR_SYN|PRF_TCPHDR_ACK)) ||
				(ack != prf_tcp_conn->dir[!dir].td_end)) {
			++conf->stats.bad_seq_ack;
			rte_pktmbuf_free(m);
			return;
		}
		ret = prf_get_opts((uint8_t *)(tcp_hdr + 1), (tcp_hdr->data_off >> 2) -
				sizeof(struct tcp_hdr), &prf_tcpopts);
		if (ret) {
			++conf->stats.malformed;
			rte_pktmbuf_free(m);
			return;
		}
		prf_tcp_conn->dir[dir].td_wscale = prf_tcpopts.wscale;
		prf_tcp_conn->dir[dir].td_maxwin = RTE_MAX((win >> prf_tcpopts.wscale) + ((prf_tcpopts.wscale == 0) ? 0 : 1), 1);
		if ((prf_tcp_conn->dir[0].td_wscale == 15) || (prf_tcp_conn->dir[1].td_wscale == 15)) {
			prf_tcp_conn->dir[dir].td_maxwin = RTE_MAX(win, 1);
			prf_tcp_conn->dir[!dir].td_maxwin = (prf_tcp_conn->dir[!dir].td_maxwin << prf_tcp_conn->dir[!dir].td_wscale)
								- ((prf_tcp_conn->dir[!dir].td_wscale == 0) ? 0 : 1);
			prf_tcp_conn->dir[dir].td_wscale = 0;
			prf_tcp_conn->dir[!dir].td_wscale = 0;
		}
		prf_tcp_conn->dir[dir].td_maxend =
		prf_tcp_conn->dir[dir].td_end = end;
		prf_tcp_conn->dir[dir].packets++;
		prf_tcp_conn->dir[dir].bytes += m->pkt_len;
		if (prf_tcp_conn->flags & PRF_TCP_STATE_SYNPROXY) {
			prf_tcp_conn->seq_diff -=
				rte_be_to_cpu_32(tcp_hdr->sent_seq);
			prf_tcp_conn->flags &= ~PRF_TCP_STATE_SYNPROXY_INIT;
			if (PRF_SEQ_GT(ack + RTE_MAX((win << prf_tcp_conn->dir[dir].td_wscale), 1),
					prf_tcp_conn->dir[!dir].td_maxend))
				prf_tcp_conn->dir[!dir].td_maxend =
					ack + RTE_MAX((win << prf_tcp_conn->dir[dir].td_wscale), 1);
			*timer = time + prf_tcp_timer_table[newstate];
			prf_tcp_conn->state = newstate;

			rte_pktmbuf_free(m);
			oldmbuf = prf_tcp_conn->m;
			while (oldmbuf != NULL) {
				tmpmbuf = (struct rte_mbuf *)oldmbuf->userdata;
				--conf->stats.stored_mbuf_cnt;
				prf_process_tcp_seg(conf, oldmbuf, prf_tcp_conn, timer, time, !dir);
				oldmbuf = tmpmbuf;
			}
			prf_tcp_conn->m = NULL;
			return;
		}
	}

	if (unlikely((((prf_tcp_conn->state == PRF_TCP_STATE_SYN_SENT) && (dir == 0)
		&& ((tcpflags & PRF_TCPHDR_SYN) == PRF_TCPHDR_SYN)) ||
		((prf_tcp_conn->state == PRF_TCP_STATE_SYN_RCV) && (dir == 1)
		&&  ((tcpflags & (PRF_TCPHDR_SYN|PRF_TCPHDR_ACK)) == (PRF_TCPHDR_SYN|PRF_TCPHDR_ACK))))
		&& PRF_SEQ_GT(seq, prf_tcp_conn->dir[dir].td_end))) {
			ret = prf_get_opts((uint8_t *)(tcp_hdr + 1), (tcp_hdr->data_off >> 2) -
					sizeof(struct tcp_hdr), &prf_tcpopts);
			if (ret) {
				++conf->stats.malformed;
				rte_pktmbuf_free(m);
				return;
			}
			prf_tcp_conn->dir[dir].td_wscale = prf_tcpopts.wscale;
			prf_tcp_conn->dir[dir].td_maxend =
			prf_tcp_conn->dir[dir].td_end = end;
			prf_tcp_conn->dir[dir].td_maxwin = RTE_MAX((win >> prf_tcpopts.wscale) + ((prf_tcpopts.wscale == 0) ? 0 : 1), 1);
			if ((dir == 1) && ((prf_tcp_conn->dir[0].td_wscale == 15) || (prf_tcp_conn->dir[1].td_wscale == 15))) {
				prf_tcp_conn->dir[dir].td_maxwin = RTE_MAX(win, 1);
				prf_tcp_conn->dir[!dir].td_maxwin = (prf_tcp_conn->dir[!dir].td_maxwin << prf_tcp_conn->dir[!dir].td_wscale)
									- ((prf_tcp_conn->dir[!dir].td_wscale == 0) ? 0 : 1);
				prf_tcp_conn->dir[dir].td_wscale = 0;
				prf_tcp_conn->dir[!dir].td_wscale = 0;
			}
	}

	if ((prf_tcp_conn->flags & PRF_TCP_STATE_SYNPROXY) && (dir == PRF_DIR_ORIG)) {
		tcp_hdr->recv_ack =
			rte_cpu_to_be_32(rte_be_to_cpu_32(tcp_hdr->recv_ack) -
			prf_tcp_conn->seq_diff);
		ack -= prf_tcp_conn->seq_diff;
		ip_hdr->hdr_checksum  = 0;
		tcp_hdr->cksum          = prf_get_ipv4_psd_sum(ip_hdr);
		m->ol_flags = PKT_TX_IP_CKSUM|PKT_TX_TCP_CKSUM;
	}

	if (PRF_SEQ_LEQ(end, prf_tcp_conn->dir[dir].td_maxend) &&
			PRF_SEQ_GEQ(seq, prf_tcp_conn->dir[dir].td_end -
			RTE_MAX((prf_tcp_conn->dir[!dir].td_maxwin <<
			prf_tcp_conn->dir[!dir].td_wscale), 1)) &&
			PRF_SEQ_LEQ(ack, prf_tcp_conn->dir[!dir].td_end) &&
			PRF_SEQ_GEQ(ack, prf_tcp_conn->dir[!dir].td_end -
			(prf_tcp_conn->dir[dir].td_maxwin <<
			prf_tcp_conn->dir[dir].td_wscale))) {
		if (prf_tcp_conn->dir[dir].td_maxwin < win)
			prf_tcp_conn->dir[dir].td_maxwin = win;
		if (PRF_SEQ_GT(end, prf_tcp_conn->dir[dir].td_end))
			prf_tcp_conn->dir[dir].td_end = end;
		if (PRF_SEQ_GT(ack + RTE_MAX((win << prf_tcp_conn->dir[dir].td_wscale), 1),
				prf_tcp_conn->dir[!dir].td_maxend))
			prf_tcp_conn->dir[!dir].td_maxend =
				ack + RTE_MAX((win << prf_tcp_conn->dir[dir].td_wscale), 1);
		*timer = time + prf_tcp_timer_table[newstate];
		prf_tcp_conn->dir[dir].packets++;
		prf_tcp_conn->dir[dir].bytes += m->pkt_len;
		if ((newstate > PRF_TCP_STATE_SYN_RCV) &&
				(prf_tcp_conn->state < PRF_TCP_STATE_ESTABL))
			--conf->stats.embrionic_counter;
		prf_tcp_conn->state = newstate;

		if ((prf_tcp_conn->flags & PRF_TCP_STATE_SYNPROXY) && (dir == 1)) {
			tcp_hdr->sent_seq =
				rte_cpu_to_be_32(rte_be_to_cpu_32(tcp_hdr->sent_seq) +
							prf_tcp_conn->seq_diff);
			ip_hdr->hdr_checksum  = 0;
			tcp_hdr->cksum          = prf_get_ipv4_psd_sum(ip_hdr);
			m->ol_flags = PKT_TX_IP_CKSUM|PKT_TX_TCP_CKSUM;
		}
		prf_send_packet(m, conf, prf_dst_ports[m->port]);
		return;
	}
	++conf->stats.bad_seq_ack;
	rte_pktmbuf_free(m);
}

struct prf_ipv4_tcp_hash *
prf_ipv4_tcp_hash_init(unsigned lcore_id)
{
	struct prf_ipv4_tcp_hash *hash = NULL;
	char buf[PRF_TCP_HASH_NAMESIZE];

	if (!prf_hash_initval)
		prf_hash_initval = (uint32_t)rte_rand();

	snprintf(buf, sizeof(buf), "tcp_hash_%u", lcore_id);
	hash = (struct prf_ipv4_tcp_hash *)rte_zmalloc_socket(buf,
			sizeof(struct prf_ipv4_tcp_hash), RTE_CACHE_LINE_SIZE, 0);
	return hash;
}

int
prf_ipv4_tcp_conn_add(struct prf_lcore_conf *conf, uint32_t sip, uint32_t dip,
		uint16_t sport, uint16_t dport, uint64_t **timer,
		struct prf_tcp_conn **prf_tcp_conn)
{
	int ret = 0, i;
	uint32_t bucket;
	struct prf_tcp_ent *ent;
	struct prf_tcp_ent *cur;
	struct prf_ipv4_tcp_hash *hash_table = conf->tcp_hash;

	if ((sip == 0) || (dip == 0) || (sport == 0) || (dport == 0))
		return -EINVAL;

	if (sip < dip)
		bucket = rte_jhash_3words(sip, dip, (sport << 16)|dport,
				prf_hash_initval) & PRF_TCP_CONN_HASH_MASK;
	else
		bucket = rte_jhash_3words(dip, sip, (dport << 16)|sport,
				prf_hash_initval) & PRF_TCP_CONN_HASH_MASK;
	for (i = 0; i <  PRF_KEYS_PER_BUCKET; i++) {
		if (hash_table->prf_tcp_key_bucket[bucket].key[i].src_addr == 0) {
			hash_table->prf_tcp_key_bucket[bucket].key[i].src_addr = sip;
			hash_table->prf_tcp_key_bucket[bucket].key[i].dst_addr = dip;
			hash_table->prf_tcp_key_bucket[bucket].key[i].src_port = sport;
			hash_table->prf_tcp_key_bucket[bucket].key[i].dst_port = dport;
			*timer = &hash_table->prf_timer_bucket[bucket].idle_timer[i];
			*prf_tcp_conn = &hash_table->prf_tcp_conn_bucket[bucket].prf_tcp_conn[i];
			return 0;
		}
	}
	ret = rte_mempool_get(prf_tcp_ent_pool, (void *)&ent);
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
	*prf_tcp_conn = &ent->prf_tcp_conn;

	if (hash_table->prf_tcp_key_bucket[bucket].tp == NULL) {
		hash_table->prf_tcp_key_bucket[bucket].tp = ent;
		return 0;
	}

	cur = hash_table->prf_tcp_key_bucket[bucket].tp;
	while (cur->next != NULL) {
		cur = cur->next;
	}
	cur->next = ent;
	return 0;
}

void
prf_ipv4_tcp_conn_del_key(struct prf_lcore_conf *conf, uint64_t bucket, int i)
{
	struct prf_ipv4_tcp_hash *hash_table = conf->tcp_hash;
	struct prf_src_track_node *node =
		hash_table->prf_tcp_conn_bucket[bucket].prf_tcp_conn[i].prf_src_track_node;
	struct rte_mbuf *tmp_mbuf, *tmp_nxt;

	if (unlikely(hash_table->prf_tcp_conn_bucket[bucket].prf_tcp_conn[i].state <
				PRF_TCP_STATE_ESTABL))
		--conf->stats.embrionic_counter;
	if (unlikely(hash_table->prf_tcp_conn_bucket[bucket].prf_tcp_conn[i].m != 0)) {
		tmp_mbuf = hash_table->prf_tcp_conn_bucket[bucket].prf_tcp_conn[i].m;
		while (tmp_mbuf) {
			tmp_nxt = (struct rte_mbuf *)tmp_mbuf->userdata;
			--conf->stats.stored_mbuf_cnt;
			rte_pktmbuf_free(tmp_mbuf);
			tmp_mbuf = tmp_nxt;
		}
	}
	if (likely(node != NULL)) {
		--node->counter;
		if (unlikely(node->counter == 0)) {
			rte_atomic64_dec(&node->rule->ref_cnt);
			prf_src_track_node_del(node->rule->hash_table, node->key);
		}
	}
	--conf->stats.states_counter;
	++conf->stats.removals;
	memset(&hash_table->prf_tcp_key_bucket[bucket].key[i], 0,
			sizeof(struct prf_conn_tuple));
	hash_table->prf_timer_bucket[bucket].idle_timer[i] = 0;
	memset(&hash_table->prf_tcp_conn_bucket[bucket].prf_tcp_conn[i], 0,
			sizeof(struct prf_tcp_conn));
}

int
prf_ipv4_tcp_conn_lookup_burst(struct prf_lcore_conf *conf, struct rte_mbuf **mb_arr,
		struct rte_mbuf **mb_new, int nb_pkt, uint64_t time)
{
	int i, j, k = 0, l = 0;
	uint32_t bucket[PRF_MAX_PKT_BURST];
	struct prf_tcp_ent *cur;
	struct ipv4_hdr *ip_hdr;
	struct tcp_hdr *tcp_hdr;
	struct prf_tcp_lookup prf_tcp_lookup[PRF_MAX_PKT_BURST];
	struct prf_ipv4_tcp_hash *hash_table = conf->tcp_hash;

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
		rte_prefetch0((void *)&hash_table->prf_tcp_key_bucket[(bucket[i])]);
	}
	i = 0;
nxt_pkt:
	for (; i < nb_pkt;) {
		ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(mb_arr[i],
				struct ether_hdr *) + 1);
		tcp_hdr = (struct tcp_hdr *)((unsigned char *) ip_hdr +
				(ip_hdr->version_ihl & 0xf)*4);
		for (j = 0; j < PRF_KEYS_PER_BUCKET; j++) {
			if ((hash_table->prf_tcp_key_bucket[bucket[i]].key[j].src_addr == ip_hdr->src_addr) &&
				(hash_table->prf_tcp_key_bucket[bucket[i]].key[j].dst_addr == ip_hdr->dst_addr) &&
				(hash_table->prf_tcp_key_bucket[bucket[i]].key[j].src_port == tcp_hdr->src_port) &&
				(hash_table->prf_tcp_key_bucket[bucket[i]].key[j].dst_port == tcp_hdr->dst_port)) {
					prf_tcp_lookup[k].timer = &hash_table->prf_timer_bucket[bucket[i]].idle_timer[j];
					prf_tcp_lookup[k].prf_tcp_conn = &hash_table->prf_tcp_conn_bucket[bucket[i]].prf_tcp_conn[j];
					prf_tcp_lookup[k].dir = PRF_DIR_ORIG;
					prf_tcp_lookup[k].m = mb_arr[i];
					k++;
					i++;
					goto nxt_pkt;
			} else if ((hash_table->prf_tcp_key_bucket[bucket[i]].key[j].src_addr == ip_hdr->dst_addr) &&
				(hash_table->prf_tcp_key_bucket[bucket[i]].key[j].dst_addr == ip_hdr->src_addr) &&
				(hash_table->prf_tcp_key_bucket[bucket[i]].key[j].src_port == tcp_hdr->dst_port) &&
				(hash_table->prf_tcp_key_bucket[bucket[i]].key[j].dst_port == tcp_hdr->src_port)) {
					prf_tcp_lookup[k].timer = &hash_table->prf_timer_bucket[bucket[i]].idle_timer[j];
					prf_tcp_lookup[k].prf_tcp_conn = &hash_table->prf_tcp_conn_bucket[bucket[i]].prf_tcp_conn[j];
					prf_tcp_lookup[k].m = mb_arr[i];
					prf_tcp_lookup[k].dir = PRF_DIR_REV;
					k++;
					i++;
					goto nxt_pkt;
			}
		}
		cur = hash_table->prf_tcp_key_bucket[bucket[i]].tp;
		while (cur != NULL) {
			++conf->stats.chained_lookup;
			if ((cur->key.src_addr == ip_hdr->src_addr) &&
				(cur->key.dst_addr == ip_hdr->dst_addr) &&
				(cur->key.src_port == tcp_hdr->src_port) &&
				(cur->key.dst_port == tcp_hdr->dst_port)) {
				prf_tcp_lookup[k].timer = &cur->idle_timer;
				prf_tcp_lookup[k].prf_tcp_conn = &cur->prf_tcp_conn;
				prf_tcp_lookup[k].m = mb_arr[i];
				prf_tcp_lookup[k].dir = PRF_DIR_ORIG;
				k++;
				i++;
				goto nxt_pkt;
			} else if ((cur->key.src_addr == ip_hdr->dst_addr) &&
					(cur->key.dst_addr == ip_hdr->src_addr) &&
					(cur->key.src_port == tcp_hdr->dst_port) &&
					(cur->key.dst_port == tcp_hdr->src_port)) {
					prf_tcp_lookup[k].timer = &cur->idle_timer;
					prf_tcp_lookup[k].prf_tcp_conn = &cur->prf_tcp_conn;
					prf_tcp_lookup[k].m = mb_arr[i];
					prf_tcp_lookup[k].dir = PRF_DIR_REV;
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
		rte_prefetch0((void *)prf_tcp_lookup[i].timer);
		rte_prefetch0((void *)prf_tcp_lookup[i].prf_tcp_conn);
	}

	conf->stats.state_match += k;
	for (i = 0; i < k; i++) {
		prf_process_tcp_seg(conf, prf_tcp_lookup[i].m, prf_tcp_lookup[i].prf_tcp_conn,
				prf_tcp_lookup[i].timer, time, prf_tcp_lookup[i].dir);
	}
	return l;
}

int
prf_ipv4_tcp_conn_lookup(struct prf_lcore_conf *conf, struct prf_conn_tuple *key,
			uint64_t **timer, struct prf_tcp_conn **prf_tcp_conn)
{
	int i;
	uint32_t bucket;
	struct prf_tcp_ent *cur;
	struct prf_ipv4_tcp_hash *hash_table = conf->tcp_hash;

	if (key->src_addr < key->dst_addr) {
		bucket = rte_jhash_3words(*((uint32_t *)key), *((uint32_t *)key + 1),
			*((uint32_t *)key + 2), prf_hash_initval) & PRF_TCP_CONN_HASH_MASK;
	} else {
		bucket = rte_jhash_3words(*((uint32_t *)key + 3), *((uint32_t *)key + 4),
			*((uint32_t *)key + 5), prf_hash_initval) & PRF_TCP_CONN_HASH_MASK;
	}
	for (i = 0; i <  PRF_KEYS_PER_BUCKET; i++) {
		if ((hash_table->prf_tcp_key_bucket[bucket].key[i].src_addr == key->src_addr) &&
			(hash_table->prf_tcp_key_bucket[bucket].key[i].dst_addr == key->dst_addr) &&
			(hash_table->prf_tcp_key_bucket[bucket].key[i].src_port == key->src_port) &&
			(hash_table->prf_tcp_key_bucket[bucket].key[i].dst_port == key->dst_port)) {
			*timer = &hash_table->prf_timer_bucket[bucket].idle_timer[i];
			*prf_tcp_conn = &hash_table->prf_tcp_conn_bucket[bucket].prf_tcp_conn[i];
			return 0;
		} else if ((hash_table->prf_tcp_key_bucket[bucket].key[i].src_addr == key->dst_addr) &&
			(hash_table->prf_tcp_key_bucket[bucket].key[i].dst_addr == key->src_addr) &&
			(hash_table->prf_tcp_key_bucket[bucket].key[i].src_port == key->dst_port) &&
			(hash_table->prf_tcp_key_bucket[bucket].key[i].dst_port == key->src_port)) {
			*timer = &hash_table->prf_timer_bucket[bucket].idle_timer[i];
			*prf_tcp_conn = &hash_table->prf_tcp_conn_bucket[bucket].prf_tcp_conn[i];
			return 1;
		}
	}
	cur = hash_table->prf_tcp_key_bucket[bucket].tp;
	while (cur) {
		++conf->stats.chained_lookup;
		if ((cur->key.src_addr == key->src_addr) &&
			(cur->key.dst_addr == key->dst_addr) &&
			(cur->key.src_port == key->src_port) &&
			(cur->key.dst_port == key->dst_port)) {
			*timer = &cur->idle_timer;
			*prf_tcp_conn = &cur->prf_tcp_conn;
			return 0;
		} else if ((cur->key.src_addr == key->dst_addr) &&
				(cur->key.dst_addr == key->src_addr) &&
				(cur->key.src_port == key->dst_port) &&
				(cur->key.dst_port == key->src_port)) {
				*timer = &cur->idle_timer;
				*prf_tcp_conn = &cur->prf_tcp_conn;
				return 1;
		}
		cur = cur->next;
	}
	return -ENOENT;
}

uint32_t
prf_tcp_seq_plus_len(uint32_t seq, uint32_t len, uint8_t flags)
{
	return (seq + len + (flags & PRF_TCPHDR_SYN ? 1 : 0) +
			(flags & PRF_TCPHDR_FIN ? 1 : 0));
}

int
prf_tcp_get_event(uint8_t flags) {
	if ((flags & (PRF_TCPHDR_SYN|PRF_TCPHDR_ACK)) == (PRF_TCPHDR_SYN|PRF_TCPHDR_ACK))
		return PRF_TCP_SYNACK_SET;
	else if ((flags & PRF_TCPHDR_SYN) == PRF_TCPHDR_SYN)
		return PRF_TCP_SYN_SET;
	else if ((flags & PRF_TCPHDR_FIN) == PRF_TCPHDR_FIN)
		return PRF_TCP_FIN_SET;
	return PRF_TCP_ACK_SET;
}

int
prf_get_opts(uint8_t *ptr, int length, struct prf_tcpopts *options)
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
					if (options->mss < PRF_DEFAULT_MSS)
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
prf_ipv4_tcp_garbage_collect(struct prf_lcore_conf *conf, uint64_t time)
{
	uint32_t bucket;
	int  i, j;
	struct prf_tcp_ent **head;
	struct prf_tcp_ent *tmp;
	struct prf_src_track_node *node = NULL;
	struct rte_mbuf *tmp_mbuf, *tmp_nxt;
	struct prf_ipv4_tcp_hash *hash_table = conf->tcp_hash;

	bucket = (conf->bucket_pair_nb << 1) & PRF_TCP_CONN_HASH_MASK;

	for (i = 0; i < PRF_GC_BUCKETS; i++) {
		rte_prefetch0((void *)&hash_table->prf_timer_bucket[bucket + i]);
		rte_prefetch0((void *)&hash_table->prf_tcp_key_bucket[bucket + i]);
		i++;
		rte_prefetch0((void *)&hash_table->prf_tcp_key_bucket[bucket + i]);
	}

	for (j = 0; j < PRF_GC_BUCKETS; j++) {
		for (i = 0; i < PRF_KEYS_PER_BUCKET; i++) {
			if (unlikely((hash_table->prf_timer_bucket[bucket].idle_timer[i] != 0) &&
				(hash_table->prf_timer_bucket[bucket].idle_timer[i] < time))) {
				prf_ipv4_tcp_conn_del_key(conf, bucket, i);
			}
		}
		head = &hash_table->prf_tcp_key_bucket[bucket].tp;
		while (unlikely((*head) != NULL)) {
			if (unlikely(((*head)->idle_timer != 0) &&
					((*head)->idle_timer < time))) {
				if (unlikely((*head)->prf_tcp_conn.state < PRF_TCP_STATE_ESTABL))
					--conf->stats.embrionic_counter;
				--conf->stats.states_counter;
				++conf->stats.removals;
				--conf->stats.chained_states;
				if (unlikely((*head)->prf_tcp_conn.m != NULL)) {
					tmp_mbuf = (*head)->prf_tcp_conn.m;
					while (tmp_mbuf != NULL) {
						tmp_nxt = (struct rte_mbuf *)tmp_mbuf->userdata;
						--conf->stats.stored_mbuf_cnt;
						rte_pktmbuf_free(tmp_mbuf);
						tmp_mbuf = tmp_nxt;
					}
				}
				node = (*head)->prf_tcp_conn.prf_src_track_node;
				if (likely(node != NULL)) {
					--node->counter;
					if (unlikely(node->counter == 0)) {
						rte_atomic64_dec(&node->rule->ref_cnt);
						prf_src_track_node_del(node->rule->hash_table, node->key);
					}
				}
				tmp = (*head);
				(*head) = (*head)->next;
				memset(tmp, 0, sizeof(struct prf_tcp_ent));
				rte_mempool_put(prf_tcp_ent_pool, tmp);
				continue;
			}
			head = &(*head)->next;
		}
		bucket = (bucket + 1) & PRF_TCP_CONN_HASH_MASK;
	}
	conf->bucket_pair_nb = bucket >> 1;
}
