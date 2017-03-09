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

#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#include "prf_stateful.h"
#include "prf_acl.h"
#include "prf_sec_ctx.h"
#include "prf_sec_ctx_api.h"
#include "main.h"
#include "prf_csum.h"

static const struct rte_acl_field_def ipv4_defs[NUM_FIELDS_IPV4] = {
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint8_t),
		.field_index = PROTO_FIELD_IPV4,
		.input_index = 0,
		.offset = 0,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC_FIELD_IPV4,
		.input_index = 1,
		.offset = offsetof(struct ipv4_hdr, src_addr) -
			offsetof(struct ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST_FIELD_IPV4,
		.input_index = 2,
		.offset = offsetof(struct ipv4_hdr, dst_addr) -
			offsetof(struct ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = SRCP_FIELD_IPV4,
		.input_index = 3,
		.offset = sizeof(struct ipv4_hdr) -
			offsetof(struct ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = DSTP_FIELD_IPV4,
		.input_index = 3,
		.offset = sizeof(struct ipv4_hdr) -
			offsetof(struct ipv4_hdr, next_proto_id) +
			sizeof(uint16_t),
	},
};

prf_acl_callback_fn_t prf_acl_callbacks[] = { prf_acl_accept, prf_acl_drop, prf_acl_accept, prf_acl_reject, prf_acl_no_track, prf_acl_sec_ctx};

struct rte_acl_ctx *acl_ctx;
int prf_acl_version = 0;
struct rte_acl_param acl_param;
struct rte_acl_config acl_build_param;

void
prf_acl_drop(struct rte_mbuf *m, uint32_t result, struct prf_lcore_conf *conf, __attribute__((unused)) uint64_t time)
{
	++conf->stats.acl_stat[(result >> PRF_ACL_RESULT_RULE_SHIFT) & PRF_ACL_RESULT_RULE_MASK];
	rte_pktmbuf_free(m);
}

void
prf_acl_accept(struct rte_mbuf *m, uint32_t result, struct prf_lcore_conf *conf, uint64_t time)
{
	struct rte_mbuf *oldmbuf = NULL;
	struct ether_hdr *eth_hdr, *oldeth_hdr;
	struct ipv4_hdr *ip_hdr, *oldip_hdr;
	struct tcp_hdr  *tcp_hdr, *oldtcp_hdr;
	uint64_t *timer = NULL;
	struct prf_tcp_conn *prf_tcp_conn = NULL;
	char *tcp_opt;
	struct prf_tcpopts prf_tcpopts;
	struct ether_addr tmp_ether;
	uint32_t seq, end, tcplen, tmp_ip;
	int ret, optlen = 0;
	uint16_t win, tmp_port;
	uint8_t tcpflags, data;

	++conf->stats.acl_stat[(result >> PRF_ACL_RESULT_RULE_SHIFT) & PRF_ACL_RESULT_RULE_MASK];
	eth_hdr		= rte_pktmbuf_mtod(m, struct ether_hdr *);
	ip_hdr		= (struct ipv4_hdr *)(eth_hdr + 1);
	tcp_hdr		= (struct tcp_hdr *)((unsigned char *) ip_hdr + (ip_hdr->version_ihl & 0xf)*4);
	tcpflags	= (tcp_hdr->tcp_flags & ~(PRF_TCPHDR_ECE|PRF_TCPHDR_CWR|PRF_TCPHDR_PSH));
	tcplen		= rte_be_to_cpu_16(ip_hdr->total_length) - ((ip_hdr->version_ihl & 0xf) << 2) - (tcp_hdr->data_off >> 2);

	seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);
	end = prf_tcp_seq_plus_len(seq, tcplen, tcpflags);
	win = rte_be_to_cpu_16(tcp_hdr->rx_win);

	/* Maybe remove (tcplen != 0) in case retransmit syn to backend*/
	if (unlikely((tcpflags != PRF_TCPHDR_SYN) || (tcplen != 0))) {
		if ((tcpflags != PRF_TCPHDR_ACK) || (tcplen != 0) || (prf_synproxy_cookie_check(ip_hdr, tcp_hdr, time / (prf_tsc_hz * 60), &prf_tcpopts))) {
			++conf->stats.state_mismatch;
			rte_pktmbuf_free(m);
			return;
		}
		if ((prf_tcpopts.wscale != 0xf) || prf_tcpopts.sackok) {
			++conf->stats.state_mismatch;
			rte_pktmbuf_free(m);
			return;
		}
		++conf->stats.cookies_rcv;
		optlen = 4;
		oldmbuf		= m;
		oldeth_hdr	= eth_hdr;
		oldip_hdr	= ip_hdr;
		oldtcp_hdr	= tcp_hdr;
		m = rte_pktmbuf_alloc(prf_pktmbuf_pool);
		if (m == NULL) {
			rte_pktmbuf_free(oldmbuf);
			return;
		}
		m->port			= oldmbuf->port;
		eth_hdr			= (struct ether_hdr *)rte_pktmbuf_append(m, sizeof(struct ether_hdr));
		ip_hdr			= (struct ipv4_hdr *)rte_pktmbuf_append(m, sizeof(struct ipv4_hdr));
		tcp_hdr			= (struct tcp_hdr *)rte_pktmbuf_append(m, sizeof(struct tcp_hdr));
		tcp_opt			= (char *)rte_pktmbuf_append(m, optlen);
		ether_addr_copy(&oldeth_hdr->d_addr, &eth_hdr->d_addr);
		ether_addr_copy(&oldeth_hdr->s_addr, &eth_hdr->s_addr);
		eth_hdr->ether_type	= rte_be_to_cpu_16(ETHER_TYPE_IPv4);

		ip_hdr->version_ihl		= (uint8_t)((4<<4)|5);
		ip_hdr->type_of_service		= 0;
		ip_hdr->total_length		= rte_cpu_to_be_16(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr) + optlen);
		ip_hdr->packet_id		= oldip_hdr->packet_id;
		ip_hdr->fragment_offset		= rte_cpu_to_be_16(1<<14); /* DF flag */
		ip_hdr->time_to_live		= 64;
		ip_hdr->next_proto_id		= IPPROTO_TCP;
		ip_hdr->hdr_checksum		= 0;
		ip_hdr->src_addr		= oldip_hdr->src_addr;
		ip_hdr->dst_addr		= oldip_hdr->dst_addr;

		tcp_hdr->src_port		= oldtcp_hdr->src_port;
		tcp_hdr->dst_port		= oldtcp_hdr->dst_port;
		tcp_hdr->sent_seq		= rte_cpu_to_be_32(rte_be_to_cpu_32(oldtcp_hdr->sent_seq) - 1);
		tcp_hdr->recv_ack		= 0;
		tcp_hdr->data_off		= (sizeof(struct tcp_hdr) + optlen) << 2;
		tcp_hdr->tcp_flags		= PRF_TCPHDR_SYN;
		tcp_hdr->rx_win			= oldtcp_hdr->rx_win;
		tcp_hdr->cksum			= prf_get_ipv4_psd_sum(ip_hdr);
		tcp_hdr->tcp_urp		= 0;

		*tcp_opt        = PRF_TCPOPT_MSS;
		*(tcp_opt + 1)  = PRF_TCPOLEN_MSS;
		*(uint16_t *)(tcp_opt + 2) = rte_cpu_to_be_16(prf_tcpopts.mss);

		m->ol_flags = PKT_TX_IP_CKSUM|PKT_TX_TCP_CKSUM;

		seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);
		goto add_state;
	}
	ret = prf_get_opts((uint8_t *)(tcp_hdr + 1), (tcp_hdr->data_off >> 2) - sizeof(struct tcp_hdr), &prf_tcpopts);
	if (ret != 0) {
		++conf->stats.malformed;
		rte_pktmbuf_free(m);
		return;
	}

	if (conf->stats.embrionic_counter >= prf_embrionic_threshold) {
		if (prf_tcpopts.mss != 0)
			optlen = 4;
		prf_tcpopts.wscale = 0xf;
		prf_tcpopts.sackok = 0;

		ether_addr_copy(&eth_hdr->d_addr, &tmp_ether);
		ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
		ether_addr_copy(&tmp_ether, &eth_hdr->s_addr);
		tmp_ip			= ip_hdr->dst_addr;
		ip_hdr->dst_addr	= ip_hdr->src_addr;
		ip_hdr->src_addr	= tmp_ip;
		tmp_port		= tcp_hdr->dst_port;
		tcp_hdr->dst_port	= tcp_hdr->src_port;
		tcp_hdr->src_port	= tmp_port;
		ip_hdr->type_of_service	= 0;
		ip_hdr->total_length	= rte_cpu_to_be_16(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr) + optlen);
		ip_hdr->time_to_live	= 64;
		ip_hdr->fragment_offset	= rte_cpu_to_be_16(1<<14); /* DF flag */
		ip_hdr->hdr_checksum	= 0;
		tcp_hdr->recv_ack	= rte_cpu_to_be_32(rte_be_to_cpu_32(tcp_hdr->sent_seq) + 1);
		tcp_hdr->tcp_urp	= 0;
		tcp_hdr->cksum		= prf_get_ipv4_psd_sum(ip_hdr);
		tcp_hdr->rx_win		= rte_cpu_to_be_16(8192);
		tcp_hdr->tcp_flags	= PRF_TCPHDR_SYN|PRF_TCPHDR_ACK;
		tcp_hdr->data_off	= (sizeof(struct tcp_hdr) + optlen) << 2;

		if (prf_tcpopts.mss) {
			data = prf_compress_opt(&prf_tcpopts);
			tcp_hdr->sent_seq = rte_cpu_to_be_32(prf_synproxy_cookie_get(ip_hdr->dst_addr, ip_hdr->src_addr,
						tcp_hdr->dst_port, tcp_hdr->src_port, rte_be_to_cpu_32(tcp_hdr->sent_seq), time / (prf_tsc_hz * 60), data));
		} else {
			prf_tcpopts.mss = PRF_DEFAULT_MSS;
			data = prf_compress_opt(&prf_tcpopts);
			tcp_hdr->sent_seq = rte_cpu_to_be_32(prf_synproxy_cookie_get(ip_hdr->dst_addr, ip_hdr->src_addr,
						tcp_hdr->dst_port, tcp_hdr->src_port, rte_be_to_cpu_32(tcp_hdr->sent_seq), time / (prf_tsc_hz * 60), data));
			prf_tcpopts.mss = 0;
		}

		tcp_opt = (char *)(tcp_hdr + 1);
		if (prf_tcpopts.mss) {
			*tcp_opt        = PRF_TCPOPT_MSS;
			*(tcp_opt + 1)  = PRF_TCPOLEN_MSS;
			*(uint16_t *)(tcp_opt + 2) = rte_cpu_to_be_16(prf_msstab[data & 0x3]);
		}

		m->data_len = m->pkt_len = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr) + optlen;
		m->ol_flags = PKT_TX_IP_CKSUM|PKT_TX_TCP_CKSUM;

		++conf->stats.cookies_sent;
		prf_send_packet(m, conf, m->port);
		return;
	}
add_state:
	ret = prf_ipv4_tcp_conn_add(conf, ip_hdr->src_addr, ip_hdr->dst_addr, tcp_hdr->src_port, tcp_hdr->dst_port, &timer, &prf_tcp_conn);
	if (unlikely(ret != 0)) {
		if (ret == -ENOENT)
			++conf->stats.no_mem_pool;
		else
			++conf->stats.malformed;
		rte_pktmbuf_free(m);
		if (oldmbuf)
			rte_pktmbuf_free(oldmbuf);
		return;
	}
	++conf->stats.states_counter;
	++conf->stats.inserts;
	++conf->stats.embrionic_counter;

	if (oldmbuf != NULL) {
		oldmbuf->userdata	= 0;
		++conf->stats.stored_mbuf_cnt;
		prf_tcp_conn->m		= oldmbuf;
		prf_tcp_conn->seq_diff	= rte_be_to_cpu_32(oldtcp_hdr->recv_ack) - 1;
		prf_tcp_conn->flags	|= PRF_TCP_STATE_SYNPROXY_INIT|PRF_TCP_STATE_SYNPROXY;
	}

	prf_tcp_conn->dir[0].td_maxend =
	prf_tcp_conn->dir[0].td_end = end;
	prf_tcp_conn->dir[0].td_maxwin = RTE_MAX((win >> prf_tcpopts.wscale) + ((prf_tcpopts.wscale == 0) ? 0 : 1), 1);
	prf_tcp_conn->dir[0].td_wscale = prf_tcpopts.wscale;
	prf_tcp_conn->dir[0].packets++;
	prf_tcp_conn->dir[0].bytes += m->pkt_len;
	*timer = time + prf_tcp_timer_table[PRF_TCP_STATE_SYN_SENT];
	prf_tcp_conn->state = PRF_TCP_STATE_SYN_SENT;
	prf_tcp_conn->prf_src_track_node = NULL;
	prf_send_packet(m, conf, prf_dst_ports[m->port]);
}

void
prf_acl_reject(struct rte_mbuf *m, uint32_t result, struct prf_lcore_conf *conf, __attribute__((unused)) uint64_t time)
{
	/* for future implementation*/
	++conf->stats.acl_stat[(result >> PRF_ACL_RESULT_RULE_SHIFT) & PRF_ACL_RESULT_RULE_MASK];
	rte_pktmbuf_free(m);
}

void
prf_acl_no_track(struct rte_mbuf *m, uint32_t result, struct prf_lcore_conf *conf, __attribute__((unused)) uint64_t time)
{
	++conf->stats.acl_stat[(result >> PRF_ACL_RESULT_RULE_SHIFT) & PRF_ACL_RESULT_RULE_MASK];
	prf_send_packet(m, conf, prf_dst_ports[m->port]);
}

void
prf_acl_sec_ctx(struct rte_mbuf *m, uint32_t result, struct prf_lcore_conf *conf, uint64_t time)
{
	struct rte_mbuf *oldmbuf = NULL;
	struct ether_hdr *eth_hdr, *oldeth_hdr;
	struct ipv4_hdr *ip_hdr, *oldip_hdr;
	struct tcp_hdr  *tcp_hdr, *oldtcp_hdr;
	uint64_t *timer = NULL;
	struct prf_tcp_conn *prf_tcp_conn = NULL;
	struct prf_sec_ctx_rule *rule;
	struct prf_src_track_node *node;
	char *tcp_opt;
	struct prf_tcpopts prf_tcpopts;
	struct ether_addr tmp_ether;
	uint32_t seq, end, tcplen, tmp_ip;
	int ret, index, optlen = 0;
	uint16_t win, tmp_port;
	uint8_t tcpflags, data;

	++conf->stats.acl_stat[(result >> PRF_ACL_RESULT_RULE_SHIFT) & PRF_ACL_RESULT_RULE_MASK];
	index = (result >> PRF_ACL_SEC_CTX_RESULT_SHIFT) & PRF_ACL_SEC_CTX_RESULT_MASK;
	if (unlikely(index >= PRF_SEC_CTX_MAX_RULES)) {
		rte_pktmbuf_free(m);
		return;
	}
	rule = &conf->rules[index];

	eth_hdr		= rte_pktmbuf_mtod(m, struct ether_hdr *);
	ip_hdr		= (struct ipv4_hdr *)(eth_hdr + 1);
	tcp_hdr		= (struct tcp_hdr *)((unsigned char *) ip_hdr + (ip_hdr->version_ihl & 0xf)*4);
	tcpflags	= (tcp_hdr->tcp_flags & ~(PRF_TCPHDR_ECE|PRF_TCPHDR_CWR|PRF_TCPHDR_PSH));
	tcplen		= rte_be_to_cpu_16(ip_hdr->total_length) - ((ip_hdr->version_ihl & 0xf) << 2) - (tcp_hdr->data_off >> 2);

	seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);
	end = prf_tcp_seq_plus_len(seq, tcplen, tcpflags);
	win = rte_be_to_cpu_16(tcp_hdr->rx_win);

	if (unlikely((tcpflags != PRF_TCPHDR_SYN) || (tcplen != 0))) {
		if ((tcpflags != PRF_TCPHDR_ACK) || (tcplen != 0) || (prf_synproxy_cookie_check(ip_hdr, tcp_hdr, time / (prf_tsc_hz * 60), &prf_tcpopts))) {
			++conf->stats.state_mismatch;
			rte_pktmbuf_free(m);
			return;
		}
		if (unlikely((prf_tcpopts.mss > rule->syn_proxy_mss) ||
				((prf_tcpopts.wscale != 0xf) && (!(rule->flags & PRF_SYN_PROXY_WSCALE_PERM))) ||
				(prf_tcpopts.sackok && (!(rule->flags & PRF_SYN_PROXY_SACK_PERM))))) {
			++conf->stats.state_mismatch;
			rte_pktmbuf_free(m);
			return;
		}

		++conf->stats.cookies_rcv;
		if (prf_tcpopts.mss)
			optlen += 4;
		if (!(prf_tcpopts.wscale == 0xf))
			optlen += 4;
		if (prf_tcpopts.sackok)
			optlen += 4;

		oldmbuf		= m;
		oldeth_hdr	= eth_hdr;
		oldip_hdr	= ip_hdr;
		oldtcp_hdr	= tcp_hdr;
		m = rte_pktmbuf_alloc(prf_pktmbuf_pool);
		if (m == NULL) {
			rte_pktmbuf_free(oldmbuf);
			return;
		}
		m->port			= oldmbuf->port;
		eth_hdr			= (struct ether_hdr *)rte_pktmbuf_append(m, sizeof(struct ether_hdr));
		ip_hdr			= (struct ipv4_hdr *)rte_pktmbuf_append(m, sizeof(struct ipv4_hdr));
		tcp_hdr			= (struct tcp_hdr *)rte_pktmbuf_append(m, sizeof(struct tcp_hdr));
		tcp_opt			= (char *)rte_pktmbuf_append(m, optlen);
		ether_addr_copy(&oldeth_hdr->d_addr, &eth_hdr->d_addr);
		ether_addr_copy(&oldeth_hdr->s_addr, &eth_hdr->s_addr);
		eth_hdr->ether_type	= rte_be_to_cpu_16(ETHER_TYPE_IPv4);

		ip_hdr->version_ihl		= (uint8_t)((4<<4)|5);
		ip_hdr->type_of_service		= 0;
		ip_hdr->total_length		= rte_cpu_to_be_16(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr) + optlen);
		ip_hdr->packet_id		= oldip_hdr->packet_id;
		ip_hdr->fragment_offset		= rte_cpu_to_be_16(1<<14); /* DF flag */
		ip_hdr->time_to_live		= 64;
		ip_hdr->next_proto_id		= IPPROTO_TCP;
		ip_hdr->hdr_checksum		= 0;
		ip_hdr->src_addr		= oldip_hdr->src_addr;
		ip_hdr->dst_addr		= oldip_hdr->dst_addr;

		tcp_hdr->src_port		= oldtcp_hdr->src_port;
		tcp_hdr->dst_port		= oldtcp_hdr->dst_port;
		tcp_hdr->sent_seq		= rte_cpu_to_be_32(rte_be_to_cpu_32(oldtcp_hdr->sent_seq) - 1);
		tcp_hdr->recv_ack		= 0;
		tcp_hdr->data_off		= (sizeof(struct tcp_hdr) + optlen) << 2;
		tcp_hdr->tcp_flags		= PRF_TCPHDR_SYN;
		tcp_hdr->rx_win			= oldtcp_hdr->rx_win;
		tcp_hdr->cksum			= prf_get_ipv4_psd_sum(ip_hdr);
		tcp_hdr->tcp_urp		= 0;

		if (prf_tcpopts.mss) {
			*tcp_opt	= PRF_TCPOPT_MSS;
			*(tcp_opt + 1)	= PRF_TCPOLEN_MSS;
			*(uint16_t *)(tcp_opt + 2) = rte_cpu_to_be_16(prf_tcpopts.mss);
			tcp_opt	+= 4;
		}
		if (!(prf_tcpopts.wscale == 0xf)) {
			*tcp_opt	= PRF_TCPOPT_NOP;
			*(++tcp_opt)	= PRF_TCPOPT_WINDOW;
			*(++tcp_opt)	= PRF_TCPOLEN_WINDOW;
			*(++tcp_opt)	= prf_tcpopts.wscale;
			++tcp_opt;
		}
		if (prf_tcpopts.sackok) {
			*tcp_opt	= PRF_TCPOPT_NOP;
			*(++tcp_opt)	= PRF_TCPOPT_NOP;
			*(++tcp_opt)	= PRF_TCPOPT_SACK_PERM;
			*(++tcp_opt)	= PRF_TCPOLEN_SACK_PERM;
		}

		m->ol_flags = PKT_TX_IP_CKSUM|PKT_TX_TCP_CKSUM;

		seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);
		goto add_state;
	}
	ret = prf_get_opts((uint8_t *)(tcp_hdr + 1), (tcp_hdr->data_off >> 2) - sizeof(struct tcp_hdr), &prf_tcpopts);
	if (ret != 0) {
		++conf->stats.malformed;
		rte_pktmbuf_free(m);
		return;
	}

	if (conf->stats.embrionic_counter >= prf_embrionic_threshold) {
		prf_tcpopts.mss = RTE_MIN(prf_tcpopts.mss, rule->syn_proxy_mss);
		if (!(rule->flags & PRF_SYN_PROXY_WSCALE_PERM))
			prf_tcpopts.wscale = 0xf;
		if (!(rule->flags & PRF_SYN_PROXY_SACK_PERM))
			prf_tcpopts.sackok = 0;
		if (prf_tcpopts.mss)
			optlen += 4;
		if (!(prf_tcpopts.wscale == 0xf))
			optlen += 4;
		if (prf_tcpopts.sackok)
			optlen += 4;

		ether_addr_copy(&eth_hdr->d_addr, &tmp_ether);
		ether_addr_copy(&eth_hdr->s_addr, &eth_hdr->d_addr);
		ether_addr_copy(&tmp_ether, &eth_hdr->s_addr);
		tmp_ip			= ip_hdr->dst_addr;
		ip_hdr->dst_addr	= ip_hdr->src_addr;
		ip_hdr->src_addr	= tmp_ip;
		tmp_port		= tcp_hdr->dst_port;
		tcp_hdr->dst_port	= tcp_hdr->src_port;
		tcp_hdr->src_port	= tmp_port;
		ip_hdr->type_of_service	= 0;
		ip_hdr->total_length	= rte_cpu_to_be_16(sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr) + optlen);
		ip_hdr->time_to_live	= 64;
		ip_hdr->fragment_offset	= rte_cpu_to_be_16(1<<14); /* DF flag */
		ip_hdr->hdr_checksum	= 0;
		tcp_hdr->recv_ack	= rte_cpu_to_be_32(rte_be_to_cpu_32(tcp_hdr->sent_seq) + 1);
		tcp_hdr->tcp_urp	= 0;
		tcp_hdr->cksum		= prf_get_ipv4_psd_sum(ip_hdr);
		tcp_hdr->rx_win		= rte_cpu_to_be_16(8192);
		tcp_hdr->tcp_flags	= PRF_TCPHDR_SYN|PRF_TCPHDR_ACK;
		tcp_hdr->data_off	= (sizeof(struct tcp_hdr) + optlen) << 2;

		if (prf_tcpopts.mss) {
			data = prf_compress_opt(&prf_tcpopts);
			tcp_hdr->sent_seq = rte_cpu_to_be_32(prf_synproxy_cookie_get(ip_hdr->dst_addr, ip_hdr->src_addr,
						tcp_hdr->dst_port, tcp_hdr->src_port, rte_be_to_cpu_32(tcp_hdr->sent_seq), time / (prf_tsc_hz * 60), data));
		} else {
			prf_tcpopts.mss = PRF_DEFAULT_MSS;
			data = prf_compress_opt(&prf_tcpopts);
			tcp_hdr->sent_seq = rte_cpu_to_be_32(prf_synproxy_cookie_get(ip_hdr->dst_addr, ip_hdr->src_addr,
						tcp_hdr->dst_port, tcp_hdr->src_port, rte_be_to_cpu_32(tcp_hdr->sent_seq), time / (prf_tsc_hz * 60), data));
			prf_tcpopts.mss = 0;
		}

		tcp_opt = (char *)(tcp_hdr + 1);
		if (prf_tcpopts.mss) {
			*tcp_opt	= PRF_TCPOPT_MSS;
			*(tcp_opt + 1)	= PRF_TCPOLEN_MSS;
			*(uint16_t *)(tcp_opt + 2) = rte_cpu_to_be_16(prf_msstab[data & 0x3]);
			tcp_opt += 4;
		}
		if (!(prf_tcpopts.wscale == 0xf)) {
			*tcp_opt	= PRF_TCPOPT_NOP;
			*(++tcp_opt)	= PRF_TCPOPT_WINDOW;
			*(++tcp_opt)	= PRF_TCPOLEN_WINDOW;
			*(++tcp_opt)	= rule->syn_proxy_wscale;
			++tcp_opt;
		}
		if (prf_tcpopts.sackok) {
			*tcp_opt	= PRF_TCPOPT_NOP;
			*(++tcp_opt)	= PRF_TCPOPT_NOP;
			*(++tcp_opt)	= PRF_TCPOPT_SACK_PERM;
			*(++tcp_opt)	= PRF_TCPOLEN_SACK_PERM;
		}

		m->data_len = m->pkt_len = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct tcp_hdr) + optlen;
		m->ol_flags = PKT_TX_IP_CKSUM|PKT_TX_TCP_CKSUM;

		++conf->stats.cookies_sent;
		prf_send_packet(m, conf, m->port);
		return;
	}
add_state:
	ret = prf_src_track_checkout(rule, rte_be_to_cpu_32(ip_hdr->src_addr), time, &node);

	/* add switch case statement for handling different non zero return causes (rate|max_conn|black_list) */
	if (ret != 0) {
		++conf->stats.src_track_overflow;
		rte_pktmbuf_free(m);
		if (oldmbuf)
			rte_pktmbuf_free(oldmbuf);
		return;
	}

	ret = prf_ipv4_tcp_conn_add(conf, ip_hdr->src_addr, ip_hdr->dst_addr, tcp_hdr->src_port, tcp_hdr->dst_port, &timer, &prf_tcp_conn);
	if (unlikely(ret != 0)) {
		if (ret == -ENOENT)
			++conf->stats.no_mem_pool;
		else
			++conf->stats.malformed;
		--node->counter;
		if (unlikely(node->counter == 0)) {
			rte_atomic64_dec(&node->rule->ref_cnt);
			prf_src_track_node_del(node->rule->hash_table, node->key);
		}
		rte_pktmbuf_free(m);
		if (oldmbuf)
			rte_pktmbuf_free(oldmbuf);
		return;
	}
	++conf->stats.states_counter;
	++conf->stats.inserts;
	++conf->stats.embrionic_counter;

	if (oldmbuf != NULL) {
		oldmbuf->userdata	= 0;
		++conf->stats.stored_mbuf_cnt;
		prf_tcp_conn->m		= oldmbuf;
		prf_tcp_conn->seq_diff	= rte_be_to_cpu_32(oldtcp_hdr->recv_ack) - 1;
		prf_tcp_conn->flags         |= PRF_TCP_STATE_SYNPROXY_INIT|PRF_TCP_STATE_SYNPROXY;
	}

	prf_tcp_conn->dir[0].td_maxend =
	prf_tcp_conn->dir[0].td_end = end;
	prf_tcp_conn->dir[0].td_maxwin = RTE_MAX((win >> prf_tcpopts.wscale) + ((prf_tcpopts.wscale == 0) ? 0 : 1), 1);
	prf_tcp_conn->dir[0].td_wscale = prf_tcpopts.wscale;
	prf_tcp_conn->dir[0].packets++;
	prf_tcp_conn->dir[0].bytes += m->pkt_len;
	*timer = time + prf_tcp_timer_table[PRF_TCP_STATE_SYN_SENT];
	prf_tcp_conn->state = PRF_TCP_STATE_SYN_SENT;
	prf_tcp_conn->prf_src_track_node = node;
	prf_send_packet(m, conf, prf_dst_ports[m->port]);
}

void
prf_init_acl_config(void)
{
	acl_param.socket_id		= PRF_SOCKET0;
	acl_param.rule_size		= RTE_ACL_RULE_SZ(RTE_DIM(ipv4_defs));
	acl_param.max_rule_num		= PRF_ACL_MAX_RULES;
	acl_build_param.num_categories	= PRF_DEFAULT_MAX_CATEGORIES;
	acl_build_param.num_fields	= RTE_DIM(ipv4_defs);
	memcpy(&acl_build_param.defs, ipv4_defs, sizeof(ipv4_defs));
}

int
prf_acl_create(struct rte_acl_rule *acl_rules, int acl_num, struct rte_acl_ctx **ctx)
{
	int ret = 0;
	char name[PRF_ACL_NAME];

	prf_acl_version++;
	snprintf(name, sizeof(name), "acl_%d", prf_acl_version);

	acl_param.name = name;
	*ctx = rte_acl_create(&acl_param);
	if (*ctx == NULL)
		return -ENOENT;

	if (acl_num > 0) {
		ret = rte_acl_add_rules(*ctx, acl_rules, acl_num);
		if (ret < 0) {
			rte_acl_free(*ctx);
			return ret;
		}
	}

	ret = rte_acl_build(*ctx, &acl_build_param);
	if (ret != 0)
		rte_acl_free(*ctx);

	return ret;
}

void
prf_build_empty_acl(struct rte_acl_ctx **ctx)
{
	int ret;
	struct acl4_rule *rules = rte_calloc(NULL, 1, sizeof(struct acl4_rule), 0);

	rules->data.category_mask = 1;
	rules->data.priority = RTE_ACL_MAX_PRIORITY - 1;
	rules->data.userdata = 1 << (PRF_ACL_RESULT_RULE_SHIFT + PRF_ACL_MAX_RULES_BITS);
	rules->field[PROTO_FIELD_IPV4].value.u8       = IPPROTO_TCP;
	rules->field[PROTO_FIELD_IPV4].mask_range.u8  = 0xff;
	rules->field[SRC_FIELD_IPV4].value.u32        = IPv4(0, 0, 0, 0);
	rules->field[SRC_FIELD_IPV4].mask_range.u32   = 0;
	rules->field[DST_FIELD_IPV4].value.u32        = IPv4(0, 0, 0, 0);
	rules->field[DST_FIELD_IPV4].mask_range.u32   = 0;
	rules->field[SRCP_FIELD_IPV4].value.u16       = 0;
	rules->field[SRCP_FIELD_IPV4].mask_range.u16  = 65535;
	rules->field[DSTP_FIELD_IPV4].value.u16       = 0;
	rules->field[DSTP_FIELD_IPV4].mask_range.u16  = 65535;

	ret = prf_acl_create((struct rte_acl_rule *)rules, 1, ctx);
	if (ret != 0)
		rte_exit(EXIT_FAILURE, "Failed to create ACL context\n");
	rte_free(rules);
}

