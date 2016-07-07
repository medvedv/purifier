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

#include <getopt.h>
#include <stdio.h>
#include <inttypes.h>
#include <rte_string_fns.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>

#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <termios.h>
#include <sys/queue.h>

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_socket.h>
#include <cmdline.h>

#include "prf_stateful.h"
#include "prf_acl.h"
#include "prf_sec_ctx.h"
#include "main.h"
#include "prf_csum.h"
#include "cmdline.h"

#define MAX_LCORES 8
#define MIN_LCORES 3
#define NB_MBUF	65535
#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define NB_RXD	512
#define NB_TXD	512

#define OFFLINE_CORE	0
#define MASTER_CORE	1
#define PRIMARY_CORE	2
#define WORKER_CORE	3

uint64_t prf_tsc_hz;
struct prf_lcore_conf prf_lcore_conf[RTE_MAX_LCORE] __rte_cache_aligned;
int prf_mastercore_id;
int prf_primarycore_id;
int prf_nb_fwd_cores;
int prf_nb_worker_cores;

struct rte_mempool *prf_pktmbuf_pool;
struct rte_mempool *prf_tcp_ent_pool;
struct rte_mempool *prf_src_track_pool;

struct  ether_addr dst_mac[PRF_MAX_PORTS] __rte_cache_aligned;
struct  ether_addr src_mac[PRF_MAX_PORTS] __rte_cache_aligned;

#define RSS_BYTE0 0x6d
#define RSS_BYTE1 0x5a
#define RSS_BYTE2 0x15
#define RSS_BYTE3 0x3e

int8_t prf_dst_ports[PRF_MAX_PORTS];
struct rte_eth_rss_reta reta_conf;
uint8_t my_rss_key[40];

static uint64_t poll_tsc;

#define OFF_ETHHEAD     (sizeof(struct ether_hdr))
#define OFF_IPV42PROTO (offsetof(struct ipv4_hdr, next_proto_id))
#define MBUF_IPV4_2PROTO(m)     \
	(rte_pktmbuf_mtod((m), uint8_t *) + OFF_ETHHEAD + OFF_IPV42PROTO)

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the network
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#define RX_PTHRESH 8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 4 /**< Default values of RX write-back threshold reg. */

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#define TX_PTHRESH 36 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg. */

#define BURST_TX_DRAIN_US	100 /* TX drain every ~100us */
#define RX_POLL_US		2  /*  Poll every ~30 pkts @15 Mpps*/

#define PREFETCH_OFFSET		16

static const struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 1, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 1, /**< CRC stripped by hardware */
	},
	.txmode = {
		.mq_mode	= ETH_MQ_TX_NONE,
	},
	.rx_adv_conf.rss_conf   = {
		.rss_key        = my_rss_key,
		.rss_hf         = ETH_RSS_IPV4,
	},
};

static const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = RX_PTHRESH,
		.hthresh = RX_HTHRESH,
		.wthresh = RX_WTHRESH,
	},
};

static const struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = TX_PTHRESH,
		.hthresh = TX_HTHRESH,
		.wthresh = TX_WTHRESH,
	},
	.tx_free_thresh = 0, /* Use PMD default values */
	.tx_rs_thresh = 0, /* Use PMD default values */
};

static inline uint16_t
get_16b_sum(uint16_t *ptr16, uint32_t nr)
{
	uint32_t sum = 0;

	while (nr > 1) {
		sum += *ptr16;
		nr -= sizeof(uint16_t);
		ptr16++;
		if (sum > UINT16_MAX)
			sum -= UINT16_MAX;
	}

	/* If length is in odd bytes */
	if (nr)
		sum += *((uint8_t *)ptr16);

	sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
	sum &= 0x0ffff;
	return (uint16_t)sum;
}

inline
uint16_t prf_get_ipv4_psd_sum(struct ipv4_hdr *ip_hdr)
{
	struct prf_psd_header psd_hdr;

	psd_hdr.src_addr = ip_hdr->src_addr;
	psd_hdr.dst_addr = ip_hdr->dst_addr;
	psd_hdr.zero	= 0;
	psd_hdr.proto	= ip_hdr->next_proto_id;
	psd_hdr.len	= rte_cpu_to_be_16((uint16_t)
			(rte_be_to_cpu_16(ip_hdr->total_length)
				- sizeof(struct ipv4_hdr)));
	return get_16b_sum((uint16_t *)&psd_hdr, sizeof(struct prf_psd_header));
}

static void
send_burst(struct prf_lcore_conf *conf, unsigned n, uint8_t port)
{
	struct rte_mbuf **m_table;
	unsigned ret;
	unsigned queue_id = conf->queue_id;

	m_table = (struct rte_mbuf **)conf->tx_mbufs[port].m_table;
	ret = rte_eth_tx_burst(port, (uint16_t) queue_id,
			m_table, (uint16_t) n);
	conf->stats.tx_pkts += ret;
	if (unlikely(ret < n)) {
		do {
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < n);
	}
}

void
prf_send_packet(struct rte_mbuf *m, struct prf_lcore_conf *conf, uint8_t port)
{
	unsigned len;

	m->pkt.vlan_macip.f.l2_len = sizeof(struct ether_hdr);
	m->pkt.vlan_macip.f.l3_len = sizeof(struct ipv4_hdr);
	len = conf->len[port];
	conf->tx_mbufs[port].m_table[len] = m;
	len++;
	if (unlikely(len == PRF_MAX_PKT_BURST)) {
		send_burst(conf, PRF_MAX_PKT_BURST, port);
		len = 0;
	}
	len = conf->len[port] = len;
}

static inline int
is_valid_ipv4_pkt(struct ipv4_hdr *pkt, uint32_t link_len)
{
	/* From http://www.rfc-editor.org/rfc/rfc1812.txt section 5.2.2 */
	/*
	 * 1. The packet length reported by the Link Layer must be large
	 * enough to hold the minimum length legal IP datagram (20 bytes).
	 */
	if (unlikely(link_len < sizeof(struct ipv4_hdr)))
		return -1;

	/* 2. The IP checksum must be correct. */
	/* this is checked in H/W */

	/*
	 * 3. The IP version number must be 4. If the version number is not 4
	 * then the packet may be another version of IP, such as IPng or
	 * ST-II.
	 */
	if (unlikely(((pkt->version_ihl) >> 4) != 4))
		return -3;
	/*
	 * 4. The IP header length field must be large enough to hold the
	 * minimum length legal IP datagram (20 bytes = 5 words).
	 */
/*        if ((pkt->version_ihl & 0xf) < 5) */
		/*Drop ip opt packets (proper handle after ACL rework)*/
	if (unlikely((pkt->version_ihl & 0xf) != 5))
		return -4;

	/*
	 * 5. The IP total length field must be large enough to hold the IP
	 * datagram header, whose length is specified in the IP header length
	 * field.
	 */
	if (unlikely(rte_cpu_to_be_16(pkt->total_length) < sizeof(struct ipv4_hdr)))
		return -5;

	return 0;
}

static int
tcp_sanity_check(struct rte_mbuf **pkt_in, struct rte_mbuf **pkt_out,
		int nb_pkt, struct prf_lcore_conf *conf)
{
	struct rte_mbuf *m;
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ipv4_hdr;
	struct tcp_hdr *tcp_hdr;
	uint16_t flag_offset, ip_flag, ip_ofs, tcplen;
	int ret, i, j = 0;
	uint8_t tcpflags;

	for (i = 0; i < nb_pkt; i++) {
		m = pkt_in[i];
		eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

		if (unlikely(((m->ol_flags & PKT_RX_IPV4_HDR) != PKT_RX_IPV4_HDR) ||
			(rte_be_to_cpu_16(eth_hdr->ether_type) != ETHER_TYPE_IPv4))) {
				++conf->stats.malformed;
				rte_pktmbuf_free(m);
				continue;
			}

		if (unlikely(m->ol_flags & (PKT_RX_IP_CKSUM_BAD|PKT_RX_L4_CKSUM_BAD))) {
			++conf->stats.bad_csum;
			rte_pktmbuf_free(m);
			continue;
		}

		ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
		/* Check to make sure the packet is valid (RFC1812) */
		ret = is_valid_ipv4_pkt(ipv4_hdr, m->pkt.data_len - sizeof(struct ether_hdr));
		if (unlikely(ret < 0)) {
			++conf->stats.malformed;
			rte_pktmbuf_free(m);
			continue;
		}

		flag_offset = rte_be_to_cpu_16(ipv4_hdr->fragment_offset);
		ip_ofs = (uint16_t)(flag_offset & IPV4_HDR_OFFSET_MASK);
		ip_flag = (uint16_t)(flag_offset & IPV4_HDR_MF_FLAG);
		if (unlikely(ip_flag != 0 || ip_ofs  != 0)) {
			++conf->stats.frags;
			rte_pktmbuf_free(m);
			continue;
		}

		if (unlikely(ipv4_hdr->next_proto_id != IPPROTO_TCP)) {
			++conf->stats.malformed;
			rte_pktmbuf_free(m);
			continue;
		}

		tcplen = rte_be_to_cpu_16(ipv4_hdr->total_length) -
					(ipv4_hdr->version_ihl & 0xf)*4;
		if (unlikely(tcplen < sizeof(struct tcp_hdr))) {
			++conf->stats.malformed;
			rte_pktmbuf_free(m);
			continue;
		}
		tcp_hdr = (struct tcp_hdr *)((unsigned char *)ipv4_hdr +
					(ipv4_hdr->version_ihl & 0xf)*4);
		if (unlikely(((tcp_hdr->data_off >> 2) < sizeof(struct tcp_hdr)) ||
					(tcplen < (tcp_hdr->data_off >> 2)))) {
			++conf->stats.malformed;
			rte_pktmbuf_free(m);
			continue;
		}

		tcpflags = (tcp_hdr->tcp_flags & ~(PRF_TCPHDR_ECE|PRF_TCPHDR_CWR|PRF_TCPHDR_PSH));
		if (unlikely(!prf_tcp_valid_flags[tcpflags])) {
			++conf->stats.bad_flags;
			rte_pktmbuf_free(m);
			continue;
		}
		pkt_out[j++] = m;
	}
	return j;
}

static int
primary_main_loop(void)
{
	struct rte_mbuf *pkts_burst[PRF_MAX_PKT_BURST];
	struct rte_mbuf *m;
	uint64_t diff_tsc, cur_tsc, prev_tsc;
	uint64_t prev_poll_tsc, diff_poll_tsc;
	int j, lcore_id, port_id, nb_rx;
	struct prf_lcore_conf *conf;
	const uint64_t drain_tsc = (prf_tsc_hz + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

	lcore_id = rte_lcore_id();
	conf = &prf_lcore_conf[lcore_id];
	prev_poll_tsc = prev_tsc = 0;

	while (1) {
		cur_tsc = rte_rdtsc();
		conf->timer = cur_tsc;

		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {
			for (port_id = 0; port_id < PRF_MAX_PORTS; port_id++) {
				if (conf->len[port_id] == 0)
					continue;
				send_burst(conf, conf->len[port_id], (uint8_t) port_id);
				conf->len[port_id] = 0;
			}
			prev_tsc = cur_tsc;
		}
		diff_poll_tsc = cur_tsc - prev_poll_tsc;
		if (unlikely(diff_poll_tsc < poll_tsc)) {
			continue;
		}
		for (port_id = 0; port_id < PRF_MAX_PORTS; port_id++) {
			nb_rx = rte_eth_rx_burst((uint8_t) port_id, conf->queue_id,
						pkts_burst, PRF_MAX_PKT_BURST);
			conf->stats.rx_pkts += nb_rx;
			for (j = 0; j < nb_rx; j++) {
				m = pkts_burst[j];
				prf_send_packet(m, conf, prf_dst_ports[port_id]);
			}
		}
		prev_poll_tsc = cur_tsc;
	}
	return 0;
}

static int
worker_main_loop(void)
{
	struct rte_mbuf *pkts_burst[PRF_MAX_PKT_BURST], *tcp_seg_arr[PRF_MAX_PKT_BURST];
	const uint8_t *acl_p[PRF_MAX_PKT_BURST];
	uint32_t result[PRF_MAX_PKT_BURST];
	const uint64_t drain_tsc = (prf_tsc_hz + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
	const uint64_t gc_int_tsc = (prf_tsc_hz + US_PER_S - 1) / US_PER_S * PRF_GC_INTERVAL;
	uint64_t diff_drain_tsc, diff_gc_tsc, cur_tsc, prev_drain_tsc, prev_gc_tsc;
	uint64_t prev_poll_tsc, diff_poll_tsc;
	int  cb, j, lcore_id, port_id, nb_rx;
	struct prf_lcore_conf *conf;

	lcore_id = rte_lcore_id();
	conf = &prf_lcore_conf[lcore_id];
	prev_poll_tsc = prev_drain_tsc = prev_gc_tsc = 0;

	while (1) {
		cur_tsc = rte_rdtsc();
		conf->timer = cur_tsc;

		diff_gc_tsc = cur_tsc - prev_gc_tsc;
		if (unlikely(diff_gc_tsc > gc_int_tsc)) {
			prf_ipv4_tcp_garbage_collect(conf, cur_tsc);
			prev_gc_tsc = cur_tsc;
		}

		diff_drain_tsc = cur_tsc - prev_drain_tsc;
		if (unlikely(diff_drain_tsc > drain_tsc)) {
			for (port_id = 0; port_id < PRF_MAX_PORTS; port_id++) {
				if (conf->len[port_id] == 0)
					continue;
				send_burst(conf, conf->len[port_id], (uint8_t) port_id);
				conf->len[port_id] = 0;
			}
			prev_drain_tsc = cur_tsc;
		}
		diff_poll_tsc = cur_tsc - prev_poll_tsc;
		if (unlikely(diff_poll_tsc < poll_tsc)) {
			continue;
		}
		for (port_id = 0; port_id < PRF_MAX_PORTS; port_id++) {
			nb_rx = rte_eth_rx_burst((uint8_t) port_id, conf->queue_id,
					pkts_burst, PRF_MAX_PKT_BURST);
			if (unlikely(nb_rx == 0))
				continue;
			conf->stats.rx_pkts += nb_rx;

			for (j = 0; j < nb_rx; j++) {
				rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));
			}

			nb_rx = tcp_sanity_check(pkts_burst, tcp_seg_arr, nb_rx, conf);
			nb_rx = prf_ipv4_tcp_conn_lookup_burst(conf, tcp_seg_arr,
					pkts_burst, nb_rx, cur_tsc);
			for (j = 0; j < nb_rx; j++) {
				acl_p[j] = MBUF_IPV4_2PROTO(pkts_burst[j]);
			}
			rte_acl_classify(acl_ctx, acl_p, result, nb_rx, 1);
			for (j = 0; j < nb_rx; j++) {
				cb = result[j] & PRF_ACL_ACTION_MASK;
				if (unlikely(cb >= PRF_MAX_ACTIONS)) {
					rte_pktmbuf_free(pkts_burst[j]);
					continue;
				}
				(*prf_acl_callbacks[cb])(pkts_burst[j], result[j], conf, cur_tsc);
			}
		}
		prev_poll_tsc = cur_tsc;
	}
	return 0;
}

/* main loop launcher*/
static int
main_loop_launcher(__attribute__((unused)) void *dummy)
{
	int lcore_id, ret = 0;
	struct prf_lcore_conf *conf;

	lcore_id = rte_lcore_id();
	conf = &prf_lcore_conf[lcore_id];
	switch (conf->core_role) {
	case PRIMARY_CORE:
		ret = primary_main_loop();
		break;
	case WORKER_CORE:
		ret = worker_main_loop();
		break;
	default:
		rte_exit(EXIT_FAILURE, "Invalid lcore role!\n");
	}
	return ret;
}

static void
init_nic(int prf_nb_fwd_cores) {
	int i, j, ret, nb_ports, portid;
	struct rte_eth_link link;
	struct rte_5tuple_filter filter;

	nb_ports = rte_eth_dev_count();
	if (nb_ports != PRF_MAX_PORTS)
		rte_exit(EXIT_FAILURE, "Invalid ethernet ports count - bye\n");

	/*init RSS*/
	for (i = 0; i < 40; i++) {
		switch (i & 0x3) {
		case 0:
			my_rss_key[i] = RSS_BYTE0;
			break;
		case 1:
			my_rss_key[i] = RSS_BYTE1;
			break;
		case 2:
			my_rss_key[i] = RSS_BYTE2;
			break;
		case 3:
			my_rss_key[i] = RSS_BYTE3;
			break;
		}
	}
	/*init RETA table*/
	for (i = 0, j = 1; i < 128; i++, j++) {
		if (j == prf_nb_fwd_cores)
			j = 1;
		reta_conf.reta[i] = j;
	}
	reta_conf.mask_lo = 0xffffffffffffffff;
	reta_conf.mask_hi = 0xffffffffffffffff;

	for (portid = 0; portid < nb_ports; portid++) {
		ret = rte_eth_dev_configure(portid, prf_nb_fwd_cores, prf_nb_fwd_cores, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n", ret, portid);

		rte_eth_macaddr_get(portid, &src_mac[portid]);

		for (i = 0; i < prf_nb_fwd_cores; i++) {
			ret = rte_eth_rx_queue_setup(portid, i, NB_RXD, PRF_SOCKET0, &rx_conf, prf_pktmbuf_pool);
				if (ret < 0)
					rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d\n", ret);
			ret = rte_eth_tx_queue_setup(portid, i, NB_TXD, PRF_SOCKET0, &tx_conf);
				if (ret < 0)
					rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d\n", ret);
		}

		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d\n", ret);

		ret = rte_eth_dev_rss_reta_update(portid, &reta_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "RETA Update fails on port %d\n", portid);

		memset(&filter, 0, sizeof(struct rte_5tuple_filter));
		filter.priority = 1;
		filter.protocol_mask = 0;
		filter.dst_ip_mask = 1;
		filter.src_ip_mask = 1;
		filter.dst_port_mask = 1;
		filter.src_port_mask = 1;

		filter.protocol = 0;
		ret = rte_eth_dev_add_5tuple_filter(portid, 1, &filter, 0);
		if (ret != 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_add_5tuple_filter: err=%d\n", ret);
		filter.protocol = IPPROTO_UDP;
		ret = rte_eth_dev_add_5tuple_filter(portid, 2, &filter, 0);
		if (ret != 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_add_5tuple_filter: err=%d\n", ret);
		filter.protocol = IPPROTO_SCTP;
		ret = rte_eth_dev_add_5tuple_filter(portid, 3, &filter, 0);
		if (ret != 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_add_5tuple_filter: err=%d\n", ret);

		rte_eth_promiscuous_enable(portid);
		rte_eth_link_get(portid, &link);
		if (link.link_status) {
			printf(" Link Up - speed %u Mbps - %s\n",
				(unsigned) link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
				("full-duplex") : ("half-duplex\n"));
		} else {
			printf(" Link Down\n");
		}
	}
}

int
MAIN(int argc, char **argv)
{
	int i, j, ret, nb_lcores, lcore_id;
	struct cmdline *cl;
	FILE *log_file;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	if (rte_eal_pci_probe() < 0)
		rte_exit(EXIT_FAILURE, "Cannot probe PCI\n");

	nb_lcores = rte_lcore_count();

	if ((nb_lcores > MAX_LCORES) || (nb_lcores < MIN_LCORES))
		rte_exit(EXIT_FAILURE, "Invalid lcores count\n");

	/*init in prf_lcore_conf core roles*/
	memset(prf_lcore_conf, 0, sizeof(struct prf_lcore_conf)*RTE_MAX_LCORE);
	prf_mastercore_id = rte_get_master_lcore();
	prf_lcore_conf[prf_mastercore_id].core_role = MASTER_CORE;
	prf_primarycore_id = rte_get_next_lcore(prf_mastercore_id, 1, 1);
	prf_lcore_conf[prf_primarycore_id].core_role = PRIMARY_CORE;
	prf_lcore_conf[prf_primarycore_id].queue_id = 0;
	j = 0;
	prf_nb_worker_cores = 0;
	RTE_LCORE_FOREACH_SLAVE(i) {
		if (i == prf_primarycore_id)
			continue;
		prf_lcore_conf[i].core_role = WORKER_CORE;
		prf_lcore_conf[i].queue_id = ++j;
		prf_nb_worker_cores++;
	}

	if (prf_nb_worker_cores == 0)
		rte_exit(EXIT_FAILURE, "No worker lcores - bye\n");
	prf_nb_fwd_cores = prf_nb_worker_cores + 1;

	/* Init memory */
	prf_pktmbuf_pool = rte_mempool_create("mbuf_pool", NB_MBUF, MBUF_SIZE,
					PRF_MEMPOOL_CACHE_SIZE,
					sizeof(struct rte_pktmbuf_pool_private),
					rte_pktmbuf_pool_init, NULL,
					rte_pktmbuf_init, NULL,
					PRF_SOCKET0, 0);
	if (prf_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	prf_tcp_ent_pool = rte_mempool_create("prf_tcp_ent_pool", PRF_NB_TCP_ENT,
					sizeof(struct prf_tcp_ent), 32,
					0, NULL, NULL, NULL, NULL, PRF_SOCKET0, 0);

	if (prf_tcp_ent_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init prf_tcp_ent pool\n");

	prf_src_track_pool = rte_mempool_create("prf_src_track_pool", PRF_NB_SRC_TRACK_ENT,
					sizeof(struct prf_src_track_ent), 32,
					0, NULL, NULL, NULL, NULL, PRF_SOCKET0, 0);

	if (prf_src_track_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init src_track pool\n");

	RTE_LCORE_FOREACH_SLAVE(i) {
		if (i == prf_primarycore_id)
			continue;
		prf_lcore_conf[i].tcp_hash = prf_ipv4_tcp_hash_init(i);
		if (prf_lcore_conf[i].tcp_hash == NULL)
			rte_exit(EXIT_FAILURE, "TCP_hash_create on core %d failed\n", i);
		printf("Init TCP_Hash on core %d\n", i);
	}

	init_nic(prf_nb_fwd_cores);

	prf_dst_ports[0] = 1;
	prf_dst_ports[1] = 0;
	prf_syn_proxy_secret[0] = (uint32_t)rte_rand();
	prf_syn_proxy_secret[1] = (uint32_t)rte_rand();
	prf_tsc_hz = rte_get_tsc_hz();
	prf_embrionic_threshold = 2000;

	poll_tsc = (prf_tsc_hz + US_PER_S - 1) / (US_PER_S * prf_nb_worker_cores) * RX_POLL_US;
	printf("Poll TSC %"PRIu64"\n", poll_tsc);

	/*init timer table*/
	prf_tcp_timer_table[PRF_TCP_STATE_SYN_SENT]	= prf_tsc_hz * 20;
	prf_tcp_timer_table[PRF_TCP_STATE_SYN_RCV]	= prf_tsc_hz * 20;
	prf_tcp_timer_table[PRF_TCP_STATE_ESTABL]	= prf_tsc_hz * 1800;
	prf_tcp_timer_table[PRF_TCP_STATE_FIN_WAIT]	= prf_tsc_hz * 120;
	prf_tcp_timer_table[PRF_TCP_STATE_CLOSE_WAIT]	= prf_tsc_hz * 120;
	prf_tcp_timer_table[PRF_TCP_STATE_LAST_ACK]	= prf_tsc_hz * 120;
	prf_tcp_timer_table[PRF_TCP_STATE_TIME_WAIT]	= prf_tsc_hz * 120;

	prf_init_acl_config();
	/*init fake acl context*/
	prf_build_empty_acl(&acl_ctx);
	log_file = fopen("log_file.log", "a+");
	rte_openlog_stream(log_file);

	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(main_loop_launcher, NULL, SKIP_MASTER);
	cl = cmdline_stdin_new(main_ctx, "ololo> ");
	if (cl == NULL)
		rte_panic("Cannot create cmdline instance\n");
	cmdline_interact(cl);
	cmdline_stdin_exit(cl);

	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}
	return 0;
}
