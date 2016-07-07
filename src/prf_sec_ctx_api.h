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

#ifndef _PRF_SEC_CTX_API_H_
#define _PRF_SEC_CTX_API_H_

struct prf_tcpopts;

uint8_t prf_compress_opt(struct prf_tcpopts *options);

uint32_t prf_synproxy_hash(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport, uint32_t count, int c);

uint32_t prf_synproxy_cookie_get(uint32_t saddr, uint32_t daddr, uint16_t sport,
					uint32_t dport, uint32_t sseq, uint32_t count, uint32_t data);

int prf_synproxy_cookie(uint32_t cookie, uint32_t saddr, uint32_t daddr,
				uint16_t sport, uint16_t dport, uint32_t sseq,
				uint32_t count, uint32_t maxdiff);

inline int prf_synproxy_cookie_check(struct ipv4_hdr *iph, struct tcp_hdr *th, uint32_t time_min, struct prf_tcpopts *options);

int prf_src_track_node_add(struct prf_src_track_hash *hash_table, uint32_t key, struct prf_src_track_node **node);

int prf_src_track_node_del(struct prf_src_track_hash *hash_table, uint32_t key);

int prf_src_track_node_lookup(struct prf_src_track_hash *hash_table, uint32_t key, struct prf_src_track_node **node);

int prf_src_track_rate_check(struct prf_src_track_node *node, struct prf_sec_ctx_rule *rule, uint64_t time);

int prf_src_track_checkout(struct prf_sec_ctx_rule *rule, uint32_t key, uint64_t time, struct prf_src_track_node **node);

int prf_ipset_lookup(struct prf_ipset_hash *hash, uint32_t key, uint64_t time);

int prf_ipset_add(struct prf_ipset_hash *hash, uint32_t key, uint64_t time);

#endif /* _PRF_SEC_CTX_API_H_ */
