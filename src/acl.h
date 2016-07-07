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

#ifndef _ACL_H_
#define _ACL_H_

#include <rte_acl.h>

struct lcore_conf;

#define ACL_NAME			32

#define ACL_MAX_ACTIONS_BITS		3
#define ACL_MAX_ACTIONS			(1 << ACL_MAX_ACTIONS_BITS)
#define ACL_ACTION_MASK			(ACL_MAX_ACTIONS - 1)

#define ACL_MAX_SEC_CTX_BITS		3
#define ACL_MAX_SEC_CTX		(1 << ACL_MAX_SEC_CTX_BITS)
#define ACL_SEC_CTX_RESULT_MASK	(ACL_MAX_SEC_CTX - 1)
#define ACL_SEC_CTX_RESULT_SHIFT	ACL_MAX_ACTIONS_BITS

#define ACL_MAX_RULES_BITS		10
#define ACL_MAX_RULES			(1 << ACL_MAX_RULES_BITS)
#define ACL_RESULT_RULE_MASK		(ACL_MAX_RULES - 1)
#define ACL_RESULT_RULE_SHIFT		(ACL_SEC_CTX_RESULT_SHIFT + ACL_MAX_SEC_CTX_BITS)

#define DEFAULT_MAX_CATEGORIES		1

enum {
	DEFAULT_POLICY = 0,
	DROP,
	ACCEPT,
	REJECT,
	NO_TRACK,
	SEC_CTX,
	MAX_ACTIONS
};

extern struct rte_acl_ctx *acl_ctx;
extern int acl_version;
extern struct rte_acl_param acl_param;
extern struct rte_acl_config acl_build_param;

typedef void (*acl_callback_fn_t)(struct rte_mbuf *m, uint32_t result, struct lcore_conf *conf, uint64_t time);

void acl_drop(struct rte_mbuf *m, uint32_t result, struct lcore_conf *conf, uint64_t time);

void acl_accept(struct rte_mbuf *m, uint32_t result, struct lcore_conf *conf, uint64_t time);

void acl_reject(struct rte_mbuf *m, uint32_t result, struct lcore_conf *conf, uint64_t time);

void acl_no_track(struct rte_mbuf *m, uint32_t result, struct lcore_conf *conf, uint64_t time);

void acl_sec_ctx(struct rte_mbuf *m, uint32_t result, struct lcore_conf *conf, uint64_t time);

void init_acl_config(void);

int acl_create(struct rte_acl_rule *acl_rules, int acl_num, struct rte_acl_ctx **ctx);

void build_empty_acl(struct rte_acl_ctx **ctx);

extern acl_callback_fn_t acl_callbacks[];

enum {
	PROTO_FIELD_IPV4,
	SRC_FIELD_IPV4,
	DST_FIELD_IPV4,
	SRCP_FIELD_IPV4,
	DSTP_FIELD_IPV4,
	NUM_FIELDS_IPV4
};

RTE_ACL_RULE_DEF(acl4_rule, NUM_FIELDS_IPV4);

#endif
