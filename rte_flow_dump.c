/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Microsoft Corporation
 * All rights reserved.
 */

#include <stdio.h>
#include <rte_flow.h>

#include "rte_flow_dump.h"

void
rte_flow_attr_dump(FILE *f,
		   const struct rte_flow_attr *attr)
{
	fprintf(f, "Flow attr group %u priority %u%s%s%s\n",
		attr->group, attr->priority,
		attr->ingress ? " ingress" : "",
		attr->egress ? " egress" : "",
		attr->transfer ? " transfer" : "");
}

static const char *rte_flow_item_names[] = {
	[RTE_FLOW_ITEM_TYPE_END]	 = "END",
	[RTE_FLOW_ITEM_TYPE_VOID]	= "VOID",
	[RTE_FLOW_ITEM_TYPE_INVERT]	= "INVERT",
	[RTE_FLOW_ITEM_TYPE_ANY]	= "ANY",
	[RTE_FLOW_ITEM_TYPE_PF]		= "PF",
	[RTE_FLOW_ITEM_TYPE_VF]		= "VF",
	[RTE_FLOW_ITEM_TYPE_PHY_PORT]	= "PHY_PORT",
	[RTE_FLOW_ITEM_TYPE_PORT_ID]	= "PORT_ID",
	[RTE_FLOW_ITEM_TYPE_RAW]	= "RAW",
	[RTE_FLOW_ITEM_TYPE_ETH]	= "ETH",
	[RTE_FLOW_ITEM_TYPE_VLAN]	= "VLAN",
	[RTE_FLOW_ITEM_TYPE_IPV4]	= "IPV4",
	[RTE_FLOW_ITEM_TYPE_IPV6]	= "IPV6",
	[RTE_FLOW_ITEM_TYPE_ICMP]	= "ICMP",
	[RTE_FLOW_ITEM_TYPE_UDP]	= "UDP",
	[RTE_FLOW_ITEM_TYPE_TCP]	= "TCP",
	[RTE_FLOW_ITEM_TYPE_SCTP]	= "SCTP",
	[RTE_FLOW_ITEM_TYPE_VXLAN]	= "VXLAN",
	[RTE_FLOW_ITEM_TYPE_E_TAG]	= "E_TAG",
	[RTE_FLOW_ITEM_TYPE_NVGRE]	= "NVGRE",
	[RTE_FLOW_ITEM_TYPE_MPLS]	= "MPLS",
	[RTE_FLOW_ITEM_TYPE_GRE]	= "GRE",
	[RTE_FLOW_ITEM_TYPE_FUZZY]	= "FUZZY",
	[RTE_FLOW_ITEM_TYPE_GTP]	= "GTP",
	[RTE_FLOW_ITEM_TYPE_GTPC]	= "GTPC",
	[RTE_FLOW_ITEM_TYPE_GTPU]	= "GTPU",
	[RTE_FLOW_ITEM_TYPE_ESP]	= "ESP",
	[RTE_FLOW_ITEM_TYPE_GENEVE]	= "GENEVE",
	[RTE_FLOW_ITEM_TYPE_VXLAN_GPE]	= "VXLAN_GPE",
	[RTE_FLOW_ITEM_TYPE_ARP_ETH_IPV4] = "ARP_ETH_IPV4",
	[RTE_FLOW_ITEM_TYPE_IPV6_EXT]	= "IPV6_EXT",
	[RTE_FLOW_ITEM_TYPE_ICMP6]	= "ICMP6",
	[RTE_FLOW_ITEM_TYPE_ICMP6_ND_NS] = "ICMP6_ND_NS",
	[RTE_FLOW_ITEM_TYPE_ICMP6_ND_NA] = "ICMP6_ND_NA",
	[RTE_FLOW_ITEM_TYPE_ICMP6_ND_OPT] = "ICMP6_ND_OPT",
	[RTE_FLOW_ITEM_TYPE_ICMP6_ND_OPT_SLA_ETH] = "ICMP6_ND_OPT_SLA_ETH",
	[RTE_FLOW_ITEM_TYPE_ICMP6_ND_OPT_TLA_ETH] = "ICMP6_ND_OPT_TLA_ETH",
	[RTE_FLOW_ITEM_TYPE_MARK]	= "MARK",
	[RTE_FLOW_ITEM_TYPE_META]	= "META",
};

static void
flow_item_any_dump(FILE *f, const char *prefix,
		   const struct rte_flow_item_any *a)
{
	if (a)
		fprintf(f, "\t  %s %u\n", prefix, a->num);
}

static void
flow_item_eth_dump(FILE *f, const char *prefix,
		   const struct rte_flow_item_eth *e)
{
	char b1[RTE_ETHER_ADDR_FMT_SIZE];
	char b2[RTE_ETHER_ADDR_FMT_SIZE];

	if (!e)
		return;

	rte_ether_format_addr(b1, sizeof(b1), &e->dst);
	rte_ether_format_addr(b2, sizeof(b2), &e->src);
	fprintf(f, "\t  %s dst %s src %s type %u\n",
		prefix, b1, b2, ntohs(e->type));
}

void
rte_flow_item_dump(FILE *f,
		   const struct rte_flow_item *pattern)
{
	fprintf(f, "%s\n",
		rte_flow_item_names[pattern->type]);

	switch (pattern->type) {
	case RTE_FLOW_ITEM_TYPE_ANY:
		flow_item_any_dump(f, "Spec", pattern->spec);
		flow_item_any_dump(f, "Mask", pattern->mask);
		break;
	case RTE_FLOW_ITEM_TYPE_ETH:
		flow_item_eth_dump(f, "Spec", pattern->spec);
		flow_item_eth_dump(f, "Mask", pattern->mask);
		break;
	default:
		fprintf(f, "spec %p mask %p last %p\n",
			pattern->spec, pattern->mask, pattern->last);
		/* fall through */
	case RTE_FLOW_ITEM_TYPE_END:
		break;
	}
}

static const char *rte_flow_action_names[] = {
	[RTE_FLOW_ACTION_TYPE_END] = "END",
	[RTE_FLOW_ACTION_TYPE_VOID] = "VOID",
	[RTE_FLOW_ACTION_TYPE_PASSTHRU] = "PASSTHRU",
	[RTE_FLOW_ACTION_TYPE_JUMP] = "JUMP",
	[RTE_FLOW_ACTION_TYPE_MARK] = "MARK",
	[RTE_FLOW_ACTION_TYPE_FLAG] = "FLAG",
	[RTE_FLOW_ACTION_TYPE_QUEUE] = "QUEUE",
	[RTE_FLOW_ACTION_TYPE_DROP] = "DROP",
	[RTE_FLOW_ACTION_TYPE_COUNT] = "COUNT",
	[RTE_FLOW_ACTION_TYPE_RSS] = "RSS",
	[RTE_FLOW_ACTION_TYPE_PF] = "PF",
	[RTE_FLOW_ACTION_TYPE_VF] = "VF",
	[RTE_FLOW_ACTION_TYPE_PHY_PORT] = "PHY_PORT",
	[RTE_FLOW_ACTION_TYPE_PORT_ID] = "PORT_ID",
	[RTE_FLOW_ACTION_TYPE_METER] = "METER",
	[RTE_FLOW_ACTION_TYPE_SECURITY] = "SECURITY",
	[RTE_FLOW_ACTION_TYPE_OF_SET_MPLS_TTL] = "OF_SET_MPLS_TTL",
	[RTE_FLOW_ACTION_TYPE_OF_DEC_MPLS_TTL] = "OF_DEC_MPLS_TTL",
	[RTE_FLOW_ACTION_TYPE_OF_SET_NW_TTL] = "OF_SET_NW_TTL",
	[RTE_FLOW_ACTION_TYPE_OF_DEC_NW_TTL] = "OF_DEC_NW_TTL",
	[RTE_FLOW_ACTION_TYPE_OF_COPY_TTL_OUT] = "OF_COPY_TTL_OUT",
	[RTE_FLOW_ACTION_TYPE_OF_COPY_TTL_IN] = "OF_COPY_TTL_IN",
	[RTE_FLOW_ACTION_TYPE_OF_POP_VLAN] = "OF_POP_VLAN",
	[RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN] = "OF_PUSH_VLAN",
	[RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID] = "OF_SET_VLAN_VID",
	[RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP] = "OF_SET_VLAN_PCP",
	[RTE_FLOW_ACTION_TYPE_OF_POP_MPLS] = "OF_POP_MPLS",
	[RTE_FLOW_ACTION_TYPE_OF_PUSH_MPLS] = "OF_PUSH_MPLS",
	[RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP] = "VXLAN_ENCAP",
	[RTE_FLOW_ACTION_TYPE_VXLAN_DECAP] = "VXLAN_DECAP",
	[RTE_FLOW_ACTION_TYPE_NVGRE_ENCAP] = "NVGRE_ENCAP",
	[RTE_FLOW_ACTION_TYPE_NVGRE_DECAP] = "NVGRE_DECAP",
	[RTE_FLOW_ACTION_TYPE_RAW_ENCAP] = "RAW_ENCAP",
	[RTE_FLOW_ACTION_TYPE_RAW_DECAP] = "RAW_DECAP",
	[RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC] = "SET_IPV4_SRC",
	[RTE_FLOW_ACTION_TYPE_SET_IPV4_DST] = "SET_IPV4_DST",
	[RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC] = "SET_IPV6_SRC",
	[RTE_FLOW_ACTION_TYPE_SET_IPV6_DST] = "SET_IPV6_DST",
	[RTE_FLOW_ACTION_TYPE_SET_TP_SRC] = "SET_TP_SRC",
	[RTE_FLOW_ACTION_TYPE_SET_TP_DST] = "SET_TP_DST",
	[RTE_FLOW_ACTION_TYPE_MAC_SWAP] = "MAC_SWAP",
	[RTE_FLOW_ACTION_TYPE_DEC_TTL] = "DEC_TTL",
	[RTE_FLOW_ACTION_TYPE_SET_TTL] = "SET_TTL",
	[RTE_FLOW_ACTION_TYPE_SET_MAC_SRC] = "SET_MAC_SRC",
	[RTE_FLOW_ACTION_TYPE_SET_MAC_DST] = "SET_MAC_DST",
};

void
rte_flow_action_dump(FILE *f,
		     const struct rte_flow_action *action)
{
	fprintf(f, "%s", rte_flow_action_names[action->type]);

	switch (action->type) {
	case RTE_FLOW_ACTION_TYPE_MARK: {
		const struct rte_flow_action_mark *m = action->conf;
		fprintf(f, " id %u", m->id);
		break;
	}
	case RTE_FLOW_ACTION_TYPE_JUMP: {
		const struct rte_flow_action_jump *j = action->conf;
		fprintf(f, " group %u", j->group);
		break;
	}
	case RTE_FLOW_ACTION_TYPE_QUEUE: {
		const struct rte_flow_action_queue *q = action->conf;
		fprintf(f, " index %u", q->index);
		break;
	}
	case RTE_FLOW_ACTION_TYPE_COUNT: {
		const struct rte_flow_action_count *c = action->conf;

		fprintf(f, " count %u%s", c->id, c->shared ? " shared" : "");
		break;
	}
	case RTE_FLOW_ACTION_TYPE_RSS: {
		const struct rte_flow_action_rss *rss = action->conf;
		uint32_t i;

		fprintf(f, " level %u types %#"PRIx64" [",
			rss->level, rss->types);
		for (i = 0; i < rss->queue_num; i++)
			fprintf(f, " %u", rss->queue[i]);
		putc(']', f);
		if (rss->key_len > 0) {
			fprintf(f, " key [");

			for (i = 0; i < rss->key_len; i++)
				fprintf(f, "%02x", rss->key[i]);
			putc(']', f);
		}
		break;
	}
	default:
		break;
	}
	fprintf(f, "\n");
}

void
rte_flow_dump(FILE *f,
	      const struct rte_flow_attr *attr,
	      const struct rte_flow_item pattern[],
	      const struct rte_flow_action actions[])
{
	int i;

	rte_flow_attr_dump(f, attr);

	i = 0;
	do {
		putc('\t', f);
		rte_flow_item_dump(f, &pattern[i]);
	} while (pattern[i++].type != RTE_FLOW_ITEM_TYPE_END);

	i = 0;
	fprintf(f, "Action\n");
	do {
		putc('\t', f);
		rte_flow_action_dump(f, &actions[i]);
	} while (actions[i++].type != RTE_FLOW_ACTION_TYPE_END);
}
