/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Microsoft Corporation
 * All rights reserved.
 */

#include <stdio.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_ether.h>

#include "pkt_dump.h"

static uint32_t pktno;
static uint64_t start;

static uint64_t time_monotonic(void)
{
	struct timespec ts;
	uint64_t ns;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	ns = ts.tv_sec * NS_PER_S + ts.tv_nsec;

	if (start)
		return ns - start;
	start = ns;
	return 0;
}

static const char *ip_proto(uint16_t proto)
{
	static char buf[32];
	
	switch (proto) {
	case IPPROTO_ICMP: return "ICMP";
	case IPPROTO_TCP:  return "TCP";
	case IPPROTO_UDP:  return "UDP";
	case IPPROTO_SCTP:  return "SCP";
	default:
		snprintf(buf, sizeof(buf), "[%#x]", proto);
		return buf;
	}
}
		
void pkt_print(const struct rte_mbuf *m)
{
	uint64_t us = time_monotonic() / 1000;
	const struct ether_hdr *eh
		= rte_pktmbuf_mtod(m, const struct ether_hdr *);
	char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
	char proto[64];

	snprintf(proto, sizeof(proto), "%#x", ntohs(eh->ether_type));

	switch (ntohs(eh->ether_type)) {
	case ETHER_TYPE_IPv4: {
		const struct ipv4_hdr *ip
			= (const struct ipv4_hdr *)(eh + 1);
		inet_ntop(AF_INET, &ip->src_addr,
			  src_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &ip->dst_addr,
			  dst_str, INET_ADDRSTRLEN);

		strcpy(proto, ip_proto(ip->next_proto_id));
		break;
	}

	case ETHER_TYPE_IPv6: {
		const struct ipv6_hdr *ip6
			= (const struct ipv6_hdr *)(eh + 1);

		inet_ntop(AF_INET6, &ip6->src_addr,
			  src_str, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &ip6->dst_addr,
			  dst_str, INET6_ADDRSTRLEN);
		strcpy(proto, ip_proto(ip6->proto));
		break;
	}

	case ETHER_TYPE_ARP:
		strcpy(proto, "ARP");
		/* fallthrough */
	default:
		ether_format_addr(src_str, ETHER_ADDR_FMT_SIZE, &eh->s_addr);
		ether_format_addr(dst_str, ETHER_ADDR_FMT_SIZE, &eh->d_addr);
	}

	printf("%-6u %"PRId64".%06"PRId64,
	       ++pktno, us / US_PER_S, us % US_PER_S);

	if (m->ol_flags & PKT_RX_VLAN_STRIPPED)
		printf(" {%u}", m->vlan_tci);

	printf(" %s → %s %s, length %u\n",	       
	       src_str, dst_str, proto, m->pkt_len);
}
