/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Microsoft Corporation
 * All rights reserved.
 */

#include <arpa/inet.h>          // for inet_ntop
#include <netinet/in.h>         // for ntohs, INET6_ADDRSTRLEN, IPPROTO_GRE
#include <rte_arp.h>            // for rte_arp_hdr, RTE_ARP_OP_REPLY, RTE_AR...
#include <rte_byteorder.h>      // for rte_be_to_cpu_16, rte_be_to_cpu_32
#include <rte_cycles.h>
#include <rte_ether.h>          // for rte_ether_hdr, rte_ether_format_addr
#include <rte_gre.h>            // for rte_gre_hdr
#include <rte_ip.h>             // for rte_ipv6_hdr, rte_ipv4_hdr, RTE_IPV4_...
#include <rte_mbuf.h>		// for rte_mbuf, ...
#include <rte_udp.h>            // for rte_udp_hdr
#include <rte_vxlan.h>          // for rte_vxlan_hdr
#include <stdint.h>             // for uint8_t, uint32_t, uint16_t
#include <stdio.h>              // for printf, snprintf, size_t
#include <sys/socket.h>         // for AF_INET, AF_INET6

#include "pkt_dump.h"

#define VXLAN_PORT 4789

static void pkt_decode(const struct rte_ether_hdr *eh);

static const char *ip_proto(uint16_t proto)
{
	static char buf[32];

	switch (proto) {
	case IPPROTO_ICMP: return "ICMP";
	case IPPROTO_TCP:  return "TCP";
	case IPPROTO_UDP:  return "UDP";
	case IPPROTO_SCTP:  return "SCP";
	case IPPROTO_GRE: return "GRE";
	default:
		snprintf(buf, sizeof(buf), "[%#x]", proto);
		return buf;
	}
}

static void vxlan_decode(const struct rte_vxlan_hdr *vxlan)
{
	uint32_t vni = rte_be_to_cpu_32(vxlan->vx_vni) >> 8;

	printf(" VXLAN %u ", vni);
	pkt_decode((const struct rte_ether_hdr *)(vxlan + 1));
}

static void gre_decode(const void *p)
{
	const struct rte_gre_hdr *gre = p;

	if (gre->proto == htons(0x6558)) {
		printf(" NVGRE");
	} else {
		printf(" GRE[%#x]", ntohs(gre->proto));
		return;
	}

	p = gre + 1;
	if (gre->c) {
		/* decode checksum? */
	}

	if (gre->k) {
		const uint32_t *key = p;
		uint32_t id = ntohl(*key);

		printf(" %#x:%x ", id >> 8, id & 0xff);
		p = key + 1;
	}

	if (gre->s) {
		/* sequence number */
	}

	pkt_decode(p);
}

static void pkt_decode(const struct rte_ether_hdr *eh)
{
	char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];

	rte_ether_format_addr(src_str, sizeof(src_str), &eh->s_addr);
	rte_ether_format_addr(dst_str, sizeof(dst_str), &eh->d_addr);
	printf("%s → %s ", src_str, dst_str);

	switch (rte_be_to_cpu_16(eh->ether_type)) {
	case RTE_ETHER_TYPE_IPV4: {
		const struct rte_ipv4_hdr *ip
			= (const struct rte_ipv4_hdr *)(eh + 1);
		size_t hlen;

		hlen = (ip->version_ihl & RTE_IPV4_HDR_IHL_MASK)
			* RTE_IPV4_IHL_MULTIPLIER;

		inet_ntop(AF_INET, &ip->src_addr, src_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &ip->dst_addr, dst_str, INET_ADDRSTRLEN);
		printf("%s → %s ", src_str, dst_str);

		if (ip->next_proto_id == IPPROTO_UDP) {
			const struct rte_udp_hdr *udp;

			udp = (const struct rte_udp_hdr *)
				((const uint8_t *)ip + hlen);
			if (ntohs(udp->dst_port) == VXLAN_PORT) {
				vxlan_decode((const struct rte_vxlan_hdr *)(udp +1));
				return;
			}
		}
		if (ip->next_proto_id == IPPROTO_GRE) {
			gre_decode((const uint8_t *)ip + hlen);
			return;
		}
		printf("%s", ip_proto(ip->next_proto_id));
		break;
	}

	case RTE_ETHER_TYPE_IPV6: {
		const struct rte_ipv6_hdr *ip6
			= (const struct rte_ipv6_hdr *)(eh + 1);

		inet_ntop(AF_INET6, &ip6->src_addr, src_str, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &ip6->dst_addr, dst_str, INET6_ADDRSTRLEN);
		printf("%s → %s ", src_str, dst_str);

		if (ip6->proto == IPPROTO_UDP) {
			const struct rte_udp_hdr *udp;

			udp = (const struct rte_udp_hdr *)(ip6 + 1);
			if (ntohs(udp->dst_port) == VXLAN_PORT) {
				vxlan_decode((const struct rte_vxlan_hdr *)(udp +1));
				return;
			}
		}
		if (ip6->proto == IPPROTO_GRE) {
			gre_decode((const uint8_t *)(ip6 + 1));
			return;
		}

		printf("%s", ip_proto(ip6->proto));
		break;
	}

	case RTE_ETHER_TYPE_ARP: {
		const struct rte_arp_hdr *ah
			= (const struct rte_arp_hdr *)(eh + 1);
		uint16_t op = rte_be_to_cpu_16(ah->arp_opcode);

		printf("ARP %s",
			 op == RTE_ARP_OP_REQUEST ? "REQ" :
			 op == RTE_ARP_OP_REPLY ? "REPLY" : "???");
		break;
	}
	default:
		printf("type %#x", ntohs(eh->ether_type));
	}
}

void pkt_print(const struct rte_mbuf *m)
{
	const struct rte_ether_hdr *eh;

	eh = rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);
	if (m->ol_flags & PKT_RX_VLAN_STRIPPED)
		printf("{%u} ", m->vlan_tci);

	pkt_decode(eh);
	printf(" length %u\n", m->pkt_len);
}
