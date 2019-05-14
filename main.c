/*
 * Demo rte_flow default rule
 * Copyright(c) 2019 Microsoft Corporation
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <unistd.h>

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_flow.h>

#define NUM_MBUFS 131071
#define MEMPOOL_CACHE 256
#define MAX_QUEUES 64
#define RX_DESC_DEFAULT	   256
#define TX_DESC_DEFAULT	   512
#define MAX_PKT_BURST 32
//#define RSS_WORKS	1
#define DST_FILTER	1

#define VNIC_RSS_HASH_TYPES \
	(ETH_RSS_IPV4 | ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP | \
	 ETH_RSS_IPV6 | ETH_RSS_NONFRAG_IPV6_TCP | ETH_RSS_NONFRAG_IPV6_UDP)

static struct rte_mempool *mb_pool;

static const struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode	= ETH_MQ_RX_NONE,
		.max_rx_pkt_len = ETHER_MAX_LEN,
		.offloads	= DEV_RX_OFFLOAD_VLAN_STRIP
				| DEV_RX_OFFLOAD_CHECKSUM,
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
		.offloads = DEV_TX_OFFLOAD_VLAN_INSERT
				| DEV_TX_OFFLOAD_IPV4_CKSUM
				| DEV_TX_OFFLOAD_TCP_CKSUM
				| DEV_TX_OFFLOAD_UDP_CKSUM,
	},
};


static void port_config(uint16_t portid)
{
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	uint16_t nrxq, ntxq;
	uint16_t nb_rxd = RX_DESC_DEFAULT;
	uint16_t nb_txd = TX_DESC_DEFAULT;
	uint16_t q;
	int r;

	rte_eth_dev_info_get(portid, &dev_info);

	nrxq = RTE_MIN(MAX_QUEUES, dev_info.max_rx_queues);
	ntxq = rte_lcore_count();

	r = rte_eth_dev_configure(portid, nrxq, ntxq, &port_conf);
	if (r < 0)
		rte_exit(EXIT_FAILURE,
			 "Cannot configure device: err=%d port=%u\n",
			 r, portid);

	r = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
	if (r < 0)
		rte_exit(EXIT_FAILURE,
			 "Cannot adjust number of descriptors: err=%d, port=%d\n",
			 r, portid);

	txq_conf = dev_info.default_txconf;
	rxq_conf = dev_info.default_rxconf;

	txq_conf.offloads = port_conf.txmode.offloads;
	rxq_conf.rx_drop_en = 1;
	//rxq_conf.rx_deferred_start = 1;
	rxq_conf.offloads = port_conf.rxmode.offloads;

	for (q = 0; q < ntxq; q++) {
		r = rte_eth_tx_queue_setup(portid, q, nb_txd, 0, &txq_conf);
		if (r < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_tx_queue_setup failed %d\n",
				 r);
	}

	for (q = 0; q < nrxq; q++) {
		r = rte_eth_rx_queue_setup(portid, q, nb_rxd, 0, &rxq_conf,
					   mb_pool);
		if (r < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_rx_queue_setup failed %d\n",
				 r);
	}
	rte_eth_dev_start(portid);

	for (q = 1; q < nrxq; q++)
		r = rte_eth_dev_rx_queue_stop(portid, q);
}

static void flow_configure(uint16_t portid, uint16_t nq)
{
	/* flow only applies to ingress */
	struct rte_flow_attr attr  = {
		.ingress = 1,
#ifdef DST_FILTER
		//.priority = 65536,
#endif
		.group = 16,
	};
	struct rte_flow_item_eth eth_zero = {
#ifdef DST_FILTER
		//.dst.addr_bytes = "\0\xc0\x1d\xc0\xff\xee",
		.dst.addr_bytes = "\0\xc0\xff\xee\xbe\x11",
		.src.addr_bytes = "\0\0\0\0\0\0",
#else
		.dst.addr_bytes = "\0\0\0\0\0\0",
		.src.addr_bytes = "\0\xc0\x01\xc0\xff\xee",
#endif
		.type = RTE_BE16(0x0800),
	};
	struct rte_flow_item_eth eth_mask = {
#ifdef DST_FILTER
		.dst.addr_bytes = "\xff\xff\xff\xff\xff\xff",
		.src.addr_bytes = "\0\0\0\0\0\0",
#else
		.dst.addr_bytes = "\0\0\0\0\0\0",
		.src.addr_bytes = "\xff\xff\xff\xff\xff\xff",
#endif
		.type = RTE_BE16(0x0000),
	};
	struct rte_flow_item pattern[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = &eth_zero,
			.mask = &eth_mask,
		},
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};
#ifdef RSS_WORKS
	uint16_t rss_queues[nq];
	struct rte_flow_action_rss act_rss = {
		.types = VNIC_RSS_HASH_TYPES,
		.queue_num = nq,
		.queue = rss_queues,
	};
#else
	struct rte_flow_action_queue act_queue = {
		.index = nq/nq, /* helps avoid __rte_unused */
	};
#endif
	struct rte_flow_action actions[] = {
#ifdef RSS_WORKS
		{
			.type = RTE_FLOW_ACTION_TYPE_RSS,
			.conf = &act_rss,
		},
#else
		{
			.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &act_queue,
		},
#endif
		{ .type = RTE_FLOW_ACTION_TYPE_END  },
	};
	struct rte_flow_error err;
	int r;

#ifdef RSS_WORKS
	unsigned int i;
	/* We do not want to use RxQ 0 for filters. */
	for (i = 1; i < 5; i++)
		rss_queues[i-1] = i;
#endif

#ifdef DST_FILTER
	printf("flow-demo: Creating Destination MAC filter!!\n");
#else
	printf("flow-demo: Creating Source MAC filter!!\n");
#endif
#ifdef RSS_WORKS
	printf("flow-demo: Creating MAC filter with RSS action!!\n");
#else
	printf("flow-demo: Creating MAC filter with QUEUE action!!\n");
#endif
	r = rte_flow_validate(portid, &attr, pattern, actions, &err);
	if (r < 0)
		rte_exit(EXIT_FAILURE,
			 "flow validate failed: %s\n error type %u %s\n",
			 rte_strerror(rte_errno), err.type, err.message);

	if (rte_flow_create(portid, &attr, pattern, actions, &err) == NULL)
		rte_exit(EXIT_FAILURE,
			 "flow create failed: %s\n error type %u %s\n",
			 rte_strerror(rte_errno), err.type, err.message);
#ifdef RSS_WORKS
	for (i = 1; i < 5; i++)
		r = rte_eth_dev_rx_queue_start(portid, i);
#else
	r = rte_eth_dev_rx_queue_start(portid, nq/nq);
#endif
}

static int
dump_rx_pkt(void *dummy __rte_unused)
{
	uint16_t q = rte_lcore_id();

	for(;;) {
		struct rte_mbuf *pkts[MAX_PKT_BURST];
		uint16_t i, n;

		n = rte_eth_rx_burst(0, q, pkts, MAX_PKT_BURST);
		if (n == 0) {
			sleep(1);
			continue;
		}

		for (i = 0; i < n; i++) {
			struct rte_mbuf *m = pkts[i];
			const struct ether_hdr *eh;
			char dst[ETHER_ADDR_FMT_SIZE], src[ETHER_ADDR_FMT_SIZE];

			eh = rte_pktmbuf_mtod(m, struct ether_hdr *);
			ether_format_addr(src, sizeof(src), &eh->s_addr);
			ether_format_addr(dst, sizeof(dst), &eh->d_addr);
			printf("[%u] %s %s %x ..%u\n",
			       q, dst, src, ntohs(eh->ether_type),
			       rte_pktmbuf_pkt_len(m));
			rte_pktmbuf_free(m);
		}
	}

	return 0;
}

static void print_mac(uint16_t portid)
{
	struct ether_addr eth_addr;
	char buf[ETHER_ADDR_FMT_SIZE];

	rte_eth_macaddr_get(portid, &eth_addr);
	ether_format_addr(buf, sizeof(buf), &eth_addr);
	printf("Initialized port %u: MAC: %s\n", portid, buf);
}

int main(int argc, char **argv)
{
	unsigned int n;
	uint16_t portid;
	int r;

	r = rte_eal_init(argc, argv);
	if (r < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");


	n = rte_eth_dev_count_avail();
	if (n != 1)
		rte_exit(EXIT_FAILURE, "Expect one external port (got %u)\n", n);

	mb_pool = rte_pktmbuf_pool_create("mb_pool", NUM_MBUFS,
					  MEMPOOL_CACHE, 0,
					  RTE_MBUF_DEFAULT_BUF_SIZE, 0);
	if (!mb_pool)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	RTE_ETH_FOREACH_DEV(portid) {
		port_config(portid);

		print_mac(portid);

		rte_eth_promiscuous_enable(portid);

		flow_configure(portid,
			       rte_lcore_count());

		r = rte_eth_dev_start(portid);
		if (r < 0)
			rte_exit(EXIT_FAILURE,
				 "Start failed: err=%d, port=%u\n",
				 r, portid);
	}

	r = rte_eal_mp_remote_launch(dump_rx_pkt, NULL, CALL_MASTER);
	if (r < 0)
		rte_exit(EXIT_FAILURE, "cannot launch cores");

	RTE_ETH_FOREACH_DEV(portid) {
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
	}

	return 0;
}
