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

#define NUM_MBUFS     65535 // should be 131071
#define MEMPOOL_CACHE 256
#define MAX_QUEUES 64
#define RX_DESC_DEFAULT	   256
#define TX_DESC_DEFAULT	   512
#define MAX_PKT_BURST 32

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
	struct ether_addr eth_addr;
	uint16_t nrxq, ntxq;
	uint16_t nb_rxd = RX_DESC_DEFAULT;
	uint16_t nb_txd = TX_DESC_DEFAULT;
	uint16_t q;
	int r;

	rte_eth_dev_info_get(portid, &dev_info);

	nrxq = RTE_MIN(MAX_QUEUES, dev_info.max_rx_queues);
	ntxq = rte_lcore_count();

	printf("Configuring Tx %u Rx %u queues\n", ntxq, nrxq);

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

	eth_random_addr((uint8_t *)&eth_addr);
	r = rte_eth_dev_default_mac_addr_set(portid, &eth_addr);
	if (r < 0)
		rte_exit(EXIT_FAILURE,
			 "rte_eth_dev_default_mac_addr_set failed: %d\n", r);


	txq_conf = dev_info.default_txconf;
	rxq_conf = dev_info.default_rxconf;

	txq_conf.offloads = port_conf.txmode.offloads;
	rxq_conf.rx_drop_en = 1;
	rxq_conf.rx_deferred_start = 1;
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
}

static void flow_configure(uint16_t portid, uint16_t nq __rte_unused)
{
	/* flow only applies to ingress */
	struct rte_flow_attr attr  = {
		.ingress = 1,
	};
	struct rte_flow_item_eth eth_zero = { };
	struct rte_flow_item pattern[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = &eth_zero,
			.mask = &eth_zero,
		},
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};
#ifdef RSS_WORKS
	uint16_t rss_queues[nq];
	struct rte_flow_action_rss act_rss = {
		.types = VNIC_RSS_HASH_TYPES,
		.queue_num = nq,
		.queue = vnic_queues,
	};
#else
	struct rte_flow_action_queue act_queue = {
		.index = 0,
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
	for (i = 0; i < nq; i++)
		vnic_queues[i] = i;
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
			sleep(10);
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
