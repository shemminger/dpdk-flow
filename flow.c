/*
 * Demo rte_flow default rule
 * Copyright(c) 2019 Microsoft Corporation
 * All rights reserved.
 *
 * Creates multiple virtual network interfaces each with a
 * unique MAC address.
 *
 * Usage:
 *    flow-demo EAL_args -- [--queues Q]  MAC...
 *
 */

#include <stdio.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_flow.h>

#include "rte_flow_dump.h"

/* steal ether_aton fron netinet/ether.h */
struct ether_addr *ether_aton_r(const char *asc, struct ether_addr *addr);
char *ether_ntoa_r(const struct ether_addr *addr, char *buf);

static unsigned int num_vnic;
static struct ether_addr *vnic_mac;
static unsigned int num_queue = 1;
static volatile bool force_quit;

#define NUM_MBUFS	   131071
#define MEMPOOL_CACHE	   256
#define RX_DESC_DEFAULT	   256
#define TX_DESC_DEFAULT	   512
#define MAX_PKT_BURST	   32
#define MAX_RX_QUEUE	   64

#define VNIC_RSS_HASH_TYPES \
	(ETH_RSS_IPV4 | ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP | \
	 ETH_RSS_IPV6 | ETH_RSS_NONFRAG_IPV6_TCP | ETH_RSS_NONFRAG_IPV6_UDP)

#define VNIC_SRC_MAC_PRIORITY	1
#define VNIC_DST_MAC_PRIORITY	2

struct lcore_queue_conf {
	uint16_t n_rx;
	uint16_t rx_queues[MAX_RX_QUEUE];
}  __rte_cache_aligned;
static struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

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


static void port_config(uint16_t portid, uint16_t ntxq, uint16_t nrxq)
{
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	uint16_t nb_rxd = RX_DESC_DEFAULT;
	uint16_t nb_txd = TX_DESC_DEFAULT;
	uint16_t q;
	int r;

	rte_eth_dev_info_get(portid, &dev_info);

	if (ntxq > dev_info.max_tx_queues)
		rte_exit(EXIT_FAILURE,
			 "Not enough transmit queues %u > %u\n",
			ntxq, dev_info.max_tx_queues);

	if (nrxq > dev_info.max_rx_queues)
		rte_exit(EXIT_FAILURE,
			 "Not enough receive queues %u > %u\n",
			nrxq, dev_info.max_rx_queues);

	printf("Configure %u Tx and %u Rx queues\n", ntxq, nrxq);
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

	r = rte_eth_dev_start(portid);
	if (r < 0)
		rte_exit(EXIT_FAILURE,
			 "Start failed: err=%d\n", r);

	/* Stop all VNIC queues */
	for (q = 1; q < nrxq; q++) {
		r = rte_eth_dev_rx_queue_stop(portid, q);
		if (r < 0)
			rte_exit(EXIT_FAILURE, "queue %u stop failed\n",
				q);
	}
}
/* Match any level mask */
static const struct rte_flow_item_any any_mask = {
	.num = UINT32_MAX,
};

/* Match encaped packets */
static const struct rte_flow_item_any inner_flow = {
	.num = 4,
};

static struct rte_flow *
flow_src_mac(uint16_t port, uint32_t id, const struct ether_addr *mac,
	     const struct rte_flow_action actions[],
	     struct rte_flow_error *err)
{
	struct rte_flow_attr attr  = {
		.group = id,
		.priority = VNIC_SRC_MAC_PRIORITY,
		.ingress = 1,
	};
	static const struct rte_flow_item_eth eth_src_mask = {
	      .src.addr_bytes = "\xff\xff\xff\xff\xff\xff",
	};
	struct rte_flow_item_eth vnic_eth_src = {
		.src = *mac,
	};
	struct rte_flow_item pattern[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_ANY,
			.spec = &inner_flow,
			.mask = &any_mask,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = &vnic_eth_src,
			.mask = &eth_src_mask,
		},
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};

	printf("flow-demo: Creating src MAC filter!!\n");
	rte_flow_dump(stdout, &attr, pattern, actions);
		      
	return rte_flow_create(port, &attr, pattern, actions, err);
}

static struct rte_flow *
flow_dst_mac(uint16_t port, uint32_t id, const struct ether_addr *mac,
	     const struct rte_flow_action actions[],
	     struct rte_flow_error *err)
{
	struct rte_flow_attr attr  = {
		.group = id,
		.priority = VNIC_DST_MAC_PRIORITY,
		.ingress = 1,
	};
	struct rte_flow_item_eth vnic_eth_dst = {
		.dst = *mac,
	};
	static const struct rte_flow_item_eth eth_dst_mask = {
	      .dst.addr_bytes = "\xff\xff\xff\xff\xff\xff",
	};
	struct rte_flow_item pattern[] = {
		{
			.type = RTE_FLOW_ITEM_TYPE_ANY,
			.spec = &inner_flow,
			.mask = &any_mask,
		},
		{
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = &vnic_eth_dst,
			.mask = &eth_dst_mask,
		},
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};

	printf("flow-demo: Creating dst MAC filter!!\n");
	rte_flow_dump(stdout, &attr, pattern, actions);
	return rte_flow_create(port, &attr, pattern, actions, err);
}

static void flow_configure(uint16_t portid, uint16_t id, uint16_t firstq)
{
	const struct ether_addr *mac = &vnic_mac[id];
	uint16_t rss_queues[num_queue];
	union {
		struct rte_flow_action_rss rss;
		struct rte_flow_action_queue queue;
	} action;
	struct rte_flow_action actions[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_VOID },
		{ .type = RTE_FLOW_ACTION_TYPE_END  },
	};
	struct rte_flow_error err;
	uint16_t q;
	int r;

	printf("Creating VNIC %u with queue %u..%u\n",
		id, firstq, firstq + num_queue -1);

	if (num_queue > 1) {
		uint16_t i;

		for (i = 0; i < num_queue; i++)
			rss_queues[i] = firstq + i;

		action.rss = (struct rte_flow_action_rss) {
			.types = VNIC_RSS_HASH_TYPES,
			.queue_num = num_queue,
			.queue = rss_queues,
		};
		actions[0] = (struct rte_flow_action) {
			.type = RTE_FLOW_ACTION_TYPE_RSS,
			.conf = &action.rss,
		};
	} else {
		action.queue.index = firstq;
		actions[0] = (struct rte_flow_action) {
			.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &action.queue,
		};
	}

	if (!flow_src_mac(portid, id, mac, actions, &err))
		rte_exit(EXIT_FAILURE,
			 "src mac flow create failed: %s\n error type %u %s\n",
			 rte_strerror(rte_errno), err.type, err.message);

	if (!flow_dst_mac(portid, id, mac, actions, &err))
		rte_exit(EXIT_FAILURE,
			 "dst mac flow create failed: %s\n error type %u %s\n",
			 rte_strerror(rte_errno), err.type, err.message);

	
	printf("flow-demo: Starting queues\n");
	for (q = firstq; q < num_queue; q++) {
		r = rte_eth_dev_rx_queue_start(portid, q);
		if (r < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_dev_rx_queue_start: q=%u failed\n", q);
	}
}

static void
dump_rx_pkt(uint16_t q, struct rte_mbuf *pkts[], uint16_t n)
{
	uint16_t i;

	for (i = 0; i < n; i++) {
		struct rte_mbuf *m = pkts[i];
		const struct ether_hdr *eh
			= rte_pktmbuf_mtod(m, struct ether_hdr *);
		char dbuf[ETHER_ADDR_FMT_SIZE], sbuf[ETHER_ADDR_FMT_SIZE];

		printf("[%u] %s %s %x ..%u\n", q,
		       ether_ntoa_r(&eh->d_addr, dbuf),
		       ether_ntoa_r(&eh->s_addr, sbuf),
		       ntohs(eh->ether_type), rte_pktmbuf_pkt_len(m));

		rte_pktmbuf_free(m);
	}
}

static int
rx_thread(void *arg __rte_unused)
{
	unsigned int core_id = rte_lcore_id();
	const struct lcore_queue_conf *c = &lcore_queue_conf[core_id];
	uint16_t i, n;

	if (c->n_rx == 0) {
		printf("Lcore %u has nothing to do\n", rte_lcore_id());
		return 0;
	}

	for (i = 0; i < c->n_rx; i++) {
		printf("Lcore %u is polling on queue %u\n",
			core_id, c->rx_queues[i]);
	}
	fflush(stdout);

	while (!force_quit) {
		uint16_t t = 0;

		for (i = 0; i < c->n_rx; i++) {
			struct rte_mbuf *pkts[MAX_PKT_BURST];
			uint16_t q = c->rx_queues[i];

			n = rte_eth_rx_burst(0, q, pkts, MAX_PKT_BURST);
			t += n;
			dump_rx_pkt(q, pkts, n);
		}
		fflush(stdout);

		if (t == 0)
			sleep(1);

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

static void usage(const char *argv0)
{
	printf("Usage: %s [EAL options] -- -v -d -q NQ MAC1 MAC2 ...\n"
	       "  -q  NQ  number of queues per Vnic\n", argv0);
	exit(1);
}

static void parse_args(int argc, char **argv)
{
	int opt;
	unsigned int i;

	while ((opt = getopt(argc, argv, "q:")) != EOF) {
		switch (opt) {
		case 'q':
			num_queue = atoi(optarg);
			break;
		default:
			usage(argv[0]);
		}
	}

	/* Additional arguments are MAC address of VNICs */
	num_vnic = argc - optind;
	vnic_mac = calloc(sizeof(struct ether_addr), num_vnic);

	for (i = 0; i < num_vnic; i++) {
		const char *asc = argv[optind + i];

		if (ether_aton_r(asc, vnic_mac + i) == NULL)
			rte_exit(EXIT_FAILURE,
				"Invalid mac address: %s\n", asc);
	}
}

static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}


int main(int argc, char **argv)
{
	unsigned int q, v, n;
	uint16_t ntxq, nrxq;
	int r;

	r = rte_eal_init(argc, argv);
	if (r < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

	parse_args(argc - r, argv + r);

	ntxq = rte_lcore_count();
	nrxq = num_vnic * num_queue + 1;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	n = rte_eth_dev_count_avail();
	if (n != 1)
		rte_exit(EXIT_FAILURE, "Expect one external port (got %u)\n", n);

	mb_pool = rte_pktmbuf_pool_create("mb_pool", NUM_MBUFS,
					  MEMPOOL_CACHE, 0,
					  RTE_MBUF_DEFAULT_BUF_SIZE, 0);
	if (!mb_pool)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	port_config(0, ntxq, nrxq);
	print_mac(0);
	rte_eth_promiscuous_enable(0);

	for (v = 0, q = 1; v < num_vnic; v++, q += num_queue)
		flow_configure(0, v, q);

	for (q = 0; q < nrxq; q++) {
		unsigned int lcore = q % rte_lcore_count();
		struct lcore_queue_conf *c = &lcore_queue_conf[lcore];

		if (c->n_rx >= MAX_RX_QUEUE)
			rte_exit(EXIT_FAILURE,
				"Too many rx queue already on core %u\n",
				lcore);

		c->rx_queues[c->n_rx++] = q;
	}

	r = rte_eal_mp_remote_launch(rx_thread, NULL, CALL_MASTER);
	if (r < 0)
		rte_exit(EXIT_FAILURE, "cannot launch cores");

	rte_eth_dev_stop(0);
	rte_eth_dev_close(0);

	return 0;
}
