/*
 * test for  rte_flow leaks
 * Copyright(c) 2021 Microsoft Corporation
 * All rights reserved.
 *
 * Creates and delete flows
 *
 * Usage:
 *    flow-leak EAL_args -- [OPTIONS] MAC...
 */

#include <stdio.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_flow.h>
#include <rte_lcore.h>
#include <rte_timer.h>
#include <rte_cycles.h>

#include "rte_flow_dump.h"
#include "pkt_dump.h"

static unsigned int num_vnic;
static struct rte_ether_addr *vnic_mac;
static struct rte_flow **src_flows, **dst_flows;
static unsigned int num_queue = 1;
static unsigned int repeat = 1;

#define MEMPOOL_CACHE	   256
#define RX_DESC_DEFAULT	   256
#define TX_DESC_DEFAULT	   512
#define MAX_RX_QUEUE	   64
#define PKTMBUF_POOL_RESERVED 128

#define FLOW_SRC_MODE	1
#define FLOW_DST_MODE	2

static bool flow_dump = false;

/*
 * Comment from rte_flow.h on meaning of priorities:
 *
 * Priorities are set on a per rule based within groups.
 *
 * Lower values denote higher priority, the highest priority for a flow rule
 * is 0, so that a flow that matches for than one rule, the rule with the
 * lowest priority value will always be matched.
 *
 * Although optional, applications are encouraged to group similar rules as
 * much as possible to fully take advantage of hardware capabilities
 * (e.g. optimized matching) and work around limitations (e.g. a single
 * pattern type possibly allowed in a given group). Applications should be
 * aware that groups are not linked by default, and that they must be
 * explicitly linked by the application using the JUMP action.
 */

#define VNIC_SRC_MAC_PRIORITY	1
#define VNIC_DST_MAC_PRIORITY	65536

static struct rte_mempool *mb_pool;

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode	= ETH_MQ_RX_NONE,
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
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

static volatile bool running = true;

static void port_config(uint16_t portid, uint16_t ntxq, uint16_t nrxq)
{
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	uint16_t nb_rxd = RX_DESC_DEFAULT;
	uint16_t nb_txd = TX_DESC_DEFAULT;
	uint16_t firstq, q;
	int r;

	r = rte_eth_dev_info_get(portid, &dev_info);
	if (r < 0)
		rte_exit(EXIT_FAILURE,
			 "Could not get device information for port %u\n",
			 portid);

	if (ntxq > dev_info.max_tx_queues)
		rte_exit(EXIT_FAILURE,
			 "Not enough transmit queues %u > %u\n",
			ntxq, dev_info.max_tx_queues);

	if (nrxq > dev_info.max_rx_queues)
		rte_exit(EXIT_FAILURE,
			 "Not enough receive queues %u > %u\n",
			nrxq, dev_info.max_rx_queues);

	printf("Configure %u Tx and %u Rx queues\n",
	       ntxq, nrxq);

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

	firstq = 1;
	for (q = 0; q < nrxq; q++) {
		if (q >= firstq)
			rxq_conf.rx_deferred_start = 1;

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
flow_src_mac(uint16_t port, uint32_t id,
	     const struct rte_ether_addr *mac,
	     const struct rte_flow_action actions[],
	     struct rte_flow_error *err)
{
	struct rte_flow_attr attr  = {
		.group = id + 1,
		.priority = VNIC_SRC_MAC_PRIORITY,
		.ingress = 1,
	};
	static const struct rte_flow_item_eth eth_src_mask = {
		.src.addr_bytes = "\xff\xff\xff\xff\xff\xff",
	};
	struct rte_flow_item_eth vnic_eth_src = {
		.src = *mac,
	};
	struct rte_flow_item patterns[3];
	struct rte_flow_item *pat = patterns;
	char ebuf[RTE_ETHER_ADDR_FMT_SIZE];

	*pat++ = (struct rte_flow_item) {
		.type = RTE_FLOW_ITEM_TYPE_ANY,
		.spec = &inner_flow,
		.mask = &any_mask,
	};

	*pat++ = (struct rte_flow_item) {
		.type = RTE_FLOW_ITEM_TYPE_ETH,
		.spec = &vnic_eth_src,
		.mask = &eth_src_mask,
	};

	*pat = (struct rte_flow_item){ .type = RTE_FLOW_ITEM_TYPE_END };

	rte_ether_format_addr(ebuf, sizeof(ebuf), mac);

	if (flow_dump)
		rte_flow_dump(stdout, &attr, patterns, actions);

	return rte_flow_create(port, &attr, patterns, actions, err);
}

static struct rte_flow *
flow_dst_mac(uint16_t port, uint32_t id,
	     const struct rte_ether_addr *mac,
	     const struct rte_flow_action actions[],
	     struct rte_flow_error *err)
{
	struct rte_flow_attr attr  = {
		.group = id + 1,
		.priority = VNIC_DST_MAC_PRIORITY,
		.ingress = 1,
	};
	struct rte_flow_item_eth vnic_eth_dst = {
		.dst = *mac,
	};
	static const struct rte_flow_item_eth eth_dst_mask = {
		.dst.addr_bytes = "\xff\xff\xff\xff\xff\xff",
	};
	struct rte_flow_item patterns[3];
	struct rte_flow_item *pat = patterns;
	char ebuf[RTE_ETHER_ADDR_FMT_SIZE];


	*pat++ = (struct rte_flow_item) {
		.type = RTE_FLOW_ITEM_TYPE_ANY,
		.spec = &inner_flow,
		.mask = &any_mask,
	};
	
	*pat++ = (struct rte_flow_item) {
		.type = RTE_FLOW_ITEM_TYPE_ETH,
		.spec = &vnic_eth_dst,
		.mask = &eth_dst_mask,
	};

	*pat = (struct rte_flow_item){ .type = RTE_FLOW_ITEM_TYPE_END };

	rte_ether_format_addr(ebuf, sizeof(ebuf), mac);
	if (flow_dump)
		rte_flow_dump(stdout, &attr, patterns, actions);

	return rte_flow_create(port, &attr, patterns, actions, err);
}

static void flow_create(uint16_t portid, uint16_t id, uint16_t q,
			const struct rte_ether_addr *mac)
{
	struct rte_flow_action_queue queue = {
		.index = q,
	};
	struct rte_flow_action actions[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_QUEUE, .conf = &queue },
		{ .type = RTE_FLOW_ACTION_TYPE_END  },
	};
	struct rte_flow_error err;
	int r;

	src_flows[id] = flow_src_mac(portid, id, mac, actions, &err);
	if (src_flows[id] == NULL)
		rte_exit(EXIT_FAILURE,
			 "src mac flow create failed: %s\n error type %u %s\n",
			 rte_strerror(rte_errno), err.type, err.message);

	dst_flows[id] = flow_dst_mac(portid, id, mac, actions, &err);
	if (dst_flows[id] == NULL)
		rte_exit(EXIT_FAILURE,
			 "dst mac flow create failed: %s\n error type %u %s\n",
			 rte_strerror(rte_errno), err.type, err.message);

	r = rte_eth_dev_rx_queue_start(portid, q);
	if (r < 0)
		rte_exit(EXIT_FAILURE,
			 "rte_eth_dev_rx_queue_start: q=%u failed\n", q);
}

static void flow_delete(uint16_t portid, uint16_t id, uint16_t q)
{
	struct rte_flow_error err;
	int r;

	if (rte_flow_destroy(portid, dst_flows[id], &err))
		rte_exit(EXIT_FAILURE,
			 "rte_flow_destroy failed: %s\n error type %u %s\n",
			 rte_strerror(rte_errno), err.type, err.message);
	dst_flows[id] = NULL;
	
	if (rte_flow_destroy(portid, src_flows[id], &err))
		rte_exit(EXIT_FAILURE,
			 "rte_flow_destroy failed: %s\n error type %u %s\n",
			 rte_strerror(rte_errno), err.type, err.message);
	src_flows[id] = NULL;
		
	r = rte_eth_dev_rx_queue_stop(portid, q);
	if (r < 0)
		rte_exit(EXIT_FAILURE,
			 "rte_eth_dev_rx_queue_stop: q=%u failed\n", q);
}

static void print_mac(uint16_t portid)
{
	struct rte_ether_addr eth_addr;
	char buf[RTE_ETHER_ADDR_FMT_SIZE];

	rte_eth_macaddr_get(portid, &eth_addr);
	rte_ether_format_addr(buf, sizeof(buf), &eth_addr);

	printf("Initialized port %u: MAC: %s\n", portid, buf);
}

static void usage(const char *argv0)
{
	printf("Usage: %s [EAL options] -- [OPTIONS] MAC1 MAC2 ...\n"
	       "  -c,--count  N  repeat count\n"
	       "  -f,--flow      flow dump\n"
	       "  -q,--queue  N  number of queues per Vnic\n"
	       "  -v,--details   print packet details\n",
	       argv0);
	exit(1);
}

static const struct option longopts[] = {
	{ "count",      required_argument, 0, 'c' },
	{ "flow",	no_argument, 0, 'f' },
	{ "queue",	required_argument, 0, 'q' },
	{ 0 }
};

static void parse_args(int argc, char **argv)
{
	unsigned int i;
	int opt;

	while ((opt = getopt_long(argc, argv, "c:q:f",
				  longopts, NULL)) != EOF) {
		switch (opt) {
		case 'c':
			repeat = atoi(optarg);
			break;
		case 'q':
			num_queue = atoi(optarg);
			break;
		case 'f':
			flow_dump = true;
			break;
		default:
			fprintf(stderr, "Unknown option\n");
			usage(argv[0]);
		}
	}

	/* Additional arguments are MAC address of VNICs */
	num_vnic = argc - optind;
	vnic_mac = calloc(sizeof(struct rte_ether_addr), num_vnic);
	for (i = 0; i < num_vnic; i++) {
		const char *asc = argv[optind + i];

		if (rte_ether_unformat_addr(asc, &vnic_mac[i]) != 0)
			rte_exit(EXIT_FAILURE,
				"Invalid mac address: %s\n", asc);
	}
}

int main(int argc, char **argv)
{
	unsigned int v;
	unsigned int num_mbufs, obj_size;
	uint16_t ntxq, nrxq;
	int r;

	r = rte_eal_init(argc, argv);
	if (r < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

	parse_args(argc - r, argv + r);

	ntxq = rte_lcore_count();
	nrxq = num_vnic * num_queue + 1;

	if (rte_eth_dev_count_avail() != 1)
		rte_exit(EXIT_FAILURE,
			 "Expect one external port\n");

	src_flows = calloc(num_vnic + 1, sizeof(struct rte_flow *));
	dst_flows = calloc(num_vnic + 1, sizeof(struct rte_flow *));

	num_mbufs =
		rte_align32pow2(nrxq * RX_DESC_DEFAULT  * 3)
		+ PKTMBUF_POOL_RESERVED;

	/* rte_pktmbuf_pool_create is optimum with 2^q - 1 */
	num_mbufs = rte_align32pow2(num_mbufs + 1) - 1;

	mb_pool = rte_pktmbuf_pool_create("mb_pool", num_mbufs,
					  MEMPOOL_CACHE, 0,
					  RTE_MBUF_DEFAULT_BUF_SIZE, 0);
	if (!mb_pool)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	obj_size = rte_mempool_calc_obj_size(RTE_MBUF_DEFAULT_BUF_SIZE,
					     0, NULL);
	printf("mbuf pool %u of %u bytes = %uMb\n",
		num_mbufs, obj_size,
		(num_mbufs * obj_size) / (1024 * 1024));

	port_config(0, ntxq, nrxq);
	print_mac(0);

	while (repeat-- > 0) {
		for (v = 1; v <= num_vnic; ++v)
			flow_create(0, v, v, &vnic_mac[v - 1]);

		for (v = 1; v <= num_vnic; ++v)
			flow_delete(0, v, v);
	}

	rte_eth_dev_stop(0);
	rte_eth_dev_close(0);
	rte_eal_cleanup();

	return 0;
}
