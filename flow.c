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
#include <rte_lcore.h>

#include "eth_compat.h"
#include "rte_flow_dump.h"

/* steal ether_aton fron netinet/ether.h */
struct ether_addr *ether_aton_r(const char *asc, struct ether_addr *addr);

static unsigned int num_vnic;
static struct rte_ether_addr *vnic_mac;
static unsigned int num_queue = 1;

#define NUM_MBUFS	   131071
#define MEMPOOL_CACHE	   256
#define RX_DESC_DEFAULT	   256
#define TX_DESC_DEFAULT	   512
#define MAX_PKT_BURST	   32
#define MAX_RX_QUEUE	   64
#define IDLE_POLL_US	   10
#define MS_PER_SEC	   1000ul
#define US_PER_SEC	   1000000ul
#define MAX_EVENTS	   16
#define STAT_INTERVAL      10
#define TIMEOUT_MS	   (STAT_INTERVAL * MS_PER_SEC)

#define FLOW_SRC_MODE	1
#define FLOW_DST_MODE	2

static bool flow_dump = false;
static bool irq_mode = false;
static bool details = false;
static bool promisc = true;
static unsigned long flow_mode = FLOW_SRC_MODE | FLOW_DST_MODE;
static uint32_t ticks_us;

#define VNIC_RSS_HASH_TYPES \
	(ETH_RSS_IPV4 | ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP | \
	 ETH_RSS_IPV6 | ETH_RSS_NONFRAG_IPV6_TCP | ETH_RSS_NONFRAG_IPV6_UDP)

#define VNIC_SRC_MAC_PRIORITY	1
#define VNIC_DST_MAC_PRIORITY	2

struct lcore_conf {
	uint16_t n_rx;
	struct rx_queue {
		uint16_t port_id;
		uint16_t queue_id;
		uint64_t rx_packets;
	} rx_queue_list[MAX_RX_QUEUE];
}  __rte_cache_aligned;
static struct lcore_conf lcore_conf[RTE_MAX_LCORE];

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

	if (irq_mode)
		port_conf.intr_conf.rxq = 1;

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
flow_src_mac(uint16_t port, uint32_t id,
	     const struct rte_ether_addr *mac,
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

	if (flow_dump) {
		printf("flow-demo: Creating src MAC filter!!\n");
		rte_flow_dump(stdout, &attr, pattern, actions);
	}

	return rte_flow_create(port, &attr, pattern, actions, err);
}

static struct rte_flow *
flow_dst_mac(uint16_t port, uint32_t id,
	     const struct rte_ether_addr *mac,
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

	if (flow_dump) {
		printf("flow-demo: Creating dst MAC filter!!\n");
		rte_flow_dump(stdout, &attr, pattern, actions);
	}
	return rte_flow_create(port, &attr, pattern, actions, err);
}

static void flow_configure(uint16_t portid, uint16_t id, uint16_t firstq)
{
	const struct rte_ether_addr *mac = &vnic_mac[id];
	uint16_t lastq = firstq + num_queue - 1;
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
	       id, firstq, lastq);

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

	if ((flow_mode & FLOW_SRC_MODE) &&
	    !flow_src_mac(portid, id, mac, actions, &err))
		rte_exit(EXIT_FAILURE,
			 "src mac flow create failed: %s\n error type %u %s\n",
			 rte_strerror(rte_errno), err.type, err.message);

	if ((flow_mode & FLOW_DST_MODE) &&
	    !flow_dst_mac(portid, id, mac, actions, &err))
		rte_exit(EXIT_FAILURE,
			 "dst mac flow create failed: %s\n error type %u %s\n",
			 rte_strerror(rte_errno), err.type, err.message);

	for (q = firstq; q <= lastq; q++) {
		r = rte_eth_dev_rx_queue_start(portid, q);
		if (r < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_dev_rx_queue_start: q=%u failed\n", q);
	}
}

static void
dump_rx_pkt(uint16_t portid, uint16_t queueid,
	    struct rte_mbuf *pkts[], uint16_t n)
{
	uint16_t i;

	for (i = 0; i < n; i++) {
		struct rte_mbuf *m = pkts[i];
		const struct rte_ether_hdr *eh
			= rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
		char dbuf[RTE_ETHER_ADDR_FMT_SIZE];
		char sbuf[RTE_ETHER_ADDR_FMT_SIZE];

		rte_ether_format_addr(dbuf, RTE_ETHER_ADDR_FMT_SIZE,
				      &eh->d_addr);
		rte_ether_format_addr(sbuf, RTE_ETHER_ADDR_FMT_SIZE,
				      &eh->s_addr);

		printf("[%u:%u] %s %s %x ..%u\n", portid, queueid,
		       dbuf, sbuf,
		       ntohs(eh->ether_type), rte_pktmbuf_pkt_len(m));

		rte_pktmbuf_free(m);
	}
	fflush(stdout);
}

static void
show_stats(void) {
	unsigned int i, lcore_id;
	uint16_t portid;
	struct rte_eth_stats stats;

	RTE_ETH_FOREACH_DEV(portid) {
		rte_eth_stats_get(portid, &stats);

		printf("%u: %"PRIu64"/%"PRIu64" |",
		       portid, stats.ipackets, stats.ibytes);

		RTE_LCORE_FOREACH(lcore_id) {
			struct lcore_conf *conf = &lcore_conf[lcore_id];

			for (i = 0; i < conf->n_rx; i++) {
				struct rx_queue *rxq = &conf->rx_queue_list[i];

				if (rxq->port_id != portid)
					continue;

				printf(" %u:%"PRIu64,
				       rxq->queue_id, rxq->rx_packets);
				rxq->rx_packets = 0;
			}
		}
		printf("\n");
	}

	fflush(stdout);
}

static unsigned int
rx_poll(struct rx_queue *rxq)
{
	uint16_t portid = rxq->port_id;
	uint16_t queueid = rxq->queue_id;
	struct rte_mbuf *pkts[MAX_PKT_BURST];
	unsigned int n;

	n = rte_eth_rx_burst(portid, queueid, pkts, MAX_PKT_BURST);
	if (n == 0)
		return 0;

	rxq->rx_packets += n;
	if (details)
		dump_rx_pkt(portid, queueid, pkts, n);

	return n;
}

/* enable interrupts on all queues this lcore is handling */
static void
enable_rx_intr(const struct lcore_conf *c)
{
	uint16_t i;

	for (i = 0; i < c->n_rx; i++) {
		rte_eth_dev_rx_intr_enable(c->rx_queue_list[i].port_id,
					   c->rx_queue_list[i].queue_id);
	}
}

static void
disable_rx_intr(const struct lcore_conf *c)
{
	uint16_t i;

	for (i = 0; i < c->n_rx; i++) {
		rte_eth_dev_rx_intr_disable(c->rx_queue_list[i].port_id,
					    c->rx_queue_list[i].queue_id);
	}
}

static void
sleep_until_interrupt(struct lcore_conf *c)
{
	struct rte_epoll_event events[MAX_EVENTS];
	int i, n;

	enable_rx_intr(c);

	for (i = 0; i < c->n_rx; i++) {
		n = rte_eth_rx_queue_count(c->rx_queue_list[i].port_id,
					   c->rx_queue_list[i].queue_id);
		if (n > 0) {
			/* lost race, packet arrived */
			disable_rx_intr(c);
			return;
		}
	}

	fflush(stdout);
	n = rte_epoll_wait(RTE_EPOLL_PER_THREAD, events,
			   MAX_EVENTS, TIMEOUT_MS);
	if (n < 0)
		rte_exit(EXIT_FAILURE, "rte_epoll_wait: failed\n");

	disable_rx_intr(c);
}

static void
event_register(const struct lcore_conf *c)
{
	int i, ret;

	for (i = 0; i < c->n_rx; i++) {
		const struct rx_queue *rxq = &c->rx_queue_list[i];
		unsigned long data = rxq->port_id << CHAR_BIT | rxq->queue_id;

		ret = rte_eth_dev_rx_intr_ctl_q(rxq->port_id, rxq->queue_id,
						RTE_EPOLL_PER_THREAD,
						RTE_INTR_EVENT_ADD,
						(void *)data);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_dev_rx_intr_ctl_q(%u, %u) failed: %d\n",
				 rxq->port_id, rxq->queue_id, ret);
	}
}

static int elapsed_us(uint64_t t1, uint64_t t0)
{
	return (int64_t)(t1 - t0) / ticks_us;
}

static int
rx_thread(void *arg __rte_unused)
{
	unsigned int core_id = rte_lcore_id();
	struct lcore_conf *c = &lcore_conf[core_id];
	uint64_t idle_start = 0;
	uint64_t last_stats = rte_rdtsc();

	if (c->n_rx == 0) {
		printf("Lcore %u has nothing to do\n", rte_lcore_id());
		return 0;
	}

	if (irq_mode)
		event_register(c);

	while (running) {
		unsigned int i, total = 0;
		uint64_t cur_tsc;
		int us;

		for (i = 0; i < c->n_rx; i++)
			total += rx_poll(&c->rx_queue_list[i]);

		cur_tsc = rte_rdtsc();
		us = elapsed_us(cur_tsc, last_stats);
		if (core_id == rte_get_master_lcore() &&
		    us >= (int)(STAT_INTERVAL * US_PER_SEC)) {
			last_stats = cur_tsc;
			show_stats();
		}

		if (!irq_mode)
			continue;

		if (total > 0) {
			idle_start = 0;
			continue;
		}

		if (idle_start == 0) {
			idle_start = cur_tsc;
			continue;
		}

		us = elapsed_us(cur_tsc, idle_start);
		if (us >= IDLE_POLL_US) {
			sleep_until_interrupt(c);
			idle_start = 0;
		}
	}

	return 0;
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
	printf("Usage: %s [EAL options] -- -[idsfpV] -q NQ MAC1 MAC2 ...\n"
	       "  -i      IRQ mode\n"
	       "  -d      destination mac only match\n"
	       "  -s      source mac only match\n"
	       "  -f      flow dump\n"
	       "  -p      don't put interface in promicious\n"
	       "  -q  NQ  number of queues per Vnic\n"
	       "  -V      print packet details\n",
	       argv0);
	exit(1);
}

static void parse_args(int argc, char **argv)
{
	int opt;
	unsigned int i;

	while ((opt = getopt(argc, argv, "vidsfpVq:")) != EOF) {
		switch (opt) {
		case 'i':
			irq_mode = true;
			break;
		case 's':
			flow_mode = FLOW_SRC_MODE;
			break;
		case 'd':
			flow_mode = FLOW_DST_MODE;
			break;
		case 'q':
			num_queue = atoi(optarg);
			break;
		case 'f':
			flow_dump = true;
			break;
		case 'p':
			promisc = false;
			break;
		case 'V':
			details = true;
			break;
		default:
			usage(argv[0]);
		}
	}

	/* Additional arguments are MAC address of VNICs */
	num_vnic = argc - optind;
	vnic_mac = calloc(sizeof(struct rte_ether_addr), num_vnic);

	for (i = 0; i < num_vnic; i++) {
		const char *asc = argv[optind + i];

		if (ether_aton_r(asc, (struct ether_addr *)(vnic_mac + i)) == NULL)
			rte_exit(EXIT_FAILURE,
				"Invalid mac address: %s\n", asc);
	}
}

static void signal_handler(int signum)
{
	printf("\n\nSignal %d received, preparing to exit...\n",
		signum);

	running = false;
}

static void
assign_queues(uint16_t portid, uint16_t nrxq)
{
	uint16_t q;

	for (q = 0; q < nrxq; q++) {
		unsigned int lcore = q % rte_lcore_count();
		struct lcore_conf *c = &lcore_conf[lcore];
		struct rx_queue *rxq;

		if (c->n_rx >= MAX_RX_QUEUE)
			rte_exit(EXIT_FAILURE,
				"Too many rx queue already on core %u\n",
				lcore);

		rxq = c->rx_queue_list + c->n_rx++;
		rxq->port_id = portid;
		rxq->queue_id = q;
		printf("Lcore %u polling %u:%u\n", lcore, portid, q);
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

	ticks_us = rte_get_tsc_hz() / US_PER_SEC;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	n = rte_eth_dev_count_avail();
	if (n != 1)
		rte_exit(EXIT_FAILURE,
			 "Expect one external port (got %u)\n", n);

	mb_pool = rte_pktmbuf_pool_create("mb_pool", NUM_MBUFS,
					  MEMPOOL_CACHE, 0,
					  RTE_MBUF_DEFAULT_BUF_SIZE, 0);
	if (!mb_pool)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	port_config(0, ntxq, nrxq);
	print_mac(0);
	if (promisc)
		rte_eth_promiscuous_enable(0);

	for (v = 0, q = 1; v < num_vnic; v++, q += num_queue)
		flow_configure(0, v, q);

	assign_queues(0, nrxq);

	printf("Portid: Packets/Bytes | queue:pkts...\n");
	r = rte_eal_mp_remote_launch(rx_thread, NULL, CALL_MASTER);
	if (r < 0)
		rte_exit(EXIT_FAILURE, "cannot launch cores");

	rte_eth_dev_stop(0);
	rte_eth_dev_close(0);

	return 0;
}
