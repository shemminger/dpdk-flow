/*
 * demo rte_flow default rule
 * Copyright(c) 2019 Microsoft Corporation
 * All rights reserved.
 *
 * Creates multiple virtual network interfaces each with a
 * unique MAC address.
 *
 * Usage:
 *    flow-demo EAL_args -- [--queues Q]  MAC...
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
static unsigned int num_queue = 1;

#define MEMPOOL_CACHE	   256
#define RX_DESC_DEFAULT	   256
#define TX_DESC_DEFAULT	   512
#define MAX_PKT_BURST	   32
#define MAX_RX_QUEUE	   64
#define IDLE_POLL_US	   10
#define MAX_EVENTS	   16
#define STAT_INTERVAL      10
#define PKTMBUF_POOL_RESERVED 128

#define FLOW_SRC_MODE	1
#define FLOW_DST_MODE	2

static bool flow_dump = false;
static bool irq_mode = false;
static bool any_mode = false;
static bool random_mac = false;
static unsigned int details;
static bool promisc = true;
static bool rss_enabled;
static unsigned long flow_mode = FLOW_SRC_MODE | FLOW_DST_MODE;
static uint32_t ticks_us;
static struct rte_timer stat_timer;

#define VNIC_RSS_HASH_TYPES \
	(ETH_RSS_IPV4 | ETH_RSS_NONFRAG_IPV4_TCP | ETH_RSS_NONFRAG_IPV4_UDP | \
	 ETH_RSS_IPV6 | ETH_RSS_NONFRAG_IPV6_TCP | ETH_RSS_NONFRAG_IPV6_UDP)

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

	if (random_mac) {
		struct rte_ether_addr mac;
		char ebuf[RTE_ETHER_ADDR_FMT_SIZE];

		rte_eth_random_addr(mac.addr_bytes);
		rte_ether_format_addr(ebuf, sizeof(ebuf), &mac);
		printf("MAC: %s\n", ebuf);

		r = rte_eth_dev_default_mac_addr_set(portid, &mac);
		if (r < 0)
			rte_exit(EXIT_FAILURE,
				 "mac_addr_set failed: %d\n", r);
	}

	if (irq_mode)
		port_conf.intr_conf.rxq = 1;
	if (rss_enabled)
		port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;

	printf("Configure %u Tx and %u Rx queues (RSS %s)\n",
	       ntxq, nrxq,
	       (port_conf.rxmode.mq_mode & ETH_MQ_RX_RSS_FLAG) ? "enabled" : "disabled");

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

	firstq = rss_enabled ? rte_lcore_count() : 1;
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
	struct rte_flow_item patterns[2];
	struct rte_flow_item *pat = patterns;
	char ebuf[RTE_ETHER_ADDR_FMT_SIZE];

	if (any_mode) {
		*pat++ = (struct rte_flow_item) {
			.type = RTE_FLOW_ITEM_TYPE_ANY,
			.spec = &inner_flow,
			.mask = &any_mask,
		};
	};

	*pat++ = (struct rte_flow_item) {
		.type = RTE_FLOW_ITEM_TYPE_ETH,
		.spec = &vnic_eth_src,
		.mask = &eth_src_mask,
	};

	*pat = (struct rte_flow_item){ .type = RTE_FLOW_ITEM_TYPE_END };

	rte_ether_format_addr(ebuf, sizeof(ebuf), mac);
	printf("Matching on %ssrc MAC %s\n",
	       any_mode ? "any ": "", ebuf);

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


	if (any_mode) {
		*pat++ = (struct rte_flow_item) {
			.type = RTE_FLOW_ITEM_TYPE_ANY,
			.spec = &inner_flow,
			.mask = &any_mask,
		};
	};

	*pat++ = (struct rte_flow_item) {
		.type = RTE_FLOW_ITEM_TYPE_ETH,
		.spec = &vnic_eth_dst,
		.mask = &eth_dst_mask,
	};

	*pat = (struct rte_flow_item){ .type = RTE_FLOW_ITEM_TYPE_END };

	rte_ether_format_addr(ebuf, sizeof(ebuf), mac);
	printf("Matching on %sdst MAC %s\n",
	       any_mode ? "any ": "", ebuf);

	if (flow_dump)
		rte_flow_dump(stdout, &attr, patterns, actions);

	return rte_flow_create(port, &attr, patterns, actions, err);
}

static void flow_configure(uint16_t portid, uint16_t id, uint16_t firstq,
			   const struct rte_ether_addr *mac)
{
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
	char buf[64];
	uint16_t q;
	int r;

	rte_ether_format_addr(buf, sizeof(buf), mac);
	printf("Creating VNIC %u [%s] with queue %u..%u\n",
	       id, buf, firstq, lastq);

	if (num_queue > 1) {
		uint16_t i;

		for (i = 0; i < num_queue; i++)
			rss_queues[i] = firstq + i;

		/* Do RSS over N queues using the default RSS key */
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

static uint64_t time_monotonic(void)
{
	static uint64_t start;
	struct timespec ts;
	uint64_t ns;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	ns = ts.tv_sec * NS_PER_S + ts.tv_nsec;

	if (start)
		return ns - start;
	start = ns;
	return 0;
}

static void
dump_rx_pkt(uint16_t portid, uint16_t queueid,
	    struct rte_mbuf *pkts[], uint16_t n)
{
	static unsigned int pktno;
	uint64_t us = time_monotonic() / 1000;
	uint16_t i;

	for (i = 0; i < n; i++) {
		printf("[%u:%u] ", portid, queueid);
		if (details > 1)
			printf("%-6u %"PRId64".%06"PRId64,
			       ++pktno, us / US_PER_S, us % US_PER_S);

		pkt_print(pkts[i]);
	}
	fflush(stdout);
}

static void
show_stats(struct rte_timer *tm __rte_unused, void *arg)
{
	unsigned long nrxq = (unsigned long)arg;
	unsigned int q, i, lcore_id;
	struct rte_eth_stats stats;

	rte_eth_stats_get(0, &stats);

	printf("%"PRIu64"/%"PRIu64, stats.ipackets, stats.ibytes);

	for (q = 0; q < nrxq; q++) {
		RTE_LCORE_FOREACH(lcore_id) {
			struct lcore_conf *conf = &lcore_conf[lcore_id];

			for (i = 0; i < conf->n_rx; i++) {
				struct rx_queue *rxq = &conf->rx_queue_list[i];

				if (rxq->queue_id == q) {
					printf(" %u@%u:%"PRIu64,
					       q, lcore_id, rxq->rx_packets);
					break;
				}
			}
		}
	}
	printf("\n");
	fflush(stdout);
}

static unsigned int
rx_poll(struct rx_queue *rxq)
{
	uint16_t portid = rxq->port_id;
	uint16_t queueid = rxq->queue_id;
	struct rte_mbuf *pkts[MAX_PKT_BURST];
	unsigned int i, n;

	n = rte_eth_rx_burst(portid, queueid, pkts, MAX_PKT_BURST);
	if (n == 0)
		return 0;

	rxq->rx_packets += n;
	if (details)
		dump_rx_pkt(portid, queueid, pkts, n);

	for (i = 0; i < n; i++)
		rte_pktmbuf_free(pkts[i]);

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

	n = rte_epoll_wait(RTE_EPOLL_PER_THREAD, events,
			   MAX_EVENTS, STAT_INTERVAL * MS_PER_S);
	if (n < 0 && errno == EINTR)
		rte_exit(EXIT_FAILURE, "rte_epoll_wait_interruptible: failed: %s\n",
			 strerror(errno));

	disable_rx_intr(c);
}

static void
event_register(struct lcore_conf *c)
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

	/* no need for rx thread if no queues  */
	if (c->n_rx == 0)
		return 0;

	if (irq_mode)
		event_register(c);

	while (running) {
		unsigned int i, total = 0;
		uint64_t cur_tsc;
		int us;

		rte_timer_manage();

		for (i = 0; i < c->n_rx; i++)
			total += rx_poll(&c->rx_queue_list[i]);

		if (!irq_mode)
			continue;

		if (total > 0) {
			idle_start = 0;
			continue;
		}

		cur_tsc = rte_rdtsc();
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
	printf("Usage: %s [EAL options] -- [OPTIONS] MAC1 MAC2 ...\n"
	       "  -a,--any       match any level\n"
	       "  -i,--irq       IRQ mode\n"
	       "  -d,--dst       destination mac only match\n"
	       "  -s,--src       source mac only match\n"
	       "  -f,--flow      flow dump\n"
	       "  -p             don't put interface in promicious\n"
	       "  -q,--queue  N  number of queues per Vnic\n"
	       "  -r,--rss       enable RSS\n"
	       "  -m,--mac	 assign random MAC address\n"
	       "  -v,--details   print packet details\n",
	       argv0);
	exit(1);
}

static const struct option longopts[] = {
	{ "irq",	no_argument, 0, 'i' },
	{ "dst",	no_argument, 0, 'd' },
	{ "src",	no_argument, 0, 's' },
	{ "flow",	no_argument, 0, 'f' },
	{ "queue",	no_argument, 0, 'q' },
	{ "rss",	no_argument, 0, 'r' },
	{ "any",	no_argument, 0, 'a' },
	{ "mac",	no_argument, 0, 'm' },
	{ 0 }
};

static void parse_args(int argc, char **argv)
{
	unsigned int i;
	int opt;

	while ((opt = getopt_long(argc, argv, "avidsfpq:rm",
				  longopts, NULL)) != EOF) {
		switch (opt) {
		case 'a':
			any_mode = true;
			break;
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
		case 'm':
			random_mac = true;
			break;
		case 'r':
			rss_enabled = true;
			break;
		case 'v':
			++details;
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

static void signal_handler(int signum)
{
	printf("\n\nSignal %d received, preparing to exit...\n",
		signum);

	running = false;
}

static void
assign_queues(uint16_t portid, uint16_t nrxq)
{
	static int lcore = -1;
	uint16_t q;

	for (q = 0; q < nrxq; q++) {
		struct lcore_conf *c;
		struct rx_queue *rxq;

		lcore = rte_get_next_lcore(lcore, 0, 1);
		c = &lcore_conf[lcore];
		if (c->n_rx >= MAX_RX_QUEUE)
			rte_exit(EXIT_FAILURE,
				"Too many rx queue already on core %u\n",
				lcore);

		rxq = c->rx_queue_list + c->n_rx++;
		rxq->port_id = portid;
		rxq->queue_id = q;
	}
}

int main(int argc, char **argv)
{
	unsigned int q, i, n, v;
	unsigned int num_mbufs, obj_size;
	uint16_t ntxq, nrxq;
	int r;

	r = rte_eal_init(argc, argv);
	if (r < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

	parse_args(argc - r, argv + r);

	ntxq = rte_lcore_count();
	nrxq = num_vnic * num_queue;
	nrxq += rss_enabled ? rte_lcore_count() : 1;

	ticks_us = rte_get_tsc_hz() / US_PER_S;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	n = rte_eth_dev_count_avail();
	if (n != 1)
		rte_exit(EXIT_FAILURE,
			 "Expect one external port (got %u)\n", n);

	num_mbufs =
		rte_align32pow2(nrxq * RX_DESC_DEFAULT  * 3)
		+ ntxq * (TX_DESC_DEFAULT + MAX_PKT_BURST)
		+ rte_lcore_count() * (MEMPOOL_CACHE + MAX_PKT_BURST)
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

	rte_timer_subsystem_init();

	port_config(0, ntxq, nrxq);
	print_mac(0);
	if (promisc)
		rte_eth_promiscuous_enable(0);
	else {
		for (i = 0; i < num_vnic; i++) {
			r = rte_eth_dev_mac_addr_add(0, &vnic_mac[i], 0);
			if (r < 0)
				rte_exit(EXIT_FAILURE,
					 "Add mac address failed: %s\n",
					 strerror(-r));
		}
	}

	/* v is the vnic id, starts with 0.
	 * q is the queue, starts after default queue
	 */
	v = 0;
	q = rss_enabled ? rte_lcore_count() : 1;
	for (i = 0; i < num_vnic; i++) {
		flow_configure(0, v, q, &vnic_mac[i]);

		/* force non-sequential id to force bug detection */
		v = 1u << i;
		q += num_queue;
	}

	assign_queues(0, nrxq);

	if (!details) {
		rte_timer_init(&stat_timer);
		rte_timer_reset(&stat_timer,
				STAT_INTERVAL * rte_get_timer_hz(),
				PERIODICAL, rte_get_master_lcore(),
				show_stats, (void *)(unsigned long)nrxq);

		printf("\n%-14s: %8s/%-10s | per-queue\n",
		       "Time", "Packets", "Bytes");
	}

	if (details) {
		printf("\n[port:queue] ");
		if (details > 1)
			printf("pktno Δt");
		printf("{vlan} Outer Ethernet...\n");
	}

	r = rte_eal_mp_remote_launch(rx_thread, NULL, CALL_MASTER);
	if (r < 0)
		rte_exit(EXIT_FAILURE, "cannot launch cores");

	if (promisc)
		rte_eth_promiscuous_disable(0);
	else {
		for (i = 0; i < num_vnic; i++) {
			rte_eth_dev_mac_addr_remove(0, &vnic_mac[i]);
		}
	}

	rte_eth_dev_stop(0);
	rte_eth_dev_close(0);

	return 0;
}
