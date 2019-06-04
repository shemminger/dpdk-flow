/*
 * Backward compatiablilty with earlier DPDK API
 * Copyright(c) 2019 Microsoft Corporation
 * All rights reserved.
 */

#include <rte_ether.h>

/* workaround pre DPDK 19.08  */
#ifndef RTE_ETHER_MAX_LEN
#define RTE_ETHER_MAX_LEN ETHER_MAX_LEN
#define RTE_ETHER_ADDR_FMT_SIZE ETHER_ADDR_FMT_SIZE

#define rte_ether_addr ether_addr
#define rte_ether_hdr ether_hdr
#define rte_ether_format_addr ether_format_addr
#endif
