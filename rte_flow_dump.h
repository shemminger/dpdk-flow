/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Microsoft Corporation
 * All rights reserved.
 */

void rte_flow_attr_dump(FILE *f, const struct rte_flow_attr *attr);
void rte_flow_item_dump(FILE *f, const struct rte_flow_item *pattern);
void rte_flow_action_dump(FILE *f,
			const struct rte_flow_action *action);
void rte_flow_dump(FILE *f,
		const struct rte_flow_attr *attr,
		const struct rte_flow_item pattern[],
		const struct rte_flow_action actions[]);
