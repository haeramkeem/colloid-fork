# TPP + Colloid Diff

```
diff --git a/tpp/linux-6.3/include/linux/memory-tiers.h b/tpp/linux-6.3/include/linux/memory-tiers.h
index c903b1d6f..fc9647b1b 100644
--- a/tpp/linux-6.3/include/linux/memory-tiers.h
+++ b/tpp/linux-6.3/include/linux/memory-tiers.h
@@ -36,9 +36,6 @@ struct memory_dev_type *alloc_memory_type(int adistance);
 void destroy_memory_type(struct memory_dev_type *memtype);
 void init_node_memory_type(int node, struct memory_dev_type *default_type);
 void clear_node_memory_type(int node, struct memory_dev_type *memtype);
-void colloid_init_memory_tier(int node);
-void colloid_clear_memory_tier(int node);
-struct memory_dev_type *colloid_get_default_dram_memtype(void);
 #ifdef CONFIG_MIGRATION
 int next_demotion_node(int node);
 void node_get_allowed_targets(pg_data_t *pgdat, nodemask_t *targets);
diff --git a/tpp/linux-6.3/include/linux/sched/numa_balancing.h b/tpp/linux-6.3/include/linux/sched/numa_balancing.h
index ae085ae29..3988762ef 100644
--- a/tpp/linux-6.3/include/linux/sched/numa_balancing.h
+++ b/tpp/linux-6.3/include/linux/sched/numa_balancing.h
@@ -22,7 +22,6 @@ extern void set_numabalancing_state(bool enabled);
 extern void task_numa_free(struct task_struct *p, bool final);
 extern bool should_numa_migrate_memory(struct task_struct *p, struct page *page,
 					int src_nid, int dst_cpu);
-extern int numa_migrate_memory_away_target(struct page *page, int src_nid);
 #else
 static inline void task_numa_fault(int last_node, int node, int pages,
 				   int flags)
@@ -43,10 +42,6 @@ static inline bool should_numa_migrate_memory(struct task_struct *p,
 {
 	return true;
 }
-static inline int numa_migrate_memory_away_target(struct page *page, int src_nid)
-{
-	return NUMA_NO_NODE;
-}
 #endif
 
 #endif /* _LINUX_SCHED_NUMA_BALANCING_H */
diff --git a/tpp/linux-6.3/include/linux/sched/sysctl.h b/tpp/linux-6.3/include/linux/sched/sysctl.h
index 8abd19833..5a64582b0 100644
--- a/tpp/linux-6.3/include/linux/sched/sysctl.h
+++ b/tpp/linux-6.3/include/linux/sched/sysctl.h
@@ -22,7 +22,6 @@ enum sched_tunable_scaling {
 #define NUMA_BALANCING_DISABLED		0x0
 #define NUMA_BALANCING_NORMAL		0x1
 #define NUMA_BALANCING_MEMORY_TIERING	0x2
-#define NUMA_BALANCING_COLLOID 0x4
 
 #ifdef CONFIG_NUMA_BALANCING
 extern int sysctl_numa_balancing_mode;
diff --git a/tpp/linux-6.3/kernel/sched/core.c b/tpp/linux-6.3/kernel/sched/core.c
index d1c4e8a98..0d18c3969 100644
--- a/tpp/linux-6.3/kernel/sched/core.c
+++ b/tpp/linux-6.3/kernel/sched/core.c
@@ -4640,7 +4640,7 @@ static struct ctl_table sched_core_sysctls[] = {
 		.mode		= 0644,
 		.proc_handler	= sysctl_numa_balancing,
 		.extra1		= SYSCTL_ZERO,
-		.extra2		= SYSCTL_ONE_HUNDRED,
+		.extra2		= SYSCTL_FOUR,
 	},
 #endif /* CONFIG_NUMA_BALANCING */
 	{}
diff --git a/tpp/linux-6.3/kernel/sched/fair.c b/tpp/linux-6.3/kernel/sched/fair.c
index bab83e570..5f6587d94 100644
--- a/tpp/linux-6.3/kernel/sched/fair.c
+++ b/tpp/linux-6.3/kernel/sched/fair.c
@@ -26,7 +26,6 @@
 #include <linux/jiffies.h>
 #include <linux/mm_api.h>
 #include <linux/highmem.h>
-#include <linux/swap.h>
 #include <linux/spinlock_api.h>
 #include <linux/cpumask_api.h>
 #include <linux/lockdep_api.h>
@@ -57,8 +56,6 @@
 #include "stats.h"
 #include "autogroup.h"
 
-extern int colloid_local_lat_gt_remote;
-extern int colloid_nid_of_interest;
 /*
  * Targeted preemption latency for CPU-bound tasks:
  *
@@ -1585,21 +1582,10 @@ bool should_numa_migrate_memory(struct task_struct *p, struct page * page,
 		unsigned long rate_limit;
 		unsigned int latency, th, def_th;
 
-		/*colloid: since we emulate slow tier with normal NUMA node,
-		in corner case, CPU on the slow NUMA could access its own page.
-		Avoid unnecessarily updating state (e.g. hot threshold) in this case*/
-		if(!node_is_toptier(dst_nid))
-			return false;
-
 		pgdat = NODE_DATA(dst_nid);
 		if (pgdat_free_space_enough(pgdat)) {
 			/* workload changed, reset hot threshold */
 			pgdat->nbp_threshold = 0;
-			if(sysctl_numa_balancing_mode & NUMA_BALANCING_COLLOID &&
-			   colloid_nid_of_interest == dst_nid &&
-			   READ_ONCE(colloid_local_lat_gt_remote))
-				return false;
-
 			return true;
 		}
 
@@ -1613,20 +1599,10 @@ bool should_numa_migrate_memory(struct task_struct *p, struct page * page,
 		if (latency >= th)
 			return false;
 
-		if(sysctl_numa_balancing_mode & NUMA_BALANCING_COLLOID &&
-		   colloid_nid_of_interest == dst_nid &&
-			READ_ONCE(colloid_local_lat_gt_remote))
-			return false;
-
 		return !numa_promotion_rate_limit(pgdat, rate_limit,
 						  thp_nr_pages(page));
 	}
 
-	/*In colloid, since we enable local hint faults, we may reach here
-	even if normal numa balancing is off. In that case, avoid going any futher. */
-	if(!(sysctl_numa_balancing_mode & NUMA_BALANCING_NORMAL))
-	   return false;
-
 	this_cpupid = cpu_pid_to_cpupid(dst_cpu, current->pid);
 	last_cpupid = page_cpupid_xchg_last(page, this_cpupid);
 
@@ -1693,46 +1669,6 @@ bool should_numa_migrate_memory(struct task_struct *p, struct page * page,
 	       group_faults_cpu(ng, src_nid) * group_faults(p, dst_nid) * 4;
 }
 
-/*
-colloid
-Should we migrate page away from local NUMA node due to congestion?
-if yes, returns nid of destination node
-otherwise returns NUMA_NO_NODE
-*/
-int numa_migrate_memory_away_target(struct page *page, int src_nid) {
-	unsigned int latency, th;
-	// TODO: add condition to ignore mlocked / unevictable pages
-	if(!(sysctl_numa_balancing_mode & NUMA_BALANCING_MEMORY_TIERING &&
-	     sysctl_numa_balancing_mode & NUMA_BALANCING_COLLOID))
-		 return NUMA_NO_NODE;
-	
-	if(src_nid != colloid_nid_of_interest)
-		return NUMA_NO_NODE;
-
-	if(!READ_ONCE(colloid_local_lat_gt_remote))
-		return NUMA_NO_NODE;
-
-	// Local memory is congested
-
-	if(sysctl_numa_balancing_mode & NUMA_BALANCING_NORMAL) {
-		// No timestamp, use active/inactive list to determine hotness
-		// Do not move pages that are not in the active list
-		if(!PageActive(page)) {
-			mark_page_accessed(page);
-			return NUMA_NO_NODE;
-		}
-	} else {
-		// Timestamp in page flags. use hint fault latency to determine hotness
-		th = NODE_DATA(src_nid)->nbp_threshold ? : sysctl_numa_balancing_hot_threshold;
-		latency = numa_hint_fault_latency(page);
-		if (latency >= th)
-			return NUMA_NO_NODE;
-	}
-
-	return next_demotion_node(src_nid);
-
-}
-
 /*
  * 'numa_type' describes the node at the moment of load balancing.
  */
@@ -2922,10 +2858,6 @@ void task_numa_fault(int last_cpupid, int mem_node, int pages, int flags)
 	     !cpupid_valid(last_cpupid)))
 		return;
 
-	/*colloid: NUMA fault stats not necessary when normal NUMA balancing is off*/
-	if(!(sysctl_numa_balancing_mode & NUMA_BALANCING_NORMAL))
-		return;
-
 	/* Allocate buffer to track faults on a per-node basis */
 	if (unlikely(!p->numa_faults)) {
 		int size = sizeof(*p->numa_faults) *
diff --git a/tpp/linux-6.3/mm/Kconfig b/tpp/linux-6.3/mm/Kconfig
index 4031f49f2..4751031f3 100644
--- a/tpp/linux-6.3/mm/Kconfig
+++ b/tpp/linux-6.3/mm/Kconfig
@@ -1204,31 +1204,4 @@ config LRU_GEN_STATS
 
 source "mm/damon/Kconfig"
 
-menu "Colloid NUMA Configuration"
-
-config COLLOID_OVERRIDE_FALLBACK
-    bool "Enable override fallback for Colloid"
-    default n
-    help
-      Enable or disable override for fallback NUMA order.
-      Say 'y' to enable and 'n' to disable.
-
-config COLLOID_DEFAULT_TIER_NUMA
-    int "Default NUMA tier for Colloid"
-    default 0
-    help
-      Specify the default NUMA tier for Colloid.
-	  Only used if COLLOID_OVERRIDE_FALLBACK is enabled.
-      Must be an integer.
-
-config COLLOID_ALTERNATE_TIER_NUMA
-    int "Alternate NUMA tier for Colloid"
-    default 1
-    help
-      Specify the alternate NUMA tier for Colloid.
-	  Only used if COLLOID_OVERRIDE_FALLBACK is enabled.
-      Must be an integer.
-
-endmenu
-
 endmenu
diff --git a/tpp/linux-6.3/mm/huge_memory.c b/tpp/linux-6.3/mm/huge_memory.c
index 7e21fa58f..3fae2d249 100644
--- a/tpp/linux-6.3/mm/huge_memory.c
+++ b/tpp/linux-6.3/mm/huge_memory.c
@@ -1546,14 +1546,6 @@ vm_fault_t do_huge_pmd_numa_page(struct vm_fault *vmf)
 	target_nid = numa_migrate_prep(page, vma, haddr, page_nid,
 				       &flags);
 
-	/*
-	colloid
-	Move pages away from local NUMA is congested
-	*/
-	if(page_nid == numa_node_id() && target_nid == NUMA_NO_NODE) {
-		target_nid = numa_migrate_memory_away_target(page, page_nid);
-	}
-
 	if (target_nid == NUMA_NO_NODE) {
 		put_page(page);
 		goto out_map;
@@ -1897,17 +1889,12 @@ int change_huge_pmd(struct mmu_gather *tlb, struct vm_area_struct *vma,
 		 * Skip scanning top tier node if normal numa
 		 * balancing is disabled
 		 */
-		 // Enable hint faults for top tier nodes in colloid
 		if (!(sysctl_numa_balancing_mode & NUMA_BALANCING_NORMAL) &&
-			!(sysctl_numa_balancing_mode & NUMA_BALANCING_COLLOID && 
-			  sysctl_numa_balancing_mode & NUMA_BALANCING_MEMORY_TIERING) &&
 		    toptier)
 			goto unlock;
 
-		// Record access time in page flags for top tier if colloid is enabled and normal numa balancing is not
 		if (sysctl_numa_balancing_mode & NUMA_BALANCING_MEMORY_TIERING &&
-		    (!toptier || ((sysctl_numa_balancing_mode & NUMA_BALANCING_COLLOID) && 
-						 !(sysctl_numa_balancing_mode & NUMA_BALANCING_NORMAL))))
+		    !toptier)
 			xchg_page_access_time(page, jiffies_to_msecs(jiffies));
 	}
 	/*
diff --git a/tpp/linux-6.3/mm/memory-tiers.c b/tpp/linux-6.3/mm/memory-tiers.c
index e24b66f3c..e593e56e5 100644
--- a/tpp/linux-6.3/mm/memory-tiers.c
+++ b/tpp/linux-6.3/mm/memory-tiers.c
@@ -105,11 +105,6 @@ static int top_tier_adistance;
 static struct demotion_nodes *node_demotion __read_mostly;
 #endif /* CONFIG_MIGRATION */
 
-int colloid_local_lat_gt_remote = 0;
-EXPORT_SYMBOL(colloid_local_lat_gt_remote);
-int colloid_nid_of_interest = NUMA_NO_NODE;
-EXPORT_SYMBOL(colloid_nid_of_interest);
-
 static inline struct memory_tier *to_memory_tier(struct device *device)
 {
 	return container_of(device, struct memory_tier, dev);
@@ -201,8 +196,6 @@ static struct memory_tier *find_create_memory_tier(struct memory_dev_type *memty
 	if (!new_memtier)
 		return ERR_PTR(-ENOMEM);
 
-	pr_info("allocated new mem tier");
-
 	new_memtier->adistance_start = adistance;
 	INIT_LIST_HEAD(&new_memtier->list);
 	INIT_LIST_HEAD(&new_memtier->memory_types);
@@ -270,9 +263,6 @@ bool node_is_toptier(int node)
 	rcu_read_unlock();
 	return toptier;
 }
-EXPORT_SYMBOL_GPL(node_is_toptier);
-
-
 
 void node_get_allowed_targets(pg_data_t *pgdat, nodemask_t *targets)
 {
@@ -336,7 +326,6 @@ int next_demotion_node(int node)
 
 	return target;
 }
-EXPORT_SYMBOL_GPL(next_demotion_node);
 
 static void disable_all_demotion_targets(void)
 {
@@ -429,24 +418,19 @@ static void establish_demotion_targets(void)
 	 * Once we detect such a memory tier, we consider that tier
 	 * as top tiper from which promotion is not allowed.
 	 */
-	// list_for_each_entry_reverse(memtier, &memory_tiers, list) {
-	// 	tier_nodes = get_memtier_nodemask(memtier);
-	// 	nodes_and(tier_nodes, node_states[N_CPU], tier_nodes);
-	// 	if (!nodes_empty(tier_nodes)) {
-	// 		/*
-	// 		 * abstract distance below the max value of this memtier
-	// 		 * is considered toptier.
-	// 		 */
-	// 		top_tier_adistance = memtier->adistance_start +
-	// 					MEMTIER_CHUNK_SIZE - 1;
-	// 		break;
-	// 	}
-	// }
-
-	// midhul. colloid: Overriding top_tier_adistance to always be default dram adistance
-	// This enables putting normal NUMA nodes (with CPUs) into lower memory tiers
-	top_tier_adistance = round_down(default_dram_type->adistance, MEMTIER_CHUNK_SIZE) + MEMTIER_CHUNK_SIZE - 1;
-	pr_info("colloid: top_tier_adistance set to %d", top_tier_adistance);
+	list_for_each_entry_reverse(memtier, &memory_tiers, list) {
+		tier_nodes = get_memtier_nodemask(memtier);
+		nodes_and(tier_nodes, node_states[N_CPU], tier_nodes);
+		if (!nodes_empty(tier_nodes)) {
+			/*
+			 * abstract distance below the max value of this memtier
+			 * is considered toptier.
+			 */
+			top_tier_adistance = memtier->adistance_start +
+						MEMTIER_CHUNK_SIZE - 1;
+			break;
+		}
+	}
 	/*
 	 * Now build the lower_tier mask for each node collecting node mask from
 	 * all memory tier below it. This allows us to fallback demotion page
@@ -504,10 +488,8 @@ static struct memory_tier *set_node_memory_tier(int node)
 	__init_node_memory_type(node, default_dram_type);
 
 	memtype = node_memory_types[node].memtype;
-	pr_info("set_node_memory_tier, memtype adist = %d", memtype->adistance);
 	node_set(node, memtype->nodes);
 	memtier = find_create_memory_tier(memtype);
-	pr_info("set_node_memory_tier, memtier adist_start = %d", memtier->adistance_start);
 	if (!IS_ERR(memtier))
 		rcu_assign_pointer(pgdat->memtier, memtier);
 	return memtier;
@@ -597,17 +579,14 @@ EXPORT_SYMBOL_GPL(init_node_memory_type);
 void clear_node_memory_type(int node, struct memory_dev_type *memtype)
 {
 	mutex_lock(&memory_tier_lock);
-	pr_info("clear_node_memory_type, map_count=%d, memtype adist=%d", node_memory_types[node].map_count, node_memory_types[node].memtype->adistance);
 	if (node_memory_types[node].memtype == memtype)
 		node_memory_types[node].map_count--;
 	/*
 	 * If we umapped all the attached devices to this node,
 	 * clear the node memory type.
 	 */
-	pr_info("clear_node_memory_type, map_count=%d, memtype adist=%d", node_memory_types[node].map_count, node_memory_types[node].memtype->adistance);
 	if (!node_memory_types[node].map_count) {
 		node_memory_types[node].memtype = NULL;
-		pr_info("node_memory_types[node].memtype set to NULL");
 		kref_put(&memtype->kref, release_memtype);
 	}
 	mutex_unlock(&memory_tier_lock);
@@ -646,43 +625,6 @@ static int __meminit memtier_hotplug_callback(struct notifier_block *self,
 	return notifier_from_errno(0);
 }
 
-struct memory_dev_type *colloid_get_default_dram_memtype() {
-	return default_dram_type;
-}
-EXPORT_SYMBOL_GPL(colloid_get_default_dram_memtype);
-
-void colloid_init_memory_tier(int node) {
-	struct memory_tier *memtier;
-
-	if (node_state(node, N_CPU)) {
-		pr_info("colloid: NUMA node is NOT zero CPU");
-	} else {
-		pr_info("colloid: NUMA node is zero CPU");
-	}
-
-	mutex_lock(&memory_tier_lock);
-	memtier = set_node_memory_tier(node);
-	if (!IS_ERR(memtier)) {
-		pr_info("set_node_memory_tier success");
-		establish_demotion_targets();
-		pr_info("established demotion targets");
-	}
-	mutex_unlock(&memory_tier_lock);
-}
-EXPORT_SYMBOL_GPL(colloid_init_memory_tier);
-
-void colloid_clear_memory_tier(int node) {
-	struct memory_tier *memtier;
-
-	mutex_lock(&memory_tier_lock);
-	clear_node_memory_tier(node);
-	pr_info("clear_node_memory_tier");
-	establish_demotion_targets();
-	pr_info("established demotion targets");
-	mutex_unlock(&memory_tier_lock);
-}
-EXPORT_SYMBOL_GPL(colloid_clear_memory_tier);
-
 static int __init memory_tier_init(void)
 {
 	int ret, node;
diff --git a/tpp/linux-6.3/mm/memory.c b/tpp/linux-6.3/mm/memory.c
index 1ba11cb21..01a23ad48 100644
--- a/tpp/linux-6.3/mm/memory.c
+++ b/tpp/linux-6.3/mm/memory.c
@@ -4734,13 +4734,6 @@ static vm_fault_t do_numa_page(struct vm_fault *vmf)
 		last_cpupid = page_cpupid_last(page);
 	target_nid = numa_migrate_prep(page, vma, vmf->address, page_nid,
 			&flags);
-	/*
-	colloid
-	Move pages away from local NUMA is congested
-	*/
-	if(page_nid == numa_node_id() && target_nid == NUMA_NO_NODE) {
-		target_nid = numa_migrate_memory_away_target(page, page_nid);
-	}
 	if (target_nid == NUMA_NO_NODE) {
 		put_page(page);
 		goto out_map;
diff --git a/tpp/linux-6.3/mm/migrate.c b/tpp/linux-6.3/mm/migrate.c
index 52da37e0e..db3f15444 100644
--- a/tpp/linux-6.3/mm/migrate.c
+++ b/tpp/linux-6.3/mm/migrate.c
@@ -599,7 +599,6 @@ void folio_migrate_flags(struct folio *newfolio, struct folio *folio)
 	 * memory node, reset cpupid, because that is used to record
 	 * page access time in slow memory node.
 	 */
-	//  TODO: For colloid, (if normal numa balancing is off) perhaps we don't want to reset 
 	if (sysctl_numa_balancing_mode & NUMA_BALANCING_MEMORY_TIERING) {
 		bool f_toptier = node_is_toptier(page_to_nid(&folio->page));
 		bool t_toptier = node_is_toptier(page_to_nid(&newfolio->page));
diff --git a/tpp/linux-6.3/mm/mprotect.c b/tpp/linux-6.3/mm/mprotect.c
index b1c55c33f..36351a00c 100644
--- a/tpp/linux-6.3/mm/mprotect.c
+++ b/tpp/linux-6.3/mm/mprotect.c
@@ -156,8 +156,6 @@ static long change_pte_range(struct mmu_gather *tlb,
 				 * Don't mess with PTEs if page is already on the node
 				 * a single-threaded process is running on.
 				 */
-				// TODO: Update this for colloid; want hint faults even for single-threaded process
-				// TODO: After making this update, make sure to test with mlocked memory
 				nid = page_to_nid(page);
 				if (target_node == nid)
 					continue;
@@ -167,16 +165,11 @@ static long change_pte_range(struct mmu_gather *tlb,
 				 * Skip scanning top tier node if normal numa
 				 * balancing is disabled
 				 */
-				// Enable hint faults for top tier nodes in colloid
 				if (!(sysctl_numa_balancing_mode & NUMA_BALANCING_NORMAL) &&
-					!(sysctl_numa_balancing_mode & NUMA_BALANCING_COLLOID && 
-					  sysctl_numa_balancing_mode & NUMA_BALANCING_MEMORY_TIERING) &&
 				    toptier)
 					continue;
-				// Record access time in page flags for top tier if colloid is enabled and normal numa balancing is not
 				if (sysctl_numa_balancing_mode & NUMA_BALANCING_MEMORY_TIERING &&
-				    (!toptier || ((sysctl_numa_balancing_mode & NUMA_BALANCING_COLLOID) && 
-								 !(sysctl_numa_balancing_mode & NUMA_BALANCING_NORMAL))))
+				    !toptier)
 					xchg_page_access_time(page,
 						jiffies_to_msecs(jiffies));
 			}
diff --git a/tpp/linux-6.3/mm/page_alloc.c b/tpp/linux-6.3/mm/page_alloc.c
index e20513966..8e39705c7 100644
--- a/tpp/linux-6.3/mm/page_alloc.c
+++ b/tpp/linux-6.3/mm/page_alloc.c
@@ -6515,9 +6515,6 @@ static void build_zonelists(pg_data_t *pgdat)
 	int node, nr_nodes = 0;
 	nodemask_t used_mask = NODE_MASK_NONE;
 	int local_node, prev_node;
-	#ifdef CONFIG_COLLOID_OVERRIDE_FALLBACK
-	int colloid_remote_idx;
-	#endif
 
 	/* NUMA-aware ordering of nodes */
 	local_node = pgdat->node_id;
@@ -6538,25 +6535,6 @@ static void build_zonelists(pg_data_t *pgdat)
 		prev_node = node;
 	}
 
-	#ifdef CONFIG_COLLOID_OVERRIDE_FALLBACK
-	// Colloid: overwrite node order for colloid local numa node
-	if(local_node == CONFIG_COLLOID_DEFAULT_TIER_NUMA) {
-		colloid_remote_idx = -1;
-		for (node = 0; node < nr_nodes; node++) {
-			if(node_order[node] == CONFIG_COLLOID_ALTERNATE_TIER_NUMA) {
-				colloid_remote_idx = node;
-				break;
-			}
-		}
-		// make sure colloid remote node is second in the list
-		while(colloid_remote_idx > 1) {
-			node_order[colloid_remote_idx] = node_order[colloid_remote_idx-1];
-			node_order[colloid_remote_idx-1] = CONFIG_COLLOID_ALTERNATE_TIER_NUMA;
-			colloid_remote_idx--;
-		}
-	}
-	#endif
-
 	build_zonelists_in_node_order(pgdat, node_order, nr_nodes);
 	build_thisnode_zonelists(pgdat);
 	pr_info("Fallback order for Node %d: ", local_node);
```
