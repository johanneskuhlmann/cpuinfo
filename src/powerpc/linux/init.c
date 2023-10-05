#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <cpuinfo.h>
#include <powerpc/linux/api.h>
#include <powerpc/api.h>
#include <linux/api.h>
#include <cpuinfo/internal-api.h>
#include <cpuinfo/log.h>

struct cpuinfo_powerpc_isa cpuinfo_isa = { 0 };

static inline uint32_t min(uint32_t a, uint32_t b) {
	return a < b ? a : b;
}

static inline int cmp(uint32_t a, uint32_t b) {
	return (a > b) - (a < b);
}

static inline bool bitmask_all(uint32_t bitfield, uint32_t mask) {
	return (bitfield & mask) == mask;
}

static void cluster_siblings_parser(
	uint32_t processor, uint32_t siblings_start, uint32_t siblings_end,
	struct cpuinfo_powerpc_linux_processor* processors)
{
	processors[processor].flags |=  CPUINFO_LINUX_FLAG_PACKAGE_CLUSTER;
	uint32_t package_leader_id = processors[processor].package_leader_id;

	for (uint32_t sibling = siblings_start; sibling < siblings_end; sibling++) {
		if (!bitmask_all(processors[sibling].flags, CPUINFO_LINUX_FLAG_VALID)) {
			cpuinfo_log_warning("invalid processor %"PRIu32" reported as a sibling for processor %"PRIu32,
					sibling, processor);
			continue;
		}

		const uint32_t sibling_package_leader_id = processors[sibling].package_leader_id;
		if (sibling_package_leader_id < package_leader_id) {
			package_leader_id = sibling_package_leader_id;
		}
		processors[sibling].package_leader_id = package_leader_id;
		// processors[sibling].flags |= CPUINFO_LINUX_FLAG_PACKAGE_CLUSTER;
	}

	processors[processor].package_leader_id = package_leader_id;
}

void cpuinfo_powerpc_linux_init(void) {
	cpuinfo_log_debug("initializing via cpuinfo_powerpc_linux_init()\n");

	// struct cpuinfo_powerpc_isa* cpuinfo_isa = malloc(sizeof(struct cpuinfo_powerpc_isa));
	struct cpuinfo_powerpc_linux_processor* powerpc_linux_processors = NULL;

	struct cpuinfo_processor* processors = NULL;
	struct cpuinfo_core* cores = NULL;
	struct cpuinfo_cluster* clusters = NULL;
	struct cpuinfo_package* packages = NULL;
	const struct cpuinfo_processor** linux_cpu_to_processor_map = NULL;
	const struct cpuinfo_core** linux_cpu_to_core_map = NULL;
	struct cpuinfo_cache* l1i = NULL;
	struct cpuinfo_cache* l1d = NULL;
	struct cpuinfo_cache* l2 = NULL;
	struct cpuinfo_cache* l3 = NULL;
	struct cpuinfo_cache* l4 = NULL;

	const uint32_t max_processors_count = cpuinfo_linux_get_max_processors_count();
	cpuinfo_log_debug("system maximum processors count: %"PRIu32, max_processors_count);

	const uint32_t max_possible_processors_count = 1 +
		cpuinfo_linux_get_max_possible_processor(max_processors_count);
	cpuinfo_log_debug("maximum possible processors count: %"PRIu32, max_possible_processors_count);

	const uint32_t max_present_processors_count = 1 +
		cpuinfo_linux_get_max_present_processor(max_processors_count);
	cpuinfo_log_debug("maximum present processors count: %"PRIu32, max_present_processors_count);

	const uint32_t powerpc_linux_processors_count = min(max_possible_processors_count, max_present_processors_count);
	powerpc_linux_processors = calloc(powerpc_linux_processors_count, sizeof(struct cpuinfo_powerpc_linux_processor));
	if (powerpc_linux_processors == NULL) {
		cpuinfo_log_error(
			"failed to allocate %zu bytes for descriptions of %"PRIu32" POWERPC logical processors",
			powerpc_linux_processors_count * sizeof(struct cpuinfo_powerpc_linux_processor),
			powerpc_linux_processors_count);
		exit(-1);
	}

	cpuinfo_linux_detect_possible_processors(
		powerpc_linux_processors_count, &powerpc_linux_processors->flags,
		sizeof(struct cpuinfo_powerpc_linux_processor),
		CPUINFO_LINUX_FLAG_POSSIBLE);

	cpuinfo_linux_detect_present_processors(
		powerpc_linux_processors_count, &powerpc_linux_processors->flags,
		sizeof(struct cpuinfo_powerpc_linux_processor),
		CPUINFO_LINUX_FLAG_PRESENT);

	char proc_cpuinfo_hardware[CPUINFO_HARDWARE_VALUE_MAX] = { 0 };

	// parse info from /proc/cpuinfo
	// this sets for all available processors:
	// CPUINFO_LINUX_FLAG_VALID if processor entry is found for this system_processor
	// CPUINFO_POWERPC_LINUX_VALID_IMPLEMENTER always
	// CPUINFO_POWERPC_LINUX_VALID_ARCHITECTURE if cpu_arch_name is POWER
	// CPUINFO_POWERPC_LINUX_VALID_PROCESSOR if additionally cpu_arch_version is in [7,8,9]
	if (!cpuinfo_powerpc_linux_parse_proc_cpuinfo(
			proc_cpuinfo_hardware,
			powerpc_linux_processors_count,
			powerpc_linux_processors)) {
		cpuinfo_log_error("failed to parse processor information from /proc/cpuinfo");
		exit(-1);
	}

	uint32_t usable_processors = 0;
	for (uint32_t i = 0; i < powerpc_linux_processors_count; i++) {
		powerpc_linux_processors[i].system_processor_id = i;
		if (bitmask_all(powerpc_linux_processors[i].flags, CPUINFO_LINUX_FLAG_VALID)) {
			usable_processors += 1;
			if (!(powerpc_linux_processors[i].flags & CPUINFO_POWERPC_LINUX_VALID_PROCESSOR)) {
				cpuinfo_log_info("processor %"PRIu32" is not listed in /proc/cpuinfo", i);
			}
			cpuinfo_log_debug("parsed processor %"PRIu32" PVR 0x%08"PRIx32,
					i, powerpc_linux_processors[i].pvr);
		} else {
			/* Processor reported in /proc/cpuinfo, but not in possible and/or present lists: log and ignore */
			if (!(powerpc_linux_processors[i].flags & CPUINFO_POWERPC_LINUX_VALID_PROCESSOR)) {
				cpuinfo_log_warning("invalid processor %"PRIu32" reported in /proc/cpuinfo", i);
			}
		}
	}
	cpuinfo_log_info("usable processors %"PRIu32"", usable_processors);


	// cpuX: logical ordering of threads in linux kernel
	// /sys/devices/system/cpu/cpu*/topology/core_siblings_list: logical ids of cpuX on same sockets
	// /sys/devices/system/cpu/cpu*/topology/core_id: hardware id key (not an index) of core providing this cpuX
	/* - - - - - - - - - - - - - - Detect cores - - - - - - - - - - - - - - */
	// use hardware key provided by /sys/devices/system/cpu/cpu*/topology/core_id to detect CoreInfo
	struct CoreInfo {
		uint32_t core_id;
		uint32_t proc_id;
		uint32_t proc_count;
	};
	uint32_t core_count=0;
	uint32_t core_capacity=4;
	struct CoreInfo* core_infos = malloc(core_capacity*sizeof(struct CoreInfo));

	// get number of cores and fill out core info
	for (uint32_t i = 0; i < usable_processors; i++) {
		static uint32_t core_id;
		if ( !cpuinfo_linux_get_processor_core_id(i, &core_id) ) {
			cpuinfo_log_error("cannot parse core_id for proc#: %"PRIu32"", i);
			exit(-1);
		}

		// check if this core_id was already found
		struct CoreInfo* core_ptr = NULL;
		for (uint32_t c = 0; c < core_count; c++) {
			if(core_infos[c].core_id == core_id){
				core_ptr = &core_infos[c];
			}
		}

		// check if valid element or add new one
		if (core_ptr == NULL){
			core_count++;

			// check capacity and resize array
			if (core_count == core_capacity){
				core_capacity *= 2;
				void* newMem = realloc(core_infos, (core_capacity)*sizeof(struct CoreInfo*));
				if (!newMem){
					cpuinfo_log_error("failed to allocate memory!");
					free(core_infos);
					exit(-1);
				}
				core_infos = (struct CoreInfo*) newMem;
			}

			// set pointer to last element and initialize it
			core_ptr = &core_infos[core_count-1];
			core_ptr->core_id = core_id;
			core_ptr->proc_id = i;
			core_ptr->proc_count = 1;
		} else { // found valid element by key: increment number of processors on this core
			core_ptr->proc_count++;
		}
	}
	/* - - - - - - - - - - - - - - Detect cores: end- - - - - - - - - - - - - - */

// - - - - read package information - - - - //
	struct PackageInfo {
		uint32_t package_id;
		uint32_t cluster_id;
		uint32_t cluster_count;
		uint32_t core_id;
		uint32_t core_count;
		uint32_t proc_id;
		uint32_t proc_count;
	};

	uint32_t package_count=0;
	uint32_t package_capacity=2;
	struct PackageInfo* package_infos = malloc(package_capacity*sizeof(struct PackageInfo ));

	for (uint32_t i = 0; i < usable_processors; i++) {
		static uint32_t package_id;
		if ( !cpuinfo_linux_get_processor_package_id(i, &package_id) ) {
			cpuinfo_log_error("cannot parse package_id for proc#: %"PRIu32"", i);
			exit(-1);
		}

		// check if this package_id was already found
		struct PackageInfo* package_ptr = NULL;
		for (uint32_t p = 0; p < package_count; p++) {
			if(package_infos[p].package_id == package_id){
				package_ptr = &package_infos[p];
			}
		}

		// check if valid element or add new one
		if (package_ptr == NULL){
			package_count++;

			// check capacity and resize array
			if (package_count == package_capacity){
				package_capacity *= 2;
				void* newMem = realloc(package_infos, (package_capacity)*sizeof(struct PackageInfo*));
				if (!newMem){
					cpuinfo_log_error("failed to allocate memory!");
					free(package_infos);
					exit(-1);
				}
				package_infos = (struct PackageInfo*) newMem;
			}

			// set pointer to last element and initialize it
			package_ptr = &package_infos[package_count-1];
			package_ptr->package_id = package_id;
			package_ptr->proc_id = i;
			package_ptr->proc_count = 1;
			package_ptr->cluster_id = i;
			package_ptr->cluster_count = 1;
		}
		else { // found valid element by key: increment number of processors on this core
			package_ptr->proc_count++;
		}
	}

	// check cores in that package
	for (uint32_t i = 0; i < package_count; i++) {
		uint32_t start = package_infos[i].proc_id;
		uint32_t end = start + package_infos[i].proc_count;
		bool init = true;
		for (uint32_t c = 0; c < core_count; c++) {
			cpuinfo_log_debug("package_id for proc#: %"PRIu32"", i);
			if ( start == core_infos[c].proc_id ){
				package_infos[i].core_id = c;
				package_infos[i].core_count = 1;
			} else if (	start <= core_infos[c].proc_id && core_infos[c].proc_count <= end ){
				package_infos[i].core_count++;
			}
		}
	}
	// l1 is shared per SMT4 core
	// l2 is shared per core pair: 2 SMT4 cores or 1 SMT8 core
	// l3 is shared locally per core pair and remotely per die or hemisphere
	// we first gather for each core and then analyze thread/core packages
	// l1: read from /sys/devices/system/cpu/cpu*/cache/index1/shared_cpu_list
	// l2: read from /sys/devices/system/cpu/cpu*/cache/index2/shared_cpu_list
	// l3: read from /sys/devices/system/cpu/cpu*/cache/index3/shared_cpu_list
	// /sys/devices/system/cpu/cpu<N>/topology/thread_siblings_list  -> identify cores
	// /sys/devices/system/cpu/cpu<N>/topology/core_siblings_list    -> identify sockets
	// /sys/devices/system/cpu/cpu<N>/topology/package_cpus_list

	// - - - - read logical processors list shared per cache level and get the count - - - - //
	#define NUM_CACHE_LEVELS 4
	u_int32_t procs_per_cache_level[NUM_CACHE_LEVELS];
	u_int32_t cache_level_counts[NUM_CACHE_LEVELS];
	for (u_int32_t i=0; i<NUM_CACHE_LEVELS; i++){
		struct List list;
		char filename[58];
		sprintf (filename, "/sys/devices/system/cpu/cpu0/cache/index%d/shared_cpu_list", i);

		cpuinfo_log_debug("parsing l%"PRIu32" cache topology in %s", i, filename);
		if (!parse_topology_file(filename, &list)){
			cpuinfo_log_warning("failed to parse the list of shared logical processors per l%"PRIu32" cache in %s", i, filename);
			procs_per_cache_level[i] = (i<2)?4:8;
		} else {
			// expand number elements in shared_cpu_list
			procs_per_cache_level[i] = list.isRange?(list.ptr[1] - list.ptr[0]):list.size;
		}
		cache_level_counts[i] = usable_processors/procs_per_cache_level[i];

		cpuinfo_log_info("procs_per_cache_level %"PRIu32": %"PRIu32", %"PRIu32"", i, procs_per_cache_level[i], cache_level_counts[i]);
	}

	l1i = calloc(cache_level_counts[0], sizeof(struct cpuinfo_cache));
	if (l1i == NULL) {
		cpuinfo_log_error("failed to allocate %zu bytes for descriptions of %"PRIu32" L1I caches",
			usable_processors * sizeof(struct cpuinfo_cache), usable_processors);
		exit(-1);
	}

	l1d = calloc(cache_level_counts[1], sizeof(struct cpuinfo_cache));
	if (l1d == NULL) {
		cpuinfo_log_error("failed to allocate %zu bytes for descriptions of %"PRIu32" L1D caches",
				usable_processors * sizeof(struct cpuinfo_cache), usable_processors);
		exit(-1);
	}

	l2 = calloc(cache_level_counts[2], sizeof(struct cpuinfo_cache));
	if (l2 == NULL) {
		cpuinfo_log_error("failed to allocate %zu bytes for descriptions of %"PRIu32" L2 caches",
				usable_processors * sizeof(struct cpuinfo_cache), usable_processors);
		exit(-1);
	}

	l3 = calloc(cache_level_counts[3], sizeof(struct cpuinfo_cache));
	if (l3 == NULL) {
		cpuinfo_log_error("failed to allocate %zu bytes for descriptions of %"PRIu32" L3 caches",
				usable_processors * sizeof(struct cpuinfo_cache), usable_processors);
		exit(-1);
	}

	cpuinfo_log_debug("decode cache");
	// decode L1
	for (uint32_t i = 0; i < cache_level_counts[1]; i++) {
		uint32_t first_proc = i*procs_per_cache_level[1];
		cpuinfo_powerpc_decode_cache(first_proc, 0, &l1i[i]);
		cpuinfo_powerpc_decode_cache(first_proc, 1, &l1d[i]);
		l1i[i].processor_start = l1d[i].processor_start = first_proc;
		l1i[i].processor_count = l1d[i].processor_count = procs_per_cache_level[1];
	}
	// decode L2
	for (uint32_t i = 0; i < cache_level_counts[2]; i++) {
		cpuinfo_powerpc_decode_cache(i, 2, &l2[i]);
		l2[i].processor_start = i*procs_per_cache_level[2];
		l2[i].processor_count = procs_per_cache_level[2];
		if (l2[i].size == 0 || l2[i].associativity == 0 || l2[i].sets == 0 || l2[i].partitions == 0 || l2[i].line_size == 0){
			cpuinfo_log_warning("L2 cache file not found: faking cache info!");
			l2[i].size = 512*1024;
			l2[i].associativity = 8;
			l2[i].line_size = 128;
			l2[i].sets = 512;
			l2[i].partitions = 1;
		}
	}
	// decode L3
	for (uint32_t i = 0; i < cache_level_counts[3]; i++) {
		cpuinfo_powerpc_decode_cache(i, 3, &l3[i]);
		l3[i].processor_start = i*procs_per_cache_level[3];
		l3[i].processor_count = procs_per_cache_level[3];
		if (l3[i].size == 0 || l3[i].associativity == 0 || l3[i].sets == 0 || l3[i].partitions == 0 || l3[i].line_size == 0){
			cpuinfo_log_warning("L3 cache file not found: faking cache info!");
			l3[i].size = 10240*1024;
			l3[i].associativity = 20;
			l3[i].line_size = 128;
			l3[i].sets = 4096;
			l3[i].partitions = 1;
		}
	}

	// - - - - - - - - - - - - - - read supported instruction set - - - - - - - - - - - - - //
	cpuinfo_log_debug("cpuinfo_powerpc_linux_init(): decode_isa_from_proc_cpuinfo\n");
	const uint32_t isa_features = cpuinfo_powerpc_linux_hwcap_from_getauxval();
	cpuinfo_ppc64_linux_decode_isa_from_proc_cpuinfo(isa_features, &cpuinfo_isa);

	// - - - - - - - - - - - - - - detect min/max frequency per core - - - - - - - - - - - - - //
	for (uint32_t i = 0; i < powerpc_linux_processors_count; i++) {
		const uint32_t max_frequency = cpuinfo_linux_get_processor_max_frequency(i);
		if (max_frequency != 0) {
			powerpc_linux_processors[i].max_frequency = max_frequency;
			powerpc_linux_processors[i].flags |= CPUINFO_LINUX_FLAG_MAX_FREQUENCY;
		}

		const uint32_t min_frequency = cpuinfo_linux_get_processor_min_frequency(i);
		if (min_frequency != 0) {
			powerpc_linux_processors[i].min_frequency = min_frequency;
			powerpc_linux_processors[i].flags |= CPUINFO_LINUX_FLAG_MIN_FREQUENCY;
		}
	}

	/* Detect package id and initialize topology group IDs */
	for (uint32_t i = 0; i < powerpc_linux_processors_count; i++) {
		if (bitmask_all(powerpc_linux_processors[i].flags, CPUINFO_LINUX_FLAG_VALID)) {
			if (cpuinfo_linux_get_processor_package_id(i, &powerpc_linux_processors[i].package_id)) {
				powerpc_linux_processors[i].flags |= CPUINFO_LINUX_FLAG_PACKAGE_ID;
			}
			powerpc_linux_processors[i].package_leader_id = i;
		}
	}

	cpuinfo_log_debug("cpuinfo_powerpc_linux_init(): decode_vendor_uarch\n");
	for (uint32_t i = 0; i < powerpc_linux_processors_count; i++) {
		if (bitmask_all(powerpc_linux_processors[i].flags, CPUINFO_LINUX_FLAG_VALID)) {
			const uint32_t cluster_leader = powerpc_linux_processors[i].package_leader_id;
			if (cluster_leader == i) {
				cpuinfo_powerpc_decode_vendor_uarch(
				powerpc_linux_processors[i].pvr,
				&powerpc_linux_processors[i].vendor,
				&powerpc_linux_processors[i].uarch);
			} else {
				powerpc_linux_processors[i].flags |= (powerpc_linux_processors[cluster_leader].flags & CPUINFO_LINUX_FLAG_MAX_FREQUENCY);
				powerpc_linux_processors[i].pvr = powerpc_linux_processors[cluster_leader].pvr;
				powerpc_linux_processors[i].vendor = powerpc_linux_processors[cluster_leader].vendor;
				powerpc_linux_processors[i].uarch = powerpc_linux_processors[cluster_leader].uarch;
				powerpc_linux_processors[i].max_frequency = powerpc_linux_processors[cluster_leader].max_frequency;
			}
		}
	}


	packages = calloc(package_count, sizeof(struct cpuinfo_package));
	if (packages == NULL) {
		cpuinfo_log_error("failed to allocate %zu bytes for descriptions of %"PRIu32" core packages",
			package_count * sizeof(struct cpuinfo_package), package_count);
			exit(-1);
	}
	uint32_t cluster_count = package_count;
	clusters = calloc(cluster_count, sizeof(struct cpuinfo_cluster));
	if (clusters == NULL) {
		cpuinfo_log_error("failed to allocate %zu bytes for descriptions of %"PRIu32" core clusters",
			cluster_count * sizeof(struct cpuinfo_cluster), cluster_count);
			exit(-1);
	}
	// uint32_t cluster_count = 0;
	for (uint32_t i = 0; i < package_count; i++) {
		struct cpuinfo_powerpc_chipset chipset = {
			.vendor = cpuinfo_powerpc_chipset_vendor_unknown,
			.model  = cpuinfo_powerpc_chipset_model_unknown,
		};
		cpuinfo_powerpc_chipset_decode(powerpc_linux_processors[packages[i].processor_start].pvr, &chipset);
		cpuinfo_powerpc_chipset_to_string(&chipset, packages[i].name);
		packages[i].processor_start = package_infos[i].proc_id;
		packages[i].processor_count = package_infos[i].proc_count;
		packages[i].core_start = package_infos[i].core_id;
		packages[i].core_count = package_infos[i].core_count;
		packages[i].cluster_start = package_infos[i].cluster_id;
		packages[i].cluster_count = package_infos[i].cluster_count;

		clusters[i].processor_start = package_infos[i].proc_id;
		clusters[i].processor_count = package_infos[i].proc_count;
		clusters[i].core_start = package_infos[i].core_id;
		clusters[i].core_count = package_infos[i].core_count;
		clusters[i].cluster_id = 0;
		clusters[i].package = &packages[i];
		// cluster_count += package_infos[i].cluster_count;
		clusters[i].vendor = powerpc_linux_processors[packages[i].processor_start].vendor;
		clusters[i].uarch = powerpc_linux_processors[packages[i].processor_start].uarch;
	}

	cores = calloc(core_count, sizeof(struct cpuinfo_core));
	if (cores == NULL) {
		cpuinfo_log_error("failed to allocate %zu bytes for descriptions of %"PRIu32" cores",
			sizeof(struct cpuinfo_core), usable_processors);
		exit(-1);
	}
	for (uint32_t i = 0; i < core_count; i++) {
		cores[i].processor_start = core_infos[i].proc_id;
		cores[i].processor_count = core_infos[i].proc_count;
		cores[i].core_id = i;
		cores[i].package = &packages[i/package_infos[0].core_count];
		cores[i].vendor = powerpc_linux_processors[0].vendor;
		cores[i].uarch = powerpc_linux_processors[0].uarch;
	}

	linux_cpu_to_processor_map = calloc(powerpc_linux_processors_count, sizeof(struct cpuinfo_processor*));
	if (linux_cpu_to_processor_map == NULL) {
		cpuinfo_log_error("failed to allocate %zu bytes for %"PRIu32" logical processor mapping entries",
			powerpc_linux_processors_count * sizeof(struct cpuinfo_processor*), powerpc_linux_processors_count);
		exit(-1);
	}

	linux_cpu_to_core_map = calloc(powerpc_linux_processors_count, sizeof(struct cpuinfo_core*));
	if (linux_cpu_to_core_map == NULL) {
		cpuinfo_log_error("failed to allocate %zu bytes for mapping entries of %"PRIu32" cores",
		powerpc_linux_processors_count * sizeof(struct cpuinfo_core*),
		powerpc_linux_processors_count);
		exit(-1);
	}

	processors = calloc(usable_processors, sizeof(struct cpuinfo_processor));
	if (processors == NULL) {
		cpuinfo_log_error("failed to allocate %zu bytes for descriptions of %"PRIu32" logical processors",
			sizeof(struct cpuinfo_processor), usable_processors);
		exit(-1);
	}

	uint32_t procs_per_core = core_infos[0].proc_count;
	for (uint32_t i = 0; i < usable_processors; i++) {
		cpuinfo_log_debug("filling info: processor %"PRIu32"", i);
		processors[i].smt_id = i % cores[i/procs_per_core].processor_count;
		processors[i].core = &cores[i/procs_per_core];
		processors[i].cluster = &clusters[i/package_infos[0].proc_count];
		processors[i].package = &packages[i/package_infos[0].proc_count];
		processors[i].linux_id = (int) powerpc_linux_processors[i].system_processor_id;
		processors[i].cache.l1i = l1i + i/procs_per_cache_level[0];
		processors[i].cache.l1d = l1d + i/procs_per_cache_level[1];
		processors[i].cache.l2 = l2 + i/procs_per_cache_level[2];
		processors[i].cache.l3 = l3 + i/procs_per_cache_level[3];
		linux_cpu_to_processor_map[powerpc_linux_processors[i].system_processor_id] = &processors[i];
		linux_cpu_to_core_map[powerpc_linux_processors[i].system_processor_id] = &cores[i/procs_per_core];
		cores[i/procs_per_core].cluster = &clusters[i/package_infos[0].proc_count];
	}

	cpuinfo_log_warning("Initialization done!\n");



	/* Commit */
	cpuinfo_processors = processors;
	cpuinfo_cores = cores;
	cpuinfo_packages = packages;
	cpuinfo_clusters = clusters;
	cpuinfo_global_uarch = (struct cpuinfo_uarch_info) {
		.uarch=clusters[0].uarch,
		.processor_count=usable_processors,
		.core_count = core_count};
	cpuinfo_cache[cpuinfo_cache_level_1i] = l1i;
	cpuinfo_cache[cpuinfo_cache_level_1d] = l1d;
	cpuinfo_cache[cpuinfo_cache_level_2]  = l2;
	cpuinfo_cache[cpuinfo_cache_level_3]  = l3;

	cpuinfo_processors_count = usable_processors;
	cpuinfo_cores_count = core_count;
	cpuinfo_clusters_count = cluster_count;
	cpuinfo_packages_count = 1;
	cpuinfo_cache_count[cpuinfo_cache_level_1i] = cache_level_counts[0];
	cpuinfo_cache_count[cpuinfo_cache_level_1d] = cache_level_counts[1];
	cpuinfo_cache_count[cpuinfo_cache_level_2]  = cache_level_counts[2];
	cpuinfo_cache_count[cpuinfo_cache_level_3]  = cache_level_counts[3];
	cpuinfo_max_cache_size = cpuinfo_compute_max_cache_size(&processors[0]);

	cpuinfo_linux_cpu_to_processor_map = linux_cpu_to_processor_map;
	cpuinfo_linux_cpu_to_core_map = linux_cpu_to_core_map;


	__sync_synchronize();
	cpuinfo_is_initialized = true;

	processors = NULL;
	cores = NULL;
	clusters = NULL;
	l1i = l1d = l2 = l3 = NULL;
	linux_cpu_to_processor_map = NULL;
	linux_cpu_to_core_map = NULL;

cleanup:
	free(powerpc_linux_processors);
	free(processors);
	free(cores);
	free(clusters);
	free(l1i);
	free(l1d);
	free(l2);
	free(l3);
	free(linux_cpu_to_processor_map);
	free(linux_cpu_to_core_map);
}
