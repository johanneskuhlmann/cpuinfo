#include <stdint.h>

#include <powerpc/linux/api.h>
#include <cpuinfo/log.h>

void cpuinfo_ppc64_linux_decode_isa_from_proc_cpuinfo(
	uint32_t features,
	struct cpuinfo_powerpc_isa isa[restrict static 1])
{
	/* TODO(rcardoso): Decoder. */
}