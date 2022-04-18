#ifndef kernel_resolver_h
#define kernel_resolver_h

#include <mach/mach_types.h>
#include <mach-o/loader.h>
#include <mach-o/getsect.h>
#include <sys/types.h>
#include <sys/sysctl.h>
// #include <sys/systm.h>
// #include <vm/vm_kern.h>

#ifdef __cplusplus
extern "C" {
#endif
    
int lookup_symbol(const char *symbol, void** symbol_out);
int find_symbol(struct mach_header_64 *mh, const char *name, void** symaddr_out);
struct segment_command_64* find_segment_64(struct mach_header_64 *mh, const char *segname);
int resolve_live_symbol(struct mach_header_64* mach_static, struct mach_header_64* mach_dyn, const char *symbol, void** symbol_out);

#ifdef __cplusplus
}
#endif

#endif /* kernel_resolver_h */

