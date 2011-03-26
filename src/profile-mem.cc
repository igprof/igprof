#include "profile.h"
#include "profile-trace.h"
#include "hook.h"
#include "walk-syms.h"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <pthread.h>
#include <malloc.h>

// -------------------------------------------------------------------
// Traps for this profiler module
DUAL_HOOK(1, void *, domalloc, _main, _libc,
          (size_t n), (n),
          "malloc", 0, "libc.so.6")
DUAL_HOOK(2, void *, docalloc, _main, _libc,
          (size_t n, size_t m), (n, m),
          "calloc", 0, "libc.so.6")
DUAL_HOOK(2, void *, dorealloc, _main, _libc,
          (void *ptr, size_t n), (ptr, n),
          "realloc", 0, "libc.so.6")
DUAL_HOOK(3, int, dopmemalign, _main, _libc,
          (void **ptr, size_t alignment, size_t size),
          (ptr, alignment, size),
          "posix_memalign", 0, "libc.so.6")
DUAL_HOOK(2, void *, domemalign, _main, _libc,
          (size_t alignment, size_t size), (alignment, size),
          "memalign", 0, "libc.so.6")
DUAL_HOOK(1, void *, dovalloc, _main, _libc,
          (size_t size), (size),
          "valloc", 0, "libc.so.6")
DUAL_HOOK(1, void, dofree, _main, _libc,
          (void *ptr), (ptr),
          "free", 0, "libc.so.6")

// Data for this profiler module
static const int                OVERHEAD_NONE   = 0; // Memory use without malloc overheads
static const int                OVERHEAD_WITH   = 1; // Memory use including malloc overheads
static const int                OVERHEAD_DELTA  = 2; // Memory use malloc overhead only

static IgProfTrace::CounterDef  s_ct_total      = { "MEM_TOTAL",    IgProfTrace::TICK, -1 };
static IgProfTrace::CounterDef  s_ct_largest    = { "MEM_MAX",      IgProfTrace::MAX, -1 };
static IgProfTrace::CounterDef  s_ct_live       = { "MEM_LIVE",     IgProfTrace::TICK_PEAK, -1 };
static bool                     s_count_total   = 0;
static bool                     s_count_largest = 0;
static bool                     s_count_live    = 0;
static int                      s_overhead      = OVERHEAD_NONE;
static bool                     s_initialized   = false;
static int                      s_moduleid      = -1;

/** Record an allocation at @a ptr of @a size bytes.  Increments counters
    in the tree for the allocations as per current configuration and adds
    the pointer to current live memory map if we are tracking leaks.  */
static void  __attribute__((noinline))
add(void *ptr, size_t size)
{
  uint64_t tstart, tend;
  IgProfTrace *buf = igprof_buffer(s_moduleid);
  if (! buf)
    return;

  if (s_overhead != OVERHEAD_NONE)
  {
    size_t actual = malloc_usable_size(ptr);
    if (s_overhead == OVERHEAD_DELTA)
    {
      if ((size = actual - size) == 0)
        return;
    }
    else
      size = actual;
  }

  RDTSC(tstart);

  void                  *addresses [IgProfTrace::MAX_DEPTH];
  int                   depth = IgHookTrace::stacktrace(addresses, IgProfTrace::MAX_DEPTH);
  IgProfTrace::Record   entries [3];
  int                   nentries = 0;

  RDTSC(tend);

  if (s_count_total)
  {
    entries[nentries].type = IgProfTrace::COUNT;
    entries[nentries].def = &s_ct_total;
    entries[nentries].amount = size;
    entries[nentries].ticks = 1;
    nentries++;
  }

  if (s_count_largest)
  {
    entries[nentries].type = IgProfTrace::COUNT;
    entries[nentries].def = &s_ct_largest;
    entries[nentries].amount = size;
    entries[nentries].ticks = 1;
    nentries++;
  }

  if (s_count_live)
  {
    entries[nentries].type = IgProfTrace::COUNT | IgProfTrace::ACQUIRE;
    entries[nentries].def = &s_ct_live;
    entries[nentries].amount = size;
    entries[nentries].ticks = 1;
    entries[nentries].resource = (IgProfTrace::Address) ptr;
    nentries++;
  }

  // Drop three top ones (stacktrace, me, hook).
  buf->push(addresses+3, depth-3, entries, nentries,
	    IgProfTrace::statFrom(depth, tstart, tend));
}

/** Remove knowledge about allocation.  If we are tracking leaks,
    removes the memory allocation from the live map and subtracts
    from the live memory counters.  */
static void
remove (void *ptr)
{
  if (s_count_live && ptr)
  {
    IgProfTrace *buf = igprof_buffer(s_moduleid);
    if (! buf)
      return;

    IgProfTrace::PerfStat perf = { 0, 0, 0, 0, 0, 0, 0 };
    IgProfTrace::Record entry
      = { IgProfTrace::RELEASE, &s_ct_live, 0, 0, (IgProfTrace::Address) ptr };
    buf->push(0, 0, &entry, 1, perf);
  }
}

// -------------------------------------------------------------------
/** Initialise memory profiling.  Traps various system calls to keep track
    of memory usage, and if requested, leaks.  */
static void
initialize(void)
{
  if (s_initialized) return;
  s_initialized = true;

  const char    *options = igprof_options();
  bool          enable = false;
  bool          opts = false;

  while (options && *options)
  {
    while (*options == ' ' || *options == ',')
      ++options;

    if (! strncmp(options, "mem", 3))
    {
      enable = true;
      options += 3;
      while (*options)
      {
        if (! strncmp(options, ":total", 6))
        {
          s_count_total = 1;
          options += 6;
          opts = true;
        }
        else if (! strncmp(options, ":largest", 8))
        {
          s_count_largest = 1;
          options += 8;
          opts = true;
        }
        else if (! strncmp(options, ":live", 5))
        {
          s_count_live = 1;
          options += 5;
          opts = true;
        }
        else if (! strncmp(options, ":all", 4))
        {
          s_count_total = 1;
          s_count_largest = 1;
          s_count_live = 1;
          options += 4;
          opts = true;
        }
        else if (! strncmp(options, ":overhead=none", 14))
        {
          s_overhead = OVERHEAD_NONE;
          options += 14;
        }
        else if (! strncmp(options, ":overhead=include", 17))
        {
          s_overhead = OVERHEAD_WITH;
          options += 17;
        }
        else if (! strncmp(options, ":overhead=delta", 15))
        {
          s_overhead = OVERHEAD_DELTA;
          options += 15;
        }
        else
          break;
      }
    }
    else
      options++;

    while (*options && *options != ',' && *options != ' ')
      options++;
  }

  if (! enable)
    return;

  if (! igprof_init(&s_moduleid, 0, false))
    return;

  igprof_disable(true);
  if (! opts)
  {
    igprof_debug("Memory: defaulting to total memory counting\n");
    s_count_total = 1;
  }
  else
  {
    if (s_count_total)
      igprof_debug("Memory: enabling total counting\n");
    if (s_count_largest)
      igprof_debug("Memory: enabling max counting\n");
    if (s_count_live)
      igprof_debug("Memory: enabling live counting\n");
  }
  igprof_debug("Memory: reporting %sallocation overhead%s\n",
               (s_overhead == OVERHEAD_NONE ? "memory use without "
                : s_overhead == OVERHEAD_WITH ? "memory use with " : ""),
               (s_overhead == OVERHEAD_DELTA ? " only" : ""));

  IgHook::hook(domalloc_hook_main.raw);
  IgHook::hook(docalloc_hook_main.raw);
  IgHook::hook(dorealloc_hook_main.raw);
  IgHook::hook(dopmemalign_hook_main.raw);
  IgHook::hook(domemalign_hook_main.raw);
  IgHook::hook(dovalloc_hook_main.raw);
  IgHook::hook(dofree_hook_main.raw);
#if __linux
  if (domalloc_hook_main.raw.chain)    IgHook::hook(domalloc_hook_libc.raw);
  if (docalloc_hook_main.raw.chain)    IgHook::hook(docalloc_hook_libc.raw);
  if (domemalign_hook_main.raw.chain)  IgHook::hook(domemalign_hook_libc.raw);
  if (dovalloc_hook_main.raw.chain)    IgHook::hook(dovalloc_hook_libc.raw);
  if (dofree_hook_main.raw.chain)      IgHook::hook(dofree_hook_libc.raw);
#endif
  igprof_debug("Memory profiler enabled\n");
  igprof_enable(true);
}

// -------------------------------------------------------------------
// Traps for this profiler module.  Track memory allocation routines.
static void *
domalloc(IgHook::SafeData<igprof_domalloc_t> &hook, size_t n)
{
  bool enabled = igprof_disable(false);
  void *result = (*hook.chain)(n);

  if (enabled && result)
    add(result, n);

  igprof_enable(false);
  return result;
}

static void *
docalloc(IgHook::SafeData<igprof_docalloc_t> &hook, size_t n, size_t m)
{
  bool enabled = igprof_disable(false);
  void *result = (*hook.chain)(n, m);

  if (enabled && result)
    add(result, n * m);

  igprof_enable(false);
  return result;
}

static void *
dorealloc(IgHook::SafeData<igprof_dorealloc_t> &hook, void *ptr, size_t n)
{
  bool enabled = igprof_disable(false);
  void *result = (*hook.chain)(ptr, n);

  if (result)
  {
    if (ptr) remove(ptr);
    if (enabled && result) add(result, n);
  }

  igprof_enable(false);
  return result;
}

static void *
domemalign(IgHook::SafeData<igprof_domemalign_t> &hook, size_t alignment, size_t size)
{
  bool enabled = igprof_disable(false);
  void *result = (*hook.chain)(alignment, size);

  if (enabled && result)
    add(result, size);

  igprof_enable(false);
  return result;
}

static void *
dovalloc(IgHook::SafeData<igprof_dovalloc_t> &hook, size_t size)
{
  bool enabled = igprof_disable(false);
  void *result = (*hook.chain)(size);

  if (enabled && result)
    add(result, size);

  igprof_enable(false);
  return result;
}

static int
dopmemalign(IgHook::SafeData<igprof_dopmemalign_t> &hook,
            void **ptr, size_t alignment, size_t size)
{
  bool enabled = igprof_disable(false);
  int result = (*hook.chain)(ptr, alignment, size);

  if (enabled && ptr && *ptr)
    add(*ptr, size);

  igprof_enable(false);
  return result;
}

static void
dofree(IgHook::SafeData<igprof_dofree_t> &hook, void *ptr)
{
  igprof_disable(false);
  remove(ptr);
  (*hook.chain)(ptr);
  igprof_enable(false);
}

// -------------------------------------------------------------------
static bool autoboot = (initialize(), true);
