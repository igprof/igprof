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
          "malloc", 0, igprof_getenv("IGPROF_MALLOC_LIB"))
DUAL_HOOK(2, void *, docalloc, _main, _libc,
          (size_t n, size_t m), (n, m),
          "calloc", 0, igprof_getenv("IGPROF_MALLOC_LIB"))
DUAL_HOOK(2, void *, dorealloc, _main, _libc,
          (void *ptr, size_t n), (ptr, n),
          "realloc", 0, igprof_getenv("IGPROF_MALLOC_LIB"))
DUAL_HOOK(3, int, dopmemalign, _main, _libc,
          (void **ptr, size_t alignment, size_t size),
          (ptr, alignment, size),
          "posix_memalign", 0, igprof_getenv("IGPROF_MALLOC_LIB"))
DUAL_HOOK(2, void *, domemalign, _main, _libc,
          (size_t alignment, size_t size), (alignment, size),
          "memalign", 0, igprof_getenv("IGPROF_MALLOC_LIB"))
DUAL_HOOK(1, void *, dovalloc, _main, _libc,
          (size_t size), (size),
          "valloc", 0, igprof_getenv("IGPROF_MALLOC_LIB"))
DUAL_HOOK(1, void, dofree, _main, _libc,
          (void *ptr), (ptr),
          "free", 0, igprof_getenv("IGPROF_MALLOC_LIB"))

// Data for this profiler module
static const int                OVERHEAD_NONE   = 0; // Memory use without malloc overheads
static const int                OVERHEAD_WITH   = 1; // Memory use including malloc overheads
static const int                OVERHEAD_DELTA  = 2; // Memory use malloc overhead only

static IgProfTrace::CounterDef  s_ct_total      = { "MEM_TOTAL",    IgProfTrace::TICK, -1 };
static IgProfTrace::CounterDef  s_ct_largest    = { "MEM_MAX",      IgProfTrace::MAX, -1 };
static IgProfTrace::CounterDef  s_ct_live       = { "MEM_LIVE",     IgProfTrace::TICK, -1 };
static int                      s_overhead      = OVERHEAD_NONE;
static bool                     s_initialized   = false;

static unsigned char s_zero_page[4096];

/** Record an allocation at @a ptr of @a size bytes.  Increments counters
    in the tree for the allocations as per current configuration and adds
    the pointer to current live memory map if we are tracking leaks.  */
static void  __attribute__((noinline))
add(void *ptr, size_t size)
{
  void *addresses[IgProfTrace::MAX_DEPTH];
  IgProfTrace *buf = igprof_buffer();
  IgProfTrace::Stack *frame;
  IgProfTrace::Counter *ctr;
  uint64_t tstart, tend;
  int depth;

  if (UNLIKELY(! buf))
    return;

  if (UNLIKELY(s_overhead != OVERHEAD_NONE))
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
  depth = IgHookTrace::stacktrace(addresses, IgProfTrace::MAX_DEPTH);
  RDTSC(tend);

  // Drop top two stack frames (me, hook).
  buf->lock();
  frame = buf->push(addresses+2, depth-2);
  //buf->tick(frame, &s_ct_total, size, 1);
  buf->tick(frame, &s_ct_largest, size, 1);
  ctr = buf->tick(frame, &s_ct_live, size, 1);
  buf->acquire(ctr, (IgProfTrace::Address) ptr, size);
  buf->traceperf(depth, tstart, tend);
  buf->unlock();
}

/** Remove knowledge about allocation.  If we are tracking leaks,
    removes the memory allocation from the live map and subtracts
    from the live memory counters.  */
static void
remove (void *ptr)
{
  if (LIKELY(ptr))
  {
    IgProfTrace *buf = igprof_buffer();
    if (UNLIKELY(! buf))
      return;

    //igprof_debug("Hi, we are in free()\n");
    
    buf->lock();
    IgProfTrace::HResource *hres = buf->findResource((IgProfTrace::Address) ptr);
    ASSERT(! hres || ! hres->record || hres->resource == (IgProfTrace::Address) ptr);
    
    if (hres && hres->record) {
      IgProfTrace::Resource *res = hres->record;
      IgProfTrace::Counter *ctr = res->counter;
      ASSERT(ctr);
      uint64_t zero_pages = 0;
      unsigned char *mem_itr = (unsigned char *) res->hashslot->resource;
      unsigned char *mem_end = mem_itr + res->size;
      for (; mem_itr < mem_end-4096; mem_itr += 4096) {
        zero_pages += !memcmp(mem_itr, s_zero_page, 4096);
      }
      buf->tick(ctr->frame, &s_ct_total, zero_pages*4096, 1);
      //igprof_debug("resource found, zero pages %d\n", zero_pages);
    }
    
    buf->release((IgProfTrace::Address) ptr);
    buf->unlock();
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
  
  memset(s_zero_page, 0, 4096);

  const char    *options = igprof_options();
  bool          enable = false;

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
        if (! strncmp(options, ":overhead=none", 14))
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

  if (! igprof_init("memory profiler", 0, false))
    return;

  igprof_disable_globally();
  igprof_debug("memory profiler: reporting %sallocation overhead%s\n",
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
  igprof_debug("memory profiler enabled\n");
  igprof_enable_globally();
}

// -------------------------------------------------------------------
// Traps for this profiler module.  Track memory allocation routines.
static void *
domalloc(IgHook::SafeData<igprof_domalloc_t> &hook, size_t n)
{
  bool enabled = igprof_disable();
  void *result = (*hook.chain)(n);

  if (LIKELY(enabled && result))
    add(result, n);
  
  if (result)
    memset(result, 1, n);

  igprof_enable();
  return result;
}

static void *
docalloc(IgHook::SafeData<igprof_docalloc_t> &hook, size_t n, size_t m)
{
  bool enabled = igprof_disable();
  void *result = (*hook.chain)(n, m);

  if (LIKELY(enabled && result))
    add(result, n * m);

  igprof_enable();
  return result;
}

static void *
dorealloc(IgHook::SafeData<igprof_dorealloc_t> &hook, void *ptr, size_t n)
{
  bool enabled = igprof_disable();
  void *result = (*hook.chain)(ptr, n);

  if (LIKELY(result))
  {
    if (ptr) {
      IgProfTrace *buf = igprof_buffer();
    
      if (buf) {
        buf->lock();
        IgProfTrace::HResource *hres = buf->findResource((IgProfTrace::Address) ptr);
        ASSERT(! hres || ! hres->record || hres->resource == (IgProfTrace::Address) ptr);
    
        if (hres && hres->record) {
          IgProfTrace::Resource *res = hres->record;
          size_t size = res->size;
          if (res->size < n)
            memset(((char *)result)+res->size, 1, n-res->size);
        }
      }
    }
    
    if (LIKELY(ptr)) remove(ptr);
    if (LIKELY(enabled && result)) add(result, n);
  }

  igprof_enable();
  return result;
}

static void *
domemalign(IgHook::SafeData<igprof_domemalign_t> &hook, size_t alignment, size_t size)
{
  bool enabled = igprof_disable();
  void *result = (*hook.chain)(alignment, size);

  if (LIKELY(enabled && result))
    add(result, size);
  
  if (result)
    memset(result, 1, size);

  igprof_enable();
  return result;
}

static void *
dovalloc(IgHook::SafeData<igprof_dovalloc_t> &hook, size_t size)
{
  bool enabled = igprof_disable();
  void *result = (*hook.chain)(size);

  if (LIKELY(enabled && result))
    add(result, size);
  
  if (result)
    memset(result, 1, size);

  igprof_enable();
  return result;
}

static int
dopmemalign(IgHook::SafeData<igprof_dopmemalign_t> &hook,
            void **ptr, size_t alignment, size_t size)
{
  bool enabled = igprof_disable();
  int result = (*hook.chain)(ptr, alignment, size);

  if (LIKELY(enabled && ptr && *ptr))
    add(*ptr, size);
  
  if (result)
    memset(*ptr, 1, size);

  igprof_enable();
  return result;
}

static void
dofree(IgHook::SafeData<igprof_dofree_t> &hook, void *ptr)
{
  igprof_disable();
  remove(ptr);
  (*hook.chain)(ptr);
  igprof_enable();
}


// -------------------------------------------------------------------
static bool autoboot = (initialize(), true);
