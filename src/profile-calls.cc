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

static IgProfTrace::CounterDef  s_ct_total      = { "CALLS_TOTAL",    IgProfTrace::TICK, -1 };
static bool                     s_initialized   = false;

/** Records calling a given function (only free for the moment). */
static void  __attribute__((noinline))
add(size_t ticks)
{
  void *addresses[IgProfTrace::MAX_DEPTH];
  IgProfTrace *buf = igprof_buffer();
  IgProfTrace::Stack *frame;
  uint64_t tstart, tend;
  int depth;

  if (UNLIKELY(! buf))
    return;

  RDTSC(tstart);
  depth = IgHookTrace::stacktrace(addresses, IgProfTrace::MAX_DEPTH);
  RDTSC(tend);

  // Drop top two stack frames (me, hook).
  buf->lock();
  frame = buf->push(addresses+2, depth-2);
  buf->tick(frame, &s_ct_total, ticks, 1);
  buf->traceperf(depth, tstart, tend);
  buf->unlock();
}

// -------------------------------------------------------------------
/** Initialise function profiling. For the moment only profiles calls to
    free and *alloc related symbols. */
static void
initialize(void)
{
  if (s_initialized) return;
  s_initialized = true;

  const char    *options = igprof_options();
  bool          enable = false;
  bool          trace_malloc = false;
  bool          trace_free = false;

  while (options && *options)
  {
    while (*options == ' ' || *options == ',')
      ++options;

    if (! strncmp(options, "func", 4))
    {
      options = options + 4;
      enable = true;
      while (*options)
      {
        if (! strncmp(options, ":name=free", 10))
        {
          trace_free=true;
          options += 10;
        }
        else if (! strncmp(options, ":name=malloc", 12))
        {
          trace_malloc=true;
          options += 12;
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

  if ((! trace_malloc) && (! trace_free))
  {
    igprof_debug("function profiler: can only profile malloc and free for the time being\n");
    return;
  }

  if (! igprof_init("function profiler", 0, false))
    return;

  igprof_disable_globally();
  igprof_debug("function profiler: profiling %s\n",
               (trace_free ? "free" : "alloc"));

  if (trace_free)
    IgHook::hook(dofree_hook_main.raw);
  else
  {
    IgHook::hook(domalloc_hook_main.raw);
    IgHook::hook(docalloc_hook_main.raw);
    IgHook::hook(dorealloc_hook_main.raw);
    IgHook::hook(dopmemalign_hook_main.raw);
    IgHook::hook(domemalign_hook_main.raw);
    IgHook::hook(dovalloc_hook_main.raw);
  }

#if __linux
  if (trace_free)
  {
    if (dofree_hook_main.raw.chain)      IgHook::hook(dofree_hook_libc.raw);
  }
  else
  {
    if (domalloc_hook_main.raw.chain)    IgHook::hook(domalloc_hook_libc.raw);
    if (docalloc_hook_main.raw.chain)    IgHook::hook(docalloc_hook_libc.raw);
    if (domemalign_hook_main.raw.chain)  IgHook::hook(domemalign_hook_libc.raw);
    if (dovalloc_hook_main.raw.chain)    IgHook::hook(dovalloc_hook_libc.raw);
  }
#endif
  igprof_enable_globally();
}

// -------------------------------------------------------------------
// Traps for this profiler module.  Track memory allocation routines.
static void *
domalloc(IgHook::SafeData<igprof_domalloc_t> &hook, size_t n)
{
  bool enabled = igprof_disable();
  uint64_t tstart, tend;

  RDTSC(tstart);
  void *result = (*hook.chain)(n);
  RDTSC(tend);

  if (LIKELY(enabled))
    add(tend - tstart);

  igprof_enable();
  return result;
}

static void *
docalloc(IgHook::SafeData<igprof_docalloc_t> &hook, size_t n, size_t m)
{
  bool enabled = igprof_disable();
  uint64_t tstart, tend;

  RDTSC(tstart);
  void *result = (*hook.chain)(n, m);
  RDTSC(tend);

  if (LIKELY(enabled))
    add(tend-tstart);

  igprof_enable();
  return result;
}

static void *
dorealloc(IgHook::SafeData<igprof_dorealloc_t> &hook, void *ptr, size_t n)
{
  bool enabled = igprof_disable();
  uint64_t tstart, tend;

  RDTSC(tstart);
  void *result = (*hook.chain)(ptr, n);
  RDTSC(tend);

  if (LIKELY(enabled))
    add(tend-tstart);

  igprof_enable();
  return result;
}

static void *
domemalign(IgHook::SafeData<igprof_domemalign_t> &hook, size_t alignment, size_t size)
{
  bool enabled = igprof_disable();
  uint64_t tstart, tend;

  RDTSC(tstart);
  void *result = (*hook.chain)(alignment, size);
  RDTSC(tend);

  if (LIKELY(enabled))
    add(tend-tstart);

  igprof_enable();
  return result;
}

static void *
dovalloc(IgHook::SafeData<igprof_dovalloc_t> &hook, size_t size)
{
  bool enabled = igprof_disable();
  uint64_t tstart, tend;

  RDTSC(tstart);
  void *result = (*hook.chain)(size);
  RDTSC(tend);

  if (LIKELY(enabled))
    add(tend-tstart);

  igprof_enable();
  return result;
}

static int
dopmemalign(IgHook::SafeData<igprof_dopmemalign_t> &hook,
            void **ptr, size_t alignment, size_t size)
{
  bool enabled = igprof_disable();
  uint64_t tstart, tend;

  RDTSC(tstart);
  int result = (*hook.chain)(ptr, alignment, size);
  RDTSC(tend);

  if (LIKELY(enabled))
    add(tend-tstart);

  igprof_enable();
  return result;
}

static void
dofree(IgHook::SafeData<igprof_dofree_t> &hook, void *ptr)
{
  bool enabled = igprof_disable();
  uint64_t tstart, tend;

  RDTSC(tstart);
  (*hook.chain)(ptr);
  RDTSC(tend);

  if (LIKELY(enabled))
    add(tend-tstart);

  igprof_enable();
}

// -------------------------------------------------------------------
static bool autoboot = (initialize(), true);
