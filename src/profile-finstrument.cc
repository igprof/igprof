#include "profile.h"
#include <pthread.h>
#include "time.h"
#include <cstdio>
#include <cstring>
#include "profile-trace.h"
#include "walk-syms.h"

static bool s_initialized = false;
static IgProfTrace::CounterDef  s_ct_calls      = { "CALLS_TOTAL",    IgProfTrace::TICK, -1 };

static void __attribute__((noinline))
add()
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

  buf->lock();
  frame = buf->push(addresses+2, depth-2);
  buf->tick(frame, &s_ct_calls, 1, 1);
  buf->traceperf(depth, tstart, tend);
  buf->unlock();

}

static void initialize(void)
{
  if (s_initialized) return;
  s_initialized = true;
  
  const char* options = igprof_options();
  bool enable = false;

  
  while (options && *options)
  {
    while (*options == ' ' || *options == ',')
      ++options;
    if (! strncmp(options, "finst", 5))
    {
      options = options + 5;
      enable = true; 
    }
    else
      options++;

    while (*options && *options != ',' && *options != ' ')
      options++;
  }
  if (! enable)
    return;

  if (! igprof_init("finstrument-profiler", 0, false))
    return;

  igprof_disable_globally();
  igprof_debug("gcc finstrument-profiler\n");

  igprof_debug("finstrument-profiler enabled\n");
  igprof_enable_globally();
}

//finstrument enter function
extern "C" void __cyg_profile_func_enter (void *this_fn UNUSED, void *caller UNUSED)
{
  bool enabled = igprof_disable();
  if (LIKELY(enabled))
    add();
  igprof_enable();
}


static bool autoboot = (initialize(), true);
