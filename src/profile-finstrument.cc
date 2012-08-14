#include "profile.h"
#include <cstdio>
#include <cstring>
#include "profile-trace.h"
#include "walk-syms.h"

static void do_enter();
static IgHook::TypedData<void()> do_enter_hook = { { 0, "__cyg_profile_func_enter",
       0, 0, &do_enter, 0, 0, 0 } };

static void do_exit();
static IgHook::TypedData<void()> do_exit_hook = { { 0, "__cyg_profile_func_exit",
       0, 0, &do_exit, 0, 0, 0 } };

static bool s_initialized = false;
static IgProfTrace::CounterDef  s_ct_time      = { "CALL_TIME",    IgProfTrace::TICK, -1 };
static IgProfTrace::CounterDef  s_ct_calls     = { "CALL_COUNT",   IgProfTrace::TICK, -1 };
uint64_t times[IgProfTrace::MAX_DEPTH];
int callCount = 0;

static void 
initialize(void)
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

  IgHook::hook(do_enter_hook.raw);
  IgHook::hook(do_exit_hook.raw);

  igprof_disable_globally();
  igprof_debug("gcc finstrument-profiler\n");
  igprof_debug("finstrument-profiler enabled\n");
  igprof_enable_globally();
}

extern "C" void __cyg_profile_func_enter(void *func UNUSED, void *caller UNUSED){}
extern "C" void __cyg_profile_func_exit(void *func UNUSED, void *caller UNUSED){}

static void 
do_enter ()
{
    int64_t tstart;
    callCount++;
    RDTSC(tstart);
    times[callCount-1] = tstart; 
}

static void 
do_exit ()
{
    uint64_t tstop;
    RDTSC(tstop);
    callCount--;
    void *addresses[IgProfTrace::MAX_DEPTH];
    IgProfTrace *buf = igprof_buffer();
    IgProfTrace::Stack *frame;
    int depth;

    if (UNLIKELY(! buf))
      return;

    depth = IgHookTrace::stacktrace(addresses, IgProfTrace::MAX_DEPTH);
     
    buf->lock();
    frame = buf->push(addresses+1, depth-1);
    buf->tick(frame, &s_ct_calls, 1, 1);
    buf->tick(frame, &s_ct_time, (tstop-times[callCount]), 1);
    buf->unlock();
}

static bool autoboot = (initialize(), true);
