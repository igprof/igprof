#include "hook.h"
#include "profile.h"
#include "profile-trace.h"
#include "walk-syms.h"
#include <cstdio>
#include <cstring>
#include <stdint.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

typedef void*(*intFunction)(void*,void*,void*,void*,void*,void*);
typedef double(*doubleFunction)(void*,void*,void*,void*,void*,void*);

intFunction chainFunctionsInt[20];
doubleFunction chainFunctionsDouble[20];
intFunction chainFunctionsEnter[20];
intFunction chainFunctionsExit[20];
doubleFunction chainFunctionsEnterDouble[20];
doubleFunction chainFunctionsExitDouble[20];

static bool s_initialized = false;
static IgProfTrace::CounterDef  s_ct_total      = { "CALLS_TOTAL",    IgProfTrace::TICK, -1, 0 };
static IgProfTrace::CounterDef  s_ct_enter      = { "ENTER_COUNT",    IgProfTrace::TICK, -1, 0 };
static IgProfTrace::CounterDef  s_ct_exit       = { "EXIT_COUNT",     IgProfTrace::TICK, -1, 0 };
/** Records calling a given function (only free for the moment). */

// Ticks time counter
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

// Ticks enter call counter 
static void  __attribute__((noinline))
add_enter()
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
  buf->tick(frame, &s_ct_enter, 1, 1);
  buf->traceperf(depth, tstart, tend);
  buf->unlock();
}

// Ticks exit call counter.
static void  __attribute__((noinline))
add_exit()
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
  buf->tick(frame, &s_ct_exit, 1, 1);
  buf->traceperf(depth, tstart, tend);
  buf->unlock();
}

//Templated classes to allow to generate replacement functions for each hook
template <int N>
class TimeHookInt
{
public:
  static void *replacement(void *a, void *b, void *c, void *d, void *e, void *f);
};
template <int N>
class TimeHookDouble
{
public:
  static double replacement(void *a, void *b, void *c, void *d, void *e, void *f);
};
template <int N>
class EnterHook
{
public:
  static void *replacement(void *a, void *b, void *c, void *d, void *e, void *f);
};
template <int N>
class ExitHook
{
public:
  static void *replacement(void *a, void *b, void *c, void *d, void *e, void *f);
};
template <int N>
class EnterHookDouble
{
public:
  static double replacement(void *a, void *b, void *c, void *d, void *e, void *f);
};
template <int N>
class ExitHookDouble
{
public:
  static double replacement(void *a, void *b, void *c, void *d, void *e, void *f);
};

// Array of replacement functions (max 10 functions each type)
intFunction hook_time_int[] =
{
  TimeHookInt<0>::replacement,
  TimeHookInt<1>::replacement,
  TimeHookInt<2>::replacement,
  TimeHookInt<3>::replacement,
  TimeHookInt<4>::replacement,
  TimeHookInt<5>::replacement,
  TimeHookInt<6>::replacement,
  TimeHookInt<7>::replacement,
  TimeHookInt<8>::replacement,
  TimeHookInt<9>::replacement,
  TimeHookInt<10>::replacement,
  TimeHookInt<11>::replacement,
  TimeHookInt<12>::replacement,
  TimeHookInt<13>::replacement,
  TimeHookInt<14>::replacement,
  TimeHookInt<15>::replacement,
  TimeHookInt<16>::replacement,
  TimeHookInt<17>::replacement,
  TimeHookInt<18>::replacement,
  TimeHookInt<19>::replacement
};
doubleFunction hook_time_double[] =
{
  TimeHookDouble<0>::replacement,
  TimeHookDouble<1>::replacement,
  TimeHookDouble<2>::replacement,
  TimeHookDouble<3>::replacement,
  TimeHookDouble<4>::replacement,
  TimeHookDouble<5>::replacement,
  TimeHookDouble<6>::replacement,
  TimeHookDouble<7>::replacement,
  TimeHookDouble<8>::replacement,
  TimeHookDouble<9>::replacement,
  TimeHookDouble<10>::replacement,
  TimeHookDouble<11>::replacement,
  TimeHookDouble<12>::replacement,
  TimeHookDouble<13>::replacement,
  TimeHookDouble<14>::replacement,
  TimeHookDouble<15>::replacement,
  TimeHookDouble<16>::replacement,
  TimeHookDouble<17>::replacement,
  TimeHookDouble<18>::replacement,
  TimeHookDouble<19>::replacement
};
intFunction hook_enter[] =
{
  EnterHook<0>::replacement, 
  EnterHook<1>::replacement, 
  EnterHook<2>::replacement, 
  EnterHook<3>::replacement, 
  EnterHook<4>::replacement, 
  EnterHook<5>::replacement, 
  EnterHook<6>::replacement, 
  EnterHook<7>::replacement, 
  EnterHook<8>::replacement, 
  EnterHook<9>::replacement, 
  EnterHook<10>::replacement, 
  EnterHook<11>::replacement, 
  EnterHook<12>::replacement, 
  EnterHook<13>::replacement, 
  EnterHook<14>::replacement, 
  EnterHook<15>::replacement, 
  EnterHook<16>::replacement, 
  EnterHook<17>::replacement, 
  EnterHook<18>::replacement, 
  EnterHook<19>::replacement 
};
intFunction hook_exit[] =
{
  ExitHook<0>::replacement,
  ExitHook<1>::replacement,
  ExitHook<2>::replacement,
  ExitHook<3>::replacement,
  ExitHook<4>::replacement,
  ExitHook<5>::replacement,
  ExitHook<6>::replacement,
  ExitHook<7>::replacement,
  ExitHook<8>::replacement,
  ExitHook<9>::replacement,
  ExitHook<10>::replacement, 
  ExitHook<11>::replacement, 
  ExitHook<12>::replacement, 
  ExitHook<13>::replacement, 
  ExitHook<14>::replacement, 
  ExitHook<15>::replacement, 
  ExitHook<16>::replacement, 
  ExitHook<17>::replacement, 
  ExitHook<18>::replacement, 
  ExitHook<19>::replacement 
};
doubleFunction hook_enter_double[] =
{
  EnterHookDouble<0>::replacement,
  EnterHookDouble<1>::replacement,
  EnterHookDouble<2>::replacement,
  EnterHookDouble<3>::replacement,
  EnterHookDouble<4>::replacement,
  EnterHookDouble<5>::replacement,
  EnterHookDouble<6>::replacement,
  EnterHookDouble<7>::replacement,
  EnterHookDouble<8>::replacement,
  EnterHookDouble<9>::replacement,
  EnterHookDouble<10>::replacement,
  EnterHookDouble<11>::replacement,
  EnterHookDouble<12>::replacement,
  EnterHookDouble<13>::replacement,
  EnterHookDouble<14>::replacement,
  EnterHookDouble<15>::replacement,
  EnterHookDouble<16>::replacement,
  EnterHookDouble<17>::replacement,
  EnterHookDouble<18>::replacement,
  EnterHookDouble<19>::replacement 
};
doubleFunction hook_exit_double[] =
{
  ExitHookDouble<0>::replacement,
  ExitHookDouble<1>::replacement,
  ExitHookDouble<2>::replacement,
  ExitHookDouble<3>::replacement,
  ExitHookDouble<4>::replacement,
  ExitHookDouble<5>::replacement,
  ExitHookDouble<6>::replacement,
  ExitHookDouble<7>::replacement,
  ExitHookDouble<8>::replacement,
  ExitHookDouble<9>::replacement,
  ExitHookDouble<10>::replacement,
  ExitHookDouble<11>::replacement,
  ExitHookDouble<12>::replacement,
  ExitHookDouble<13>::replacement,
  ExitHookDouble<14>::replacement,
  ExitHookDouble<15>::replacement,
  ExitHookDouble<16>::replacement,
  ExitHookDouble<17>::replacement,
  ExitHookDouble<18>::replacement,
  ExitHookDouble<19>::replacement
};

// Hooks functions given in the functions strings
// The string is in from FUNCTION1:LIBRARY1,FUNCTION2:LIBRRY2...
// Type parameter tells which kind of hooke need to be added.
void create_hooks(int type, char *functions)
{
  IgHook::TypedData<void*(void*,void*,void*,void*,void*,void*)>hookdata;
  IgHook::TypedData<double(void*,void*,void*,void*,void*,void*)>hookdatadouble;
  hookdata.typed.options = 0;
  hookdata.typed.version = 0;
  hookdata.typed.original = 0;
  hookdata.typed.trampoline = 0;
  int hook_count = 0;
  char *saveptr;
  char *token = strtok_r(functions, ",:", &saveptr);
  char *lib;
  while ((token != NULL) && hook_count < 20)
  {
    lib = strtok_r(NULL, ",:", &saveptr);

    // If type is less than 3, replacement function need to return value trough
    // %rax. If more or equal to 3. The replacement function returns value
    // trough %XMM0 register
    if (type < 3)
    {
      hookdata.typed.function = token;
      hookdata.typed.library = 0;
    }
    else
    {
      hookdatadouble.typed.function = token;
      hookdatadouble.typed.library = 0;
    }

    switch (type)
    {
      case 0:
        hookdata.typed.replacement = hook_time_int[hook_count];
        IgHook::hook(hookdata.raw);
        chainFunctionsInt[hook_count] = hookdata.typed.chain;
        ++hook_count;
        hookdata.typed.replacement = hook_time_int[hook_count];
        hookdata.typed.library = lib;
        IgHook::hook(hookdata.raw);
        chainFunctionsInt[hook_count] = hookdata.typed.chain;
        break;
      case 1:
        hookdata.typed.replacement = hook_enter[hook_count];
        IgHook::hook(hookdata.raw);
        chainFunctionsEnter[hook_count] = hookdata.typed.chain;
        ++hook_count;
        hookdata.typed.replacement = hook_enter[hook_count];
        hookdata.typed.library = lib;
        IgHook::hook(hookdata.raw);
        chainFunctionsEnter[hook_count] = hookdata.typed.chain;
        break;
      case 2:
        hookdata.typed.replacement = hook_exit[hook_count];
        IgHook::hook(hookdata.raw);
        chainFunctionsExit[hook_count] = hookdata.typed.chain;
        ++hook_count;
        hookdata.typed.replacement = hook_exit[hook_count];
        hookdata.typed.library = lib;
        IgHook::hook(hookdata.raw);
        chainFunctionsExit[hook_count] = hookdata.typed.chain;
        break;
      case 3:
        hookdatadouble.typed.replacement = hook_time_double[hook_count];
        IgHook::hook(hookdatadouble.raw);
        chainFunctionsDouble[hook_count] = hookdatadouble.typed.chain;
        ++hook_count;
        hookdatadouble.typed.replacement = hook_time_double[hook_count];
        hookdatadouble.typed.library = lib;
        IgHook::hook(hookdatadouble.raw);
        chainFunctionsDouble[hook_count] = hookdatadouble.typed.chain;
        break;
      case 4:
        hookdatadouble.typed.replacement = hook_enter_double[hook_count];
        IgHook::hook(hookdatadouble.raw);
        chainFunctionsEnterDouble[hook_count] = hookdatadouble.typed.chain;
        ++hook_count;
        hookdatadouble.typed.replacement = hook_time_double[hook_count];
        hookdatadouble.typed.library = lib;
        IgHook::hook(hookdatadouble.raw);
        chainFunctionsDouble[hook_count] = hookdatadouble.typed.chain;
        break;
      case 5:
        hookdatadouble.typed.replacement = hook_exit_double[hook_count];
        IgHook::hook(hookdatadouble.raw);
        chainFunctionsExitDouble[hook_count] = hookdatadouble.typed.chain;
        ++hook_count;
        hookdatadouble.typed.replacement = hook_exit_double[hook_count];
        hookdatadouble.typed.library = lib;
        IgHook::hook(hookdatadouble.raw);
        chainFunctionsExitDouble[hook_count] = hookdatadouble.typed.chain;
        break;
    }
    token = strtok_r(NULL, ",:", &saveptr);
    ++hook_count;
  }
}

static void
initialize()
{
  if (s_initialized) return;
  s_initialized = true;

  const char    *options = igprof_options();
  bool          function_time = false;
  bool          function_enter_exit = false;

  while (options && *options)
  {
    while (*options == ' ' || *options == ',')
      ++options;

    if (! strncmp(options, "mfunc", 5))
    {
      options = options + 5;
      function_time = true;
    }
    else if (! strncmp(options, "mfenter-exit", 11))
    {
      options = options + 11;
      function_enter_exit = true;
    }

    while (*options && *options != ',' && *options != ' ')
      options++;
  }

  if (! (function_time || function_enter_exit))
    return;

  if (! igprof_init("Multi function profiler", 0, false))
    return;

  if (function_time)
  {
    char *hook_these_int = igprof_getenv("IGPROF_MULTIFUNCTION_INT");
    if (hook_these_int)
      create_hooks(0, hook_these_int);
    char *hook_these_double = igprof_getenv("IGPROF_MULTIFUNCTION_FLOAT");
    if (hook_these_double)
      create_hooks(3, hook_these_double);
  }
  else
  {
    char *hook_these_enter_int = igprof_getenv("IGPROF_MULTIFUNCTION_ENTER_INT");
    if (hook_these_enter_int)
      create_hooks(1, hook_these_enter_int);
    char *hook_these_exit_int = igprof_getenv("IGPROF_MULTIFUNCTION_EXIT_INT");
    if (hook_these_exit_int)
      create_hooks(2, hook_these_exit_int);
    char *hook_these_enter_double = igprof_getenv("IGPROF_MULTIFUNCTION_ENTER_FLOAT");
    if (hook_these_enter_double)
      create_hooks(4, hook_these_enter_double);
    char *hook_these_exit_double = igprof_getenv("IGPROF_MULTIFUNCTION_EXIT_FLOAT");
    if (hook_these_exit_double)
      create_hooks(5, hook_these_exit_double);
  }

  // Decide correct hook to be inserted and call create_hooks functions
  igprof_enable_globally();
}

// 6 Different type of replacement functions. Template number tells which chain
// function will be called. (max 10 funtions of each type)
template<int N>
void *TimeHookInt<N>::replacement(void *a, void *b, void *c, void *d, void *e, void *f)
{
  bool enabled = igprof_disable();

  uint64_t tstart, tend;
  RDTSC(tstart);
  void *result = (chainFunctionsInt[N])(a,b,c,d,e,f);
  RDTSC(tend);

  if (LIKELY(enabled))
    add(tend-tstart);

  igprof_enable();
  return result;
}
template<int N>
double TimeHookDouble<N>::replacement(void *a, void *b, void *c, void *d, void *e, void *f)
{
  bool enabled = igprof_disable();

  uint64_t tstart, tend;
  RDTSC(tstart);
  double result = (chainFunctionsDouble[N])(a,b,c,d,e,f);
  RDTSC(tend);

  if (LIKELY(enabled))
    add(tend-tstart);

  igprof_enable();
  return result;
}
template<int N>
void *EnterHook<N>::replacement(void *a, void *b, void *c, void *d, void *e, void *f)
{
  bool enabled = igprof_disable();
  void *result = (chainFunctionsEnter[N])(a,b,c,d,e,f);

  if (LIKELY(enabled))
    add_enter();

  igprof_enable();
  return result;
}
template<int N>
void *ExitHook<N>::replacement(void *a, void *b, void *c, void *d, void *e, void *f)
{
  bool enabled = igprof_disable();
  void *result = (chainFunctionsExit[N])(a,b,c,d,e,f);

  if (LIKELY(enabled))
    add_exit();

  igprof_enable();
  return result;
}
template<int N>
double EnterHookDouble<N>::replacement(void *a, void *b, void *c, void *d, void *e, void *f)
{
  bool enabled = igprof_disable();
  double result = (chainFunctionsEnterDouble[N])(a,b,c,d,e,f);

  if (LIKELY(enabled))
    add_exit();

  igprof_enable();
  return result;
}
template<int N>
double ExitHookDouble<N>::replacement(void *a, void *b, void *c, void *d, void *e, void *f)
{
  bool enabled = igprof_disable();
  double result = (chainFunctionsExitDouble[N])(a,b,c,d,e,f);

  if (LIKELY(enabled))
    add_exit();

  igprof_enable();
  return result;
}

static bool autoboot = (initialize(), true);
