#include "profile.h"
#include "profile-trace.h"
#include "hook.h"
#include "walk-syms.h"
#include <cstdlib>
#include <cstring>
#include <signal.h>
#include <sys/time.h>

#ifdef __APPLE__
typedef sig_t sighandler_t;
#endif

// -------------------------------------------------------------------
// Traps for this profiler module
LIBHOOK(0, int, dofork, _main, (), (), "fork", 0, 0)
LIBHOOK(1, int, dosystem, _main, (const char *cmd), (cmd), "system", 0, 0)
LIBHOOK(3, int, dopthread_sigmask, _main,
        (int how, sigset_t *newmask, sigset_t *oldmask),
        (how, newmask, oldmask),
        "pthread_sigmask", 0, 0)
LIBHOOK(3, int, dosigaction, _main,
        (int signum, const struct sigaction *act, struct sigaction *oact),
        (signum, act, oact),
        "sigaction", 0, 0)

// Data for this profiler module
static IgProfTrace::CounterDef  s_ct_ticks      = { "PERF_TICKS", IgProfTrace::TICK, -1 };
static bool                     s_initialized   = false;
static int                      s_signal        = SIGPROF;
static int                      s_itimer        = ITIMER_PROF;

/** Convert timeval to seconds. */
static inline double tv2sec(const timeval &tv)
{ return tv.tv_sec + tv.tv_usec * 1e-6; }

/** Performance profiler signal handler, SIGPROF or SIGALRM depending
    on the current profiler mode.  Record a tick for the current
    program location.  Assumes the signal handler is registered for
    the correct thread.  Skip ticks when this profiler is not
    enabled.  */
static void
profileSignalHandler(int /* nsig */, siginfo_t * /* info */, void * /* ctx */)
{
  void *addresses [IgProfTrace::MAX_DEPTH];
  if (LIKELY(igprof_disable()))
  {
    IgProfTrace *buf = igprof_buffer();
    if (LIKELY(buf))
    {
      IgProfTrace::Stack *frame;
      uint64_t tstart, tend;
      int depth;

      RDTSC(tstart);
      depth = IgHookTrace::stacktrace(addresses, IgProfTrace::MAX_DEPTH);
      RDTSC(tend);

      // Drop three top stackframes (stacktrace, me, signal frame).
      frame = buf->push(addresses+3, depth-3);
      buf->tick(frame, &s_ct_ticks, 1, 1);
      buf->traceperf(depth, tstart, tend);
    }
  }
  igprof_enable();
}

/** Enable profiling timer.  You should have called
    #enableSignalHandler() before calling this function.
    This needs to be executed in every thread to be profiled. */
static void
enableTimer(void)
{
  itimerval interval = { { 0, 5000 }, { 0, 5000 } };
  setitimer(s_itimer, &interval, 0);
}

/** Enable profiling signal handler.  */
static void
enableSignalHandler(void)
{
  sigset_t profset;
  sigemptyset(&profset);
  sigaddset(&profset, s_signal);
  pthread_sigmask(SIG_UNBLOCK, &profset, 0);

  struct sigaction sa;
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = (sighandler_t) &profileSignalHandler;
  sa.sa_flags = SA_RESTART | SA_SIGINFO;
  sigaction(s_signal, &sa, 0);
}

/** Thread setup function.  */
static void
threadInit(void)
{
  // Enable profiling in this thread.
  enableSignalHandler();
  enableTimer();
}

// -------------------------------------------------------------------
/** Possibly start performance profiler.  */
static void
initialize(void)
{
  if (s_initialized) return;
  s_initialized = true;

  const char    *options = igprof_options();
  bool          enable = false;

  while (options && *options)
  {
    while (*options == ' ' || *options == ',')
      ++options;

    if (! strncmp(options, "perf", 4))
    {
      enable = true;
      options += 4;
      while (*options)
      {
        if (! strncmp(options, ":real", 5))
        {
          s_signal = SIGALRM;
          s_itimer = ITIMER_REAL;
          options += 5;
        }
        else if (! strncmp(options, ":user", 5))
        {
          s_signal = SIGVTALRM;
          s_itimer = ITIMER_VIRTUAL;
          options += 5;
        }
        else if (! strncmp(options, ":process", 7))
        {
          s_signal = SIGPROF;
          s_itimer = ITIMER_PROF;
          options += 7;
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

  double clockres = 0;
  itimerval precision;
  itimerval interval = { { 0, 5000 }, { 100, 0 } };
  itimerval nullified = { { 0, 0 }, { 0, 0 } };
  setitimer(s_itimer, &interval, 0);
  getitimer(s_itimer, &precision);
  setitimer(s_itimer, &nullified, 0);
  clockres = precision.it_interval.tv_sec
             + 1e-6 * precision.it_interval.tv_usec;

  if (! igprof_init("performance profiler", &threadInit, true, clockres))
    return;

  igprof_disable_globally();
  if (s_itimer == ITIMER_REAL)
    igprof_debug("Perf: measuring real time\n");
  else if (s_itimer == ITIMER_VIRTUAL)
    igprof_debug("Perf: profiling user time\n");
  else if (s_itimer == ITIMER_PROF)
    igprof_debug("Perf: profiling process time\n");

  // Enable profiler.
  IgHook::hook(dofork_hook_main.raw);
  IgHook::hook(dosystem_hook_main.raw);
  IgHook::hook(dopthread_sigmask_hook_main.raw);
  IgHook::hook(dosigaction_hook_main.raw);
  igprof_debug("Performance profiler enabled\n");

  enableSignalHandler();
  enableTimer();
  igprof_enable_globally();
}

// -------------------------------------------------------------------
// Trap fiddling with thread signal masks
static int
dopthread_sigmask(IgHook::SafeData<igprof_dopthread_sigmask_t> &hook,
                  int how, sigset_t *newmask,  sigset_t *oldmask)
{
  struct sigaction cursig;
  struct itimerval curtimer;
  if (newmask
      && (how == SIG_BLOCK || how == SIG_SETMASK)
      && sigismember(newmask, s_signal)
      && sigaction(s_signal, 0, &cursig) == 0
      && cursig.sa_handler
      && getitimer(s_itimer, &curtimer) == 0
      && (curtimer.it_interval.tv_sec || curtimer.it_interval.tv_usec))
  {
    igprof_debug("pthread_sigmask(): prevented profiling signal"
                 " %d from being blocked in thread 0x%lx"
                 " [handler 0x%lx, interval %.0f us]\n",
                 s_signal, (unsigned long) pthread_self(),
                 (unsigned long) cursig.sa_handler,
                 1e6 * curtimer.it_interval.tv_sec
                 + curtimer.it_interval.tv_usec);
    sigdelset(newmask, s_signal);
  }

  return hook.chain(how, newmask, oldmask);
}

// Trap fiddling with the profiling signal.
static int
dosigaction(IgHook::SafeData<igprof_dosigaction_t> &hook,
            int signum, const struct sigaction *act, struct sigaction *oact)
{
  struct sigaction sa;
  if (signum == s_signal
      && act
      && act->sa_handler != (sighandler_t) &profileSignalHandler)
  {
    igprof_debug("sigaction(): prevented profiling signal"
                 " %d from being overridden in thread 0x%lx\n",
                 s_signal, (unsigned long) pthread_self());
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = (sighandler_t) &profileSignalHandler;
    sa.sa_flags = SA_RESTART | SA_SIGINFO;
    act = &sa;
  }

  return hook.chain(signum, act, oact);
}

// Trap fork to deactivate profiling around it, then artificially
// add back the cost associated to actual fork call. This trickery
// is required because large processes can take a rather long time
// to fork, and linux clone() routine can go into an infinite loop
// processing ERESTARTNOINTR if a signal arrives within clone().
static int
dofork(IgHook::SafeData<igprof_dofork_t> &hook)
{
  // Slow down profiling to once per 10sec, which should be slow
  // enough to complete fork() under any circumstances.
  double dt = 0;
  int nticks = 0;
  bool enabled = igprof_disable();
  itimerval slow = { { 10, 0 }, { 10, 0 } };
  itimerval fast = { { 0, 5000 }, { 0, 5000 } };
  itimerval left = { { 0, 0 }, { 0, 0 } };
  setitimer(s_itimer, &slow, &left);
  dt = tv2sec(left.it_interval) - tv2sec(left.it_value);

  // Do the fork() call.
  int ret = hook.chain();

  // Now calculate how much time we spent doing the fork, and blame
  // the actual system call for it, drop this frame out of stack.
  // Only do this in the parent; in child the timer is disabled.
  if (ret > 0)
  {
    setitimer(s_itimer, &fast, &slow);
    getitimer(s_itimer, &left);
    IgProfTrace *buf = igprof_buffer();
    dt += tv2sec(slow.it_interval) - tv2sec(slow.it_value);
    nticks = int(dt / tv2sec(left.it_interval) + 0.5);
    if (enabled && nticks && buf)
    {
      void *addresses [IgProfTrace::MAX_DEPTH];
      IgProfTrace::Stack *frame;
      uint64_t tstart, tend;
      int depth;

      RDTSC(tstart);
      depth = IgHookTrace::stacktrace(addresses, IgProfTrace::MAX_DEPTH);
      if (depth > 1) addresses[1] = __extension__ (void *) hook.original;
      RDTSC(tend);

      frame = buf->push(addresses+1, depth-1);
      buf->tick(frame, &s_ct_ticks, 1, nticks);
      buf->traceperf(depth, tstart, tend);
    }
    igprof_debug("resuming profiling after blinking for fork() for"
		 " %.3fms, %d ticks\n", dt*1000, nticks);
  }

  igprof_enable();
  return ret;
}

// Trap system to deactivate profiling around it, like fork(). The
// system() normally calls clone() system call directly via vsyscall
// interface, without going thru fork() or clone() functions, so we
// can't trap into clone().
static int
dosystem(IgHook::SafeData<igprof_dosystem_t> &hook, const char *cmd)
{
  // See fork() for the implementation details.
  int nticks = 0;
  double dt = 0;
  bool enabled = igprof_disable();
  itimerval slow = { { 10, 0 }, { 10, 0 } };
  itimerval fast = { { 0, 5000 }, { 0, 5000 } };
  itimerval left = { { 0, 0 }, { 0, 0 } };
  setitimer(s_itimer, &slow, &left);
  dt = tv2sec(left.it_interval) - tv2sec(left.it_value);

  int ret = hook.chain(cmd);

  setitimer(s_itimer, &fast, &slow);
  getitimer(s_itimer, &left);
  IgProfTrace *buf = igprof_buffer();
  dt += tv2sec(slow.it_interval) - tv2sec(slow.it_value);
  nticks = int(dt / tv2sec(left.it_interval) + 0.5);
  if (enabled && nticks && buf)
  {
    void *addresses [IgProfTrace::MAX_DEPTH];
    IgProfTrace::Stack *frame;
    uint64_t tstart, tend;
    int depth;

    RDTSC(tstart);
    depth = IgHookTrace::stacktrace(addresses, IgProfTrace::MAX_DEPTH);
    if (depth > 1) addresses[1] = __extension__ (void *) hook.original;
    RDTSC(tend);

    frame = buf->push(addresses+1, depth-1);
    buf->tick(frame, &s_ct_ticks, 1, nticks);
    buf->traceperf(depth, tstart, tend);
  }

  igprof_debug("resuming profiling after blinking for system() for"
	       " %.3fms, %d ticks\n", dt*1000, nticks);
  igprof_enable();
  return ret;
}

// -------------------------------------------------------------------
static bool autoboot = (initialize(), true);
